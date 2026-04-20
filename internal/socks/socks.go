package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/doctor/go-ocproxy/internal/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	dnsCacheMinTTL      = 30 * time.Second
	dnsCacheMaxTTL      = 1 * time.Hour
	dnsCacheFallbackTTL = 5 * time.Minute // 用于没有 TTL 信息的路径（系统 DNS fallback）
	dnsUDPTimeout       = 2 * time.Second
	dnsTCPTimeout       = 3 * time.Second
	dnsMaxAttempts      = 3
)

type dnsCacheEntry struct {
	ip     net.IP
	expiry time.Time
}

type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsCacheEntry)}
}

func (c *dnsCache) get(name string) (net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[name]
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.ip, true
}

func (c *dnsCache) set(name string, ip net.IP, ttl time.Duration) {
	if ttl < dnsCacheMinTTL {
		ttl = dnsCacheMinTTL
	} else if ttl > dnsCacheMaxTTL {
		ttl = dnsCacheMaxTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[name] = dnsCacheEntry{ip: ip, expiry: time.Now().Add(ttl)}
}

type Server struct {
	ns         *stack.NetStack
	listen     string
	dnsServers []string
	cache      *dnsCache
}

func NewServer(ns *stack.NetStack, listen string, dnsServers []string) *Server {
	return &Server{
		ns:         ns,
		listen:     listen,
		dnsServers: dnsServers,
		cache:      newDNSCache(),
	}
}

func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 server listening on %s", s.listen)
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) resolve(ctx context.Context, name string) (net.IP, error) {
	if ip, ok := s.cache.get(name); ok {
		return ip, nil
	}

	if len(s.dnsServers) == 0 {
		ips, err := net.LookupIP(name)
		if err != nil || len(ips) == 0 {
			return nil, err
		}
		s.cache.set(name, ips[0], dnsCacheFallbackTTL)
		return ips[0], nil
	}

	// 多 DNS 服务器轮询 + UDP→TCP fallback，起点随机避免所有并发查询都压第一个 server
	start := rand.Intn(len(s.dnsServers))
	var lastErr error
	for i := 0; i < dnsMaxAttempts; i++ {
		server := s.dnsServers[(start+i)%len(s.dnsServers)]
		ip, ttl, err := s.dnsQuery(ctx, name, server)
		if err == nil && ip != nil {
			s.cache.set(name, ip, ttl)
			return ip, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// dnsQuery 对单一 DNS 服务器查询 A 记录：先 UDP，超时或 TC 截断后切 TCP。
// 返回解析出的 IP 和响应里真实的 TTL。
func (s *Server) dnsQuery(ctx context.Context, name, server string) (net.IP, time.Duration, error) {
	dnsAddr := server
	if !strings.Contains(dnsAddr, ":") {
		dnsAddr += ":53"
	}
	host, portStr, _ := net.SplitHostPort(dnsAddr)
	port, _ := strconv.Atoi(portStr)
	parsed := net.ParseIP(host).To4()
	if parsed == nil {
		return nil, 0, &net.AddrError{Err: "invalid dns server", Addr: host}
	}
	addr := &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{parsed[0], parsed[1], parsed[2], parsed[3]}),
		Port: uint16(port),
	}

	id := uint16(rand.Uint32())
	query, err := buildDNSQuery(name, id)
	if err != nil {
		return nil, 0, err
	}

	// UDP first
	resp, truncated, udpErr := s.queryUDP(ctx, addr, query)
	if udpErr == nil && !truncated {
		return parseDNSResponse(resp, id)
	}
	// TCP fallback: UDP 失败或响应被截断
	resp, tcpErr := s.queryTCP(ctx, addr, query)
	if tcpErr != nil {
		if udpErr != nil {
			return nil, 0, fmt.Errorf("udp: %v; tcp: %v", udpErr, tcpErr)
		}
		return nil, 0, tcpErr
	}
	return parseDNSResponse(resp, id)
}

func (s *Server) queryUDP(ctx context.Context, addr *tcpip.FullAddress, query []byte) ([]byte, bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dnsUDPTimeout)
	defer cancel()
	conn, err := s.ns.DialUDP(dialCtx, addr)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsUDPTimeout))

	if _, err := conn.Write(query); err != nil {
		return nil, false, err
	}
	buf := make([]byte, 1232) // EDNS 推荐 payload 大小
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	if n < 12 {
		return nil, false, fmt.Errorf("udp dns response too short: %d bytes", n)
	}
	// flags 第 2 字节 bit 1 = TC (truncated)
	truncated := (buf[2] & 0x02) != 0
	return buf[:n], truncated, nil
}

func (s *Server) queryTCP(ctx context.Context, addr *tcpip.FullAddress, query []byte) ([]byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, dnsTCPTimeout)
	defer cancel()
	conn, err := s.ns.DialTCP(dialCtx, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(dnsTCPTimeout))

	// RFC 1035: TCP DNS 前置 2 字节长度
	var lenPrefix [2]byte
	binary.BigEndian.PutUint16(lenPrefix[:], uint16(len(query)))
	if _, err := conn.Write(lenPrefix[:]); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	var respLenBuf [2]byte
	if _, err := io.ReadFull(conn, respLenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(respLenBuf[:])
	if respLen == 0 {
		return nil, fmt.Errorf("tcp dns zero-length response")
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// buildDNSQuery 构造 A 记录查询报文。
func buildDNSQuery(name string, id uint16) ([]byte, error) {
	buf := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT
	// AN/NS/AR counts = 0（已清零）
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid dns label %q", label)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)          // root label
	buf = append(buf, 0, 1, 0, 1) // qtype=A(1), qclass=IN(1)
	return buf, nil
}

// parseDNSResponse 解析响应，返回第一条 A 记录的 IP 和 TTL。
func parseDNSResponse(resp []byte, expectedID uint16) (net.IP, time.Duration, error) {
	if len(resp) < 12 {
		return nil, 0, fmt.Errorf("dns response too short: %d", len(resp))
	}
	if binary.BigEndian.Uint16(resp[0:2]) != expectedID {
		return nil, 0, fmt.Errorf("dns id mismatch")
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if rcode := flags & 0x0F; rcode != 0 {
		return nil, 0, fmt.Errorf("dns rcode %d", rcode)
	}
	qdCount := binary.BigEndian.Uint16(resp[4:6])
	anCount := binary.BigEndian.Uint16(resp[6:8])

	off := 12
	for i := uint16(0); i < qdCount; i++ {
		newOff, err := skipDNSName(resp, off)
		if err != nil {
			return nil, 0, err
		}
		off = newOff + 4 // qtype + qclass
		if off > len(resp) {
			return nil, 0, fmt.Errorf("dns question truncated")
		}
	}
	for i := uint16(0); i < anCount; i++ {
		newOff, err := skipDNSName(resp, off)
		if err != nil {
			return nil, 0, err
		}
		off = newOff
		if off+10 > len(resp) {
			return nil, 0, fmt.Errorf("dns answer header truncated")
		}
		rtype := binary.BigEndian.Uint16(resp[off : off+2])
		ttl := binary.BigEndian.Uint32(resp[off+4 : off+8])
		rdLen := binary.BigEndian.Uint16(resp[off+8 : off+10])
		off += 10
		if off+int(rdLen) > len(resp) {
			return nil, 0, fmt.Errorf("dns rdata truncated")
		}
		if rtype == 1 && rdLen == 4 { // A
			ip := net.IPv4(resp[off], resp[off+1], resp[off+2], resp[off+3])
			return ip, time.Duration(ttl) * time.Second, nil
		}
		off += int(rdLen)
	}
	return nil, 0, fmt.Errorf("no A record in dns response")
}

// skipDNSName 跳过一个 DNS 域名（支持压缩指针），返回名字结束后的偏移。
func skipDNSName(msg []byte, off int) (int, error) {
	for {
		if off >= len(msg) {
			return 0, fmt.Errorf("dns name overflow")
		}
		b := msg[off]
		if b == 0 {
			return off + 1, nil
		}
		if b&0xC0 == 0xC0 {
			// 压缩指针，占 2 字节，名字到此终止
			if off+2 > len(msg) {
				return 0, fmt.Errorf("dns name pointer overflow")
			}
			return off + 2, nil
		}
		if b&0xC0 != 0 {
			return 0, fmt.Errorf("dns invalid label prefix 0x%02x", b)
		}
		off += 1 + int(b)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	ctx := context.Background()

	buf := make([]byte, 1024)
	// 1. Negotiation
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	conn.Write([]byte{0x05, 0x00})

	// 2. Request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	var host string
	var targetIP net.IP
	switch buf[3] {
	case 0x01: // IPv4
		if _, err := io.ReadFull(conn, buf[:4]); err != nil {
			return
		}
		targetIP = net.IP(buf[:4])
		host = targetIP.String()
	case 0x03: // Domain
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		l := int(buf[0])
		if _, err := io.ReadFull(conn, buf[:l]); err != nil {
			return
		}
		host = string(buf[:l])
		ip, err := s.resolve(ctx, host)
		if err != nil {
			log.Printf("DNS lookup failed for %s: %v", host, err)
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		targetIP = ip
	default:
		return
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	port := uint16(buf[0])<<8 | uint16(buf[1])

	// 3. Connect via NetStack
	log.Printf("Proxying: %s -> %s (%s)", conn.RemoteAddr(), host, targetIP)
	targetIP4 := targetIP.To4()
	addr := tcpip.AddrFrom4([4]byte{targetIP4[0], targetIP4[1], targetIP4[2], targetIP4[3]})
	remote, err := s.ns.DialTCP(ctx, &tcpip.FullAddress{
		Addr: addr,
		Port: port,
	})
	if err != nil {
		log.Printf("Dial failed: %v", err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 4. Copy data
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(remote, conn)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(conn, remote)
		errCh <- err
	}()
	<-errCh
}
