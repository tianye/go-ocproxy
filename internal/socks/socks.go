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
	"time"

	"github.com/doctor/go-ocproxy/internal/stack"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type Server struct {
	ns         *stack.NetStack
	listen     string
	dnsServers []string
}

func NewServer(ns *stack.NetStack, listen string, dnsServers []string) *Server {
	return &Server{
		ns:         ns,
		listen:     listen,
		dnsServers: dnsServers,
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

// resolve 通过 VPN 隧道解析域名。
//
// 历史：老版本用 net.Resolver{PreferGo:true, Dial: ns.DialUDP} 把 Go 内置 resolver
// 的 UDP dial 重定向到 gVisor。但实测在部分环境下 UDP DNS 包走出 gVisor 后没有应答
// （openconnect --script-tun 的 UDP 转发行为不稳 / 公司 DNS 对 gVisor 源 IP 不回 /
//  回包在 CSTP 通道里丢），表现为 `read udp <internal>: i/o timeout`，默认 5s 起跳，
// 且 Go resolver 错误里 "server" 字段是 /etc/resolv.conf 的热点 DNS，极易误导排查。
//
// 现在改为**直接手写 DNS-over-TCP 查询**（RFC 7766）：
//   1. 通过 gVisor 的 TCP 通道拨公司 DNS <ip>:53
//   2. 发送带 2-byte 长度前缀的 DNS query
//   3. 读回 A 记录第一个 IPv4 并返回
//
// 好处：TCP 路径在 VPN 模式下已验证稳定（跟业务流量同一条路），超时可控（3s），
// 错误信息准确（直接暴露 "dial tcp <dns>:53" 或 "rcode N"）。
func (s *Server) resolve(ctx context.Context, name string) (net.IP, error) {
	if len(s.dnsServers) == 0 {
		ips, err := net.LookupIP(name)
		if err != nil || len(ips) == 0 {
			return nil, err
		}
		return ips[0], nil
	}

	var lastErr error
	for _, srv := range s.dnsServers {
		ip, err := s.queryA(ctx, srv, name)
		if err == nil && ip != nil {
			return ip, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}

// queryA 通过 gVisor TCP 连接向指定 DNS server 查询 A 记录。
func (s *Server) queryA(ctx context.Context, dnsServer, name string) (net.IP, error) {
	addrStr := dnsServer
	if !strings.Contains(addrStr, ":") {
		addrStr += ":53"
	}
	host, portStr, err := net.SplitHostPort(addrStr)
	if err != nil {
		return nil, err
	}
	portN, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ipv4 := net.ParseIP(host).To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("dns server %q not an IPv4 address", dnsServer)
	}

	qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	conn, err := s.ns.DialTCP(qctx, &tcpip.FullAddress{
		Addr: tcpip.AddrFrom4([4]byte{ipv4[0], ipv4[1], ipv4[2], ipv4[3]}),
		Port: uint16(portN),
	})
	if err != nil {
		return nil, fmt.Errorf("dial tcp %s:%d: %w", host, portN, err)
	}
	defer conn.Close()
	if dl, ok := qctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	query := buildDNSQueryA(name)
	framed := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(query)))
	copy(framed[2:], query)
	if _, err := conn.Write(framed); err != nil {
		return nil, fmt.Errorf("write query: %w", err)
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read resp length: %w", err)
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	if respLen == 0 || respLen > 65535 {
		return nil, fmt.Errorf("invalid resp length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return nil, fmt.Errorf("read resp: %w", err)
	}
	return parseFirstA(respBuf)
}

// buildDNSQueryA 构造一个查询 A 记录的最小 DNS 请求（12B header + QNAME + QTYPE+QCLASS）。
func buildDNSQueryA(name string) []byte {
	buf := make([]byte, 0, 32+len(name))
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], uint16(rand.Intn(0xffff))) // ID
	binary.BigEndian.PutUint16(header[2:4], 0x0100)                    // flags: RD=1
	binary.BigEndian.PutUint16(header[4:6], 1)                         // QDCOUNT
	buf = append(buf, header...)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)             // end of QNAME
	buf = append(buf, 0x00, 0x01)       // QTYPE=A
	buf = append(buf, 0x00, 0x01)       // QCLASS=IN
	return buf
}

// parseFirstA 从 DNS 响应里拉出第一条 A 记录的 IPv4。
func parseFirstA(resp []byte) (net.IP, error) {
	if len(resp) < 12 {
		return nil, fmt.Errorf("dns response too short (%d)", len(resp))
	}
	rcode := resp[3] & 0x0f
	if rcode != 0 {
		return nil, fmt.Errorf("dns rcode=%d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(resp[4:6]))
	an := int(binary.BigEndian.Uint16(resp[6:8]))
	if an == 0 {
		return nil, fmt.Errorf("no answer records")
	}

	p := 12
	// 跳过 question sections
	for i := 0; i < qd; i++ {
		np, err := skipName(resp, p)
		if err != nil {
			return nil, err
		}
		p = np + 4 // QTYPE + QCLASS
		if p > len(resp) {
			return nil, fmt.Errorf("truncated question")
		}
	}

	// 扫 answer sections
	for i := 0; i < an; i++ {
		np, err := skipName(resp, p)
		if err != nil {
			return nil, err
		}
		p = np
		if p+10 > len(resp) {
			return nil, fmt.Errorf("truncated RR header")
		}
		rtype := binary.BigEndian.Uint16(resp[p : p+2])
		rdlen := int(binary.BigEndian.Uint16(resp[p+8 : p+10]))
		p += 10
		if p+rdlen > len(resp) {
			return nil, fmt.Errorf("truncated RDATA")
		}
		if rtype == 1 && rdlen == 4 {
			return net.IPv4(resp[p], resp[p+1], resp[p+2], resp[p+3]).To4(), nil
		}
		p += rdlen
	}
	return nil, fmt.Errorf("no A record in answer")
}

// skipName 跳过一个 DNS name（可能带压缩指针），返回 name 结束后的 offset。
func skipName(buf []byte, p int) (int, error) {
	for {
		if p >= len(buf) {
			return 0, fmt.Errorf("truncated name")
		}
		l := int(buf[p])
		if l == 0 {
			return p + 1, nil
		}
		if l&0xc0 == 0xc0 {
			if p+2 > len(buf) {
				return 0, fmt.Errorf("truncated name pointer")
			}
			return p + 2, nil
		}
		p += 1 + l
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
