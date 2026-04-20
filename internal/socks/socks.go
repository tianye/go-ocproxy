package socks

import (
	"context"
	"io"
	"log"
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

// resolve 通过 VPN 隧道的 DNS 做域名解析。
//
// 走 Go 内置 resolver（PreferGo）+ 自定义 Dial 把 UDP 查询重定向到 gVisor，
// 经 VPN 隧道打到公司内网 DNS。
//
// 历史坑：只有在 internal/stack.Run 的 datagram 边界 bug 修好之后，UDP DNS 才真正通。
// 之前 read 把 IP 包截断，UDP DNS 响应永远到不了 resolver，表现为 5s i/o timeout。
// 参见 stack.Run 的注释。
func (s *Server) resolve(ctx context.Context, name string) (net.IP, error) {
	if len(s.dnsServers) == 0 {
		ips, err := net.LookupIP(name)
		if err != nil || len(ips) == 0 {
			return nil, err
		}
		return ips[0], nil
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dnsAddr := s.dnsServers[0]
			if !strings.Contains(dnsAddr, ":") {
				dnsAddr += ":53"
			}
			host, portStr, _ := net.SplitHostPort(dnsAddr)
			port, _ := strconv.Atoi(portStr)
			ip := net.ParseIP(host).To4()
			addr := tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
			return s.ns.DialUDP(ctx, &tcpip.FullAddress{
				Addr: addr,
				Port: uint16(port),
			})
		},
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(lookupCtx, "ip4", name)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	return ips[0], nil
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
