package stack

import (
	"context"
	"fmt"
	"io"
	"net"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type NetStack struct {
	Stack *stack.Stack
	Link  *channel.Endpoint
}

func NewNetStack(ipAddr string, mtu uint32) (*NetStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})

	link := channel.New(256, mtu, "")
	if err := s.CreateNIC(1, link); err != nil {
		return nil, fmt.Errorf("create NIC failed: %v", err)
	}

	ip := net.ParseIP(ipAddr).To4()
	addr := tcpip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addr.WithPrefix(),
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address failed: %v", err)
	}

	// 设置默认路由
	subnet, _ := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{0, 0, 0, 0}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         1,
		},
	})

	return &NetStack{
		Stack: s,
		Link:  link,
	}, nil
}

func (ns *NetStack) DialTCP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	return gonet.DialTCPWithBind(ctx, ns.Stack, tcpip.FullAddress{}, *addr, ipv4.ProtocolNumber)
}

func (ns *NetStack) DialUDP(ctx context.Context, addr *tcpip.FullAddress) (net.Conn, error) {
	return gonet.DialUDP(ns.Stack, &tcpip.FullAddress{}, addr, ipv4.ProtocolNumber)
}

// Run 在给定的 VPN 管道上跑 gVisor 网络栈。
//
// ⚠️ VPNFD 不是字节流 pipe，而是 AF_UNIX SOCK_DGRAM（见 openconnect tun.c
// openconnect_setup_tun_script: `socketpair(AF_UNIX, SOCK_DGRAM, 0, fds)`）。
// 语义：每次 read() 返回一个完整 IP 包；如果 buffer 比 datagram 小，**多出来的部分
// 被内核直接丢弃**（POSIX SOCK_DGRAM 行为）。
//
// 历史 bug：老版本用 io.ReadFull(input, header[:20]) + io.ReadFull(input, payload)
// 分两次读，以为 VPNFD 是字节流。但在 SOCK_DGRAM 上，第一次 read(20) 只拿回 IP header
// 就把整个 datagram 的 payload 丢完；第二次 read 读到下一个 datagram，再次截断。
// 结果：所有 IP 包都被截成只剩 header，TCP/UDP payload 100% 丢失。
//   - TCP 勉强跑（重传能容忍一部分丢包）但极不稳定
//   - UDP DNS 一问一答直接零响应 → 总是 5s 超时
// 参见 openconnect `os_read_tun`：`read(fd, buf, MTU)` 一次拿整个 packet。
func (ns *NetStack) Run(input io.Reader, output io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Outbound：gVisor → VPN（output.Write 一次一个完整 IP 包即可；
	// os.File 底层 write(fd, buf, n) 对 SOCK_DGRAM 自动按 datagram 发送）
	go func() {
		for {
			pkt := ns.Link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			buf := pkt.ToBuffer()
			if _, err := output.Write(buf.Flatten()); err != nil {
				buf.Release()
				return
			}
			buf.Release()
		}
	}()

	// Inbound：VPN → gVisor
	// 一次 Read 拿一个完整 datagram。65535 是 IPv4 最大长度，足够任何合法 IP 包。
	pktBuf := make([]byte, 65535)
	for {
		n, err := input.Read(pktBuf)
		if err != nil {
			return err
		}
		if n < 20 {
			continue // 非法 IP 包（不够 header 长度），丢弃
		}
		// 拷贝一份，避免下次 Read 覆盖
		data := make([]byte, n)
		copy(data, pktBuf[:n])
		pk := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(data),
		})
		ns.Link.InjectInbound(ipv4.ProtocolNumber, pk)
	}
}
