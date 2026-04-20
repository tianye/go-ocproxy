package stack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"

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
	//
	// ⚠️ 历史 bug：早期代码在 output.Write 出错时直接 return，使整个出向 goroutine
	// 永久退出，后续 gVisor 产生的所有出向包都静默堆积在 channel 里，表现为
	// "浏览器并发请求几秒后全部 hang，DNS/TCP 集体超时且不恢复"。
	//
	// 真正的致命错误（fd 已关闭、EPIPE）才应该退出。瞬时错误（ENOBUFS：
	// AF_UNIX SOCK_DGRAM 发送缓冲被 burst 打满；EMSGSIZE：单包超限）是可恢复的，
	// 只 drop 这一个包，继续读下一个。
	go func() {
		for {
			pkt := ns.Link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			buf := pkt.ToBuffer()
			_, err := output.Write(buf.Flatten())
			buf.Release()
			if err == nil {
				continue
			}
			if isFatalWriteErr(err) {
				log.Printf("outbound write fatal, exiting: %v", err)
				return
			}
			log.Printf("outbound write transient (dropping 1 pkt): %v", err)
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

// isFatalWriteErr 判断写 VPN 出错是否致命，致命则出向 goroutine 该退出。
// 非致命（例如 ENOBUFS 的瞬时缓冲打满、EMSGSIZE 的单包超限）只丢当前包继续跑，
// 不能因为一次可恢复的错误就把整个出向链路永久打死。
func isFatalWriteErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed) {
		return true
	}
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.EBADF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ENOTCONN) {
		return true
	}
	return false
}
