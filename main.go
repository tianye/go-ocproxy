package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/doctor/go-ocproxy/internal/socks"
	"github.com/doctor/go-ocproxy/internal/stack"
)

const (
	Version = "1.0.0 (Go-gVisor rewrite)"
)

func main() {
	// 严格对齐 ocproxy 的参数规范
	socksPort := flag.String("D", "1080", "SOCKS5 dynamic port forward (standard ocproxy flag)")
	showVersion := flag.Bool("V", false, "Show version information")
	
	// 其它可选参数
	localIP := flag.String("ip", "", "Internal IPv4 address")
	mtu := flag.Int("mtu", 1500, "MTU")
	
	flag.Parse()

	// 如果指定了 -V，打印版本并退出
	if *showVersion {
		fmt.Printf("go-ocproxy version: %s\n", Version)
		fmt.Println("A modern rewrite of ocproxy using Google's gVisor netstack.")
		return
	}

	// 1. 读取 OpenConnect 环境变量
	envIP := os.Getenv("INTERNAL_IP4_ADDRESS")
	if *localIP == "" {
		*localIP = envIP
	}
	if *localIP == "" {
		log.Fatal("Internal IP address not set. Use -ip or run via openconnect.")
	}

	envMTU := os.Getenv("INTERNAL_IP4_MTU")
	if envMTU != "" {
		m, err := strconv.Atoi(envMTU)
		if err == nil {
			*mtu = m
		}
	}

	// 读取 DNS
	dnsServers := []string{}
	envDNS := os.Getenv("INTERNAL_IP4_DNS")
	if envDNS != "" {
		dnsServers = strings.Fields(envDNS)
	}

	listenAddr := "127.0.0.1:" + *socksPort

	// 明确标识 Go 版本
	log.Printf("-----------------------------------------")
	log.Printf("  go-ocproxy %s", Version)
	log.Printf("  Based on Google gVisor Netstack")
	log.Printf("-----------------------------------------")
	log.Printf("Listening:   %s (SOCKS5)", listenAddr)
	log.Printf("Internal IP: %s", *localIP)
	log.Printf("DNS Servers: %v", dnsServers)

	// 2. 初始化 gVisor 网络栈
	ns, err := stack.NewNetStack(*localIP, uint32(*mtu))
	if err != nil {
		log.Fatalf("Failed to initialize netstack: %v", err)
	}

	// 3. 启动 SOCKS5 服务
	server := socks.NewServer(ns, listenAddr, dnsServers)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Printf("SOCKS5 server error: %v", err)
		}
	}()

	// 4. 处理退出信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down go-ocproxy...")
		os.Exit(0)
	}()

	// 5. 阻塞运行协议栈 I/O
	if err := ns.Run(os.Stdin, os.Stdout); err != nil {
		if err != os.ErrClosed && !strings.Contains(err.Error(), "file already closed") {
			log.Fatalf("Netstack runtime error: %v", err)
		}
	}
}
