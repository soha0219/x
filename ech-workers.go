// ech-proxy-core.go - v12.0 (The Minimalist)
// 协议内核：【最终破局版】
// 1. 回归 v1.2 成功的经验：发起一个绝对干净的 WebSocket 握手，不带任何自定义 Header。
// 2. 采用 v5.1 的隧道内认证方案，确保隧道安全。
// 3. 包含了所有必要的 Bug 修复（SOCKS5, 编译错误等）。
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== Config Structures ========================
type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
}
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"` }

// ======================== Global State ========================
var proxySettingsMap = make(map[string]ProxySettings)

// ======================== Main Logic ========================
func main() {
	configPath := flag.String("c", "config.json", "Path to config")
	flag.Parse()
	log.Println("[Core] X-Link Kernel v12.0 (The Minimalist) Starting...")
	
	file, err := os.ReadFile(*configPath)
	if err != nil { log.Fatalf("Failed to read config: %v", err) }

	var globalConfig Config
	if err := json.Unmarshal(file, &globalConfig); err != nil { log.Fatalf("Config parse error: %v", err) }

	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				proxySettingsMap[outbound.Tag] = settings
			}
		}
	}

	var wg sync.WaitGroup
	for _, inbound := range globalConfig.Inbounds {
		wg.Add(1)
		go func(ib Inbound) { defer wg.Done(); runInbound(ib) }(inbound)
	}
	log.Println("[Core] Engine started.")
	wg.Wait()
}

func runInbound(ib Inbound) {
	listener, err := net.Listen("tcp", ib.Listen)
	if err != nil { log.Printf("[Error] Listen failed on %s: %v", ib.Listen, err); return }
	log.Printf("[Inbound] Listening on %s (%s)", ib.Listen, ib.Tag)
	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		go handleGeneralConnection(conn, ib.Tag)
	}
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil { return }
	var target string
	var err error
	var firstFrame []byte
	var mode int
	switch buf[0] {
	case 0x05:
		target, err = handleSOCKS5(conn)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf)
	}
	if err != nil { return }
	outboundTag := "proxy" // Simplified routing
	log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, conn.RemoteAddr().String(), target, outboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

func handleSOCKS5(conn net.Conn) (string, error) {
	handshakeBuf := make([]byte, 2); if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return "", err }
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4); if _, err := io.ReadFull(conn, header); err != nil { return "", err }
	if header[1] != 0x01 { conn.Write([]byte{0x05, 0x07, 0x00, 0x01}); return "", errors.New("unsupported command") }
	var host string
	switch header[3] {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	default: return "", errors.New("bad addr type")
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil { return "", nil, 0, err }
	if req.Method == "CONNECT" { return req.Host, nil, 2, nil }
	var buf bytes.Buffer; req.WriteProxy(&buf); return req.Host, buf.Bytes(), 3, nil
}

const ( modeSOCKS5 = 1; modeHTTPConnect = 2; modeHTTPProxy = 3 )

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	err := startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
	if err != nil { log.Printf("Tunnel failed for %s: %v", target, err) }
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	if mode == modeSOCKS5 && len(firstFrame) == 0 {
		local.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buffer := make([]byte, 32*1024)
		n, readErr := local.Read(buffer)
		local.SetReadDeadline(time.Time{})
		if n > 0 { firstFrame = buffer[:n] }
		if readErr != nil && !os.IsTimeout(readErr) && readErr != io.EOF { return readErr }
	}

	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
		if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")) }
		return err
	}
	defer wsConn.Close()

	var handshakeBuf bytes.Buffer
	settings, _ := proxySettingsMap[outboundTag]
	tokenBytes := []byte(settings.Token)

	tokenLen := uint16(len(tokenBytes)); binary.Write(&handshakeBuf, binary.BigEndian, tokenLen)
	handshakeBuf.Write(tokenBytes)

	addrLen := uint16(len(target)); binary.Write(&handshakeBuf, binary.BigEndian, addrLen)
	handshakeBuf.WriteString(target)

	if len(firstFrame) > 0 { handshakeBuf.Write(firstFrame) }
	if err := wsConn.WriteMessage(websocket.BinaryMessage, handshakeBuf.Bytes()); err != nil { return err }

	if mode == modeSOCKS5 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == modeHTTPConnect { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }

	done := make(chan bool, 2)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if err != nil { wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); done <- true; return }
			if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { done <- true; return }
		}
	}()
	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil { local.Close(); done <- true; return }
			if _, err := local.Write(msg); err != nil { done <- true; return }
		}
	}()
	<-done; return nil
}

// 【核心修改】回归 v1.2 的成功模式：绝对干净的握手
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	host, port, _, err := parseServerAddr(settings.Server)
	if err != nil { return nil, fmt.Errorf("invalid server address: %w", err) }

	// 1. 构造一个干净的 URL，路径为 "/"
	wsURL := fmt.Sprintf("wss://%s:%s/", host, port)
	
	tlsCfg := &tls.Config{ MinVersion: tls.VersionTLS13, ServerName: host }
	
	// 2. 不添加任何自定义 Header，保持 Dialer 的默认行为
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}
	
	// 3. 执行干净的握手，第二个参数传 nil
	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
}

func parseServerAddr(addr string) (host, port, path string, err error) { 
    path = "/"
    if idx := strings.Index(addr, "/"); idx != -1 { 
        path = addr[idx:]
        addr = addr[:idx] 
    }
    host, port, err = net.SplitHostPort(addr)
    return 
}
