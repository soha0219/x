// ech-proxy-core.go - v5.1 (X-Link Protocol Kernel - Compile Fixed)
// 纯净版内核：移除 ECH，使用标准 TLS + WebSocket + 私有握手
package main

import (
	"bufio"
	"bytes"
	// "context" // 移除
	"crypto/tls"
	"encoding/base64"
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
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ======================== Config Structures ========================

type Config struct {
	Inbounds  []Inbound  `json:"inbounds"`
	Outbounds []Outbound `json:"outbounds"`
	Routing   Routing    `json:"routing"`
}
type Inbound struct {
	Tag      string `json:"tag"`
	Listen   string `json:"listen"`
	Protocol string `json:"protocol"`
}
type Outbound struct {
	Tag      string          `json:"tag"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings,omitempty"`
}
type ProxySettings struct { // 简化了设置
	Server    string `json:"server"`
	ServerIP  string `json:"server_ip"`
	Token     string `json:"token"`
}
type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"` // 【【核心修正】】
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	GeoIP       string   `json:"geoip,omitempty"`
	Port        []int    `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// ======================== Global State ========================

var (
	globalConfig      Config
	proxySettingsMap  = make(map[string]ProxySettings)
	chinaIPRanges     []ipRange
	chinaIPV6Ranges   []ipRangeV6
	chinaIPRangesMu   sync.RWMutex
	chinaIPV6RangesMu sync.RWMutex
)

type ipRange struct { start uint32; end uint32 }
type ipRangeV6 struct { start [16]byte; end [16]byte }

// ======================== Main Logic ========================

func main() {
	configPath := flag.String("c", "config.json", "Path to the configuration file")
	flag.Parse()

	log.Println("[Core] X-Link Kernel v1.0 Starting...")
	log.Println("[Core] Loading configuration from", *configPath)
	file, err := os.ReadFile(*configPath); if err != nil { log.Fatalf("[Fatal] Failed to read config: %v", err) }
	if err := json.Unmarshal(file, &globalConfig); err != nil { log.Fatalf("[Fatal] Config parse error: %v", err) }

	loadChinaListsForRouter()
	parseOutbounds()

	var wg sync.WaitGroup
	for _, inbound := range globalConfig.Inbounds {
		wg.Add(1)
		go func(ib Inbound) {
			defer wg.Done()
			runInbound(ib)
		}(inbound)
	}
	log.Println("[Core] Engine started. Waiting for connections...")
	wg.Wait()
}

func parseOutbounds() {
	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" { // GUI生成的名字没变，内核里兼容一下
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				proxySettingsMap[outbound.Tag] = settings
			}
		}
	}
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
	clientAddr := conn.RemoteAddr().String()
	
	buf := make([]byte, 1); if _, err := io.ReadFull(conn, buf); err != nil { return }

	var target string
	var err error
	var firstFrame []byte
	var mode int

	switch buf[0] {
	case 0x05:
		err = handleSOCKS5(conn, clientAddr, inboundTag)
		if err != nil { log.Printf("[%s] SOCKS5 Error: %v", inboundTag, err) }
		return
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		target, firstFrame, mode, err = parseHTTP(conn, clientAddr, buf[0], inboundTag)
	default:
		return // Unknown protocol
	}
	
	if err != nil { return }

	outboundTag := route(target, inboundTag)
	dispatch(conn, target, outboundTag, firstFrame, mode)
}

// ======================== Routing Logic (Standard) ========================

func route(target, inboundTag string) string {
	host, portStr, _ := net.SplitHostPort(target); if host == "" { host = target }
	port, _ := strconv.Atoi(portStr)

	for _, rule := range globalConfig.Routing.Rules {
		// Inbound Tag Matching
		if len(rule.InboundTag) > 0 {
			match := false
			for _, t := range rule.InboundTag { if t == inboundTag { match = true; break } }
			if !match { continue }
		}

		// Domain Matching
		if len(rule.Domain) > 0 {
			for _, d := range rule.Domain { if strings.Contains(host, d) { return rule.OutboundTag } }
		}

		// GeoIP Matching
		if rule.GeoIP == "cn" {
			if isChinaIPForRouter(net.ParseIP(host)) { return rule.OutboundTag }
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) { return rule.OutboundTag }
		}
		
		// Port Matching
		if len(rule.Port) > 0 {
			for _, p := range rule.Port { if p == port { return rule.OutboundTag } }
		}

		// Catch-all (empty rule)
		if len(rule.Domain)==0 && rule.GeoIP=="" && len(rule.Port)==0 && len(rule.InboundTag)==0 {
			return rule.OutboundTag
		}
	}
	
	// 【【【核心修正】】】
	if globalConfig.Routing.DefaultOutbound != "" {
		return globalConfig.Routing.DefaultOutbound
	}
    
    return "direct" // 最终的回退
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	outbound, found := findOutbound(outboundTag)
	if !found { return }
	
	switch outbound.Protocol {
	case "freedom": handleDirect(conn, target, firstFrame, mode)
	case "blackhole": conn.Close()
	case "ech-proxy": handleProxy(conn, target, outboundTag, firstFrame, mode)
	}
}

// ======================== Proxy Logic (X-Link Protocol) ========================

const ( modeSOCKS5 = 1; modeHTTPConnect = 2; modeHTTPProxy = 3 )

func handleSOCKS5(conn net.Conn, clientAddr, inboundTag string) error {
	handshakeBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, handshakeBuf); err != nil { return err }
	conn.Write([]byte{0x05, 0x00})
	
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil { return err }
	
	cmd, atyp := header[1], header[3]
	var host string
	switch atyp {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	default: return errors.New("bad addr type")
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	if cmd == 0x01 { // CONNECT
		log.Printf("[%s] SOCKS5: %s -> %s", inboundTag, clientAddr, target)
		outboundTag := route(target, inboundTag)
		if outboundTag != "direct" && outboundTag != "block" {
			log.Printf("[%s] %s -> %s | Routed to [%s]", inboundTag, clientAddr, target, outboundTag)
		}
		dispatch(conn, target, outboundTag, nil, modeSOCKS5)
	}
	return nil
}

func parseHTTP(conn net.Conn, clientAddr string, firstByte byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), conn))
	req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }
	if req.Method == "CONNECT" {
		log.Printf("[%s] HTTP: %s -> CONNECT %s", inboundTag, clientAddr, req.Host)
		return req.Host, nil, modeHTTPConnect, nil
	}
	// Normal HTTP
	var buf bytes.Buffer
	req.WriteProxy(&buf)
	return req.URL.Host, buf.Bytes(), modeHTTPProxy, nil
}

func handleDirect(clientConn net.Conn, target string, firstFrame []byte, mode int) error {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { return err }
	defer remote.Close()
	if mode == modeSOCKS5 { clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if mode == modeHTTPConnect { clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) }
	if len(firstFrame) > 0 { remote.Write(firstFrame) }
	go io.Copy(remote, clientConn)
	io.Copy(clientConn, remote)
	return nil
}

// 【核心修改】X-Link 协议握手
func handleProxy(clientConn net.Conn, target, outboundTag string, firstFrame []byte, mode int) error {
	wsConn, err := dialSpecificWebSocket(outboundTag); if err != nil { return err }
	defer wsConn.Close()

	// 1. 发送私有握手包: X-LINK:target|payload
	connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil { return err }
	
	// 2. 等待服务端确认 (X-LINK-OK)
	_, msg, err := wsConn.ReadMessage()
	if err != nil || string(msg) != "X-LINK-OK" { 
		return fmt.Errorf("X-Link handshake failed: %s", string(msg)) 
	}

	// 3. 响应本地客户端
	if mode == modeSOCKS5 { clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if mode == modeHTTPConnect { clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) }

	// 4. 双向转发
	done := make(chan bool, 2)
	go func() { 
		buf := make([]byte, 32*1024)
		for { 
			n, err := clientConn.Read(buf)
			if err != nil { wsConn.WriteMessage(websocket.CloseMessage, []byte{}); done<-true; return }
			wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()
	go func() { 
		for { 
			_, msg, err := wsConn.ReadMessage()
			if err != nil { clientConn.Close(); done<-true; return }
			clientConn.Write(msg)
		} 
	}()
	<-done
	return nil
}

// 【核心修改】标准 TLS WebSocket 连接
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }
	
	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)
	
	// 标准 TLS 配置
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: host,
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 10 * time.Second,
		Subprotocols:     []string{settings.Token},
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(n, a string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(a)
			return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, _, err := dialer.Dial(wsURL, nil)
	return conn, err
}

// ... (Helpers) ...
func findOutbound(tag string) (Outbound, bool) { for _, ob := range globalConfig.Outbounds { if ob.Tag == tag { return ob, true } }; return Outbound{}, false }
func getExeDir() string { exePath, err := os.Executable(); if err != nil { return "." }; return filepath.Dir(exePath) }
func ipToUint32(ip net.IP) uint32 { ip = ip.To4(); if ip == nil { return 0 }; return binary.BigEndian.Uint32(ip) }
func isChinaIPForRouter(ip net.IP) bool { if ip == nil { return false }; if ip4 := ip.To4(); ip4 != nil { val := ipToUint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock(); for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } } } else if ip16 := ip.To16(); ip16 != nil { var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock(); for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } } }; return false }
func loadChinaListsForRouter() { loadIPListForRouter("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false); loadIPListForRouter("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true) }
func loadIPListForRouter(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) { 
	filePath := filepath.Join(getExeDir(), filename)
	file, err := os.Open(filePath); if err != nil { return }
	defer file.Close()
	var rangesV4 []ipRange; var rangesV6 []ipRangeV6
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) < 2 { continue }
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1])
		if startIP == nil || endIP == nil { continue }
		if isV6 {
			var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16())
			rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e})
		} else {
			s, e := ipToUint32(startIP), ipToUint32(endIP)
			if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) }
		}
	}
	mu.Lock(); defer mu.Unlock()
	if isV6 { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6)) } else { reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4)) }
}
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); return }
