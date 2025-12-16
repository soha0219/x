

// core/core-binary.go (v3.3 - Pure Binary)
// 职责：只处理纯二进制流协议，性能最高。
// 兼容：X-Link Server v3.3

//go:build binary
// +build binary

package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy"
	"encoding/json"
	"net/url"
)

// ... (Structs 保持不变) ...
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"`; ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }
var ( globalConfig Config; proxySettingsMap = make(map[string]ProxySettings) )

// ======================== Entry Point ========================
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil { return nil, err }
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	log.Printf("[Core] Titan Engine v3.3 (Pure Binary) Listening on %s", inbound.Listen)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil { break }
			go handleGeneralConnection(conn, inbound.Tag)
		}
	}()
	return listener, nil
}

func parseOutbounds() {
	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			var settings ProxySettings
			if err := json.Unmarshal(outbound.Settings, &settings); err == nil {
				proxySettingsMap[outbound.Tag] = settings
			}
		}
	}
}

// 【核心简化】：只走二进制逻辑
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
		target, err = handleSOCKS5(conn, inboundTag)
		mode = 1
	default:
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}
	if err != nil { return }
	
	wsConn, err := tryBinaryHandshake(target, "proxy", firstFrame)
	if err != nil {
		log.Printf("[ERROR] Binary connection to %s failed: %v", target, err)
		return
	}
	
	log.Printf("[Success] Tunnel for %s established via Binary Protocol", target)

	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }
	
	pipeBinary(conn, wsConn)
}

func tryBinaryHandshake(target, tag string, frame []byte) (*websocket.Conn, error) {
	wsConn, err := dialSpecificWebSocket(tag)
	if err != nil { return nil, err }
	
	wsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer wsConn.SetReadDeadline(time.Time{})
	
	var buf bytes.Buffer
	buf.Write([]byte{0x01, 0x01})
	host, portStr, _ := net.SplitHostPort(target)
	portInt, _ := net.LookupPort("tcp", portStr)
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		buf.WriteByte(0x01); buf.Write(ip4)
	} else {
		buf.WriteByte(0x03); buf.WriteByte(byte(len(host))); buf.WriteString(host)
	}
	portBytes := make([]byte, 2); binary.BigEndian.PutUint16(portBytes, uint16(portInt))
	buf.Write(portBytes)
	if len(frame) > 0 { buf.Write(frame) }

	if err := wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil { wsConn.Close(); return nil, err }
	
	_, msg, err := wsConn.ReadMessage()
	if err != nil { wsConn.Close(); return nil, err }
	if len(msg) < 2 || msg[0] != 0x01 || msg[1] != 0x00 { wsConn.Close(); return nil, errors.New("binary response invalid") }
	
	return wsConn, nil
}

// ... (pipeBinary, handleSOCKS5, handleHTTP, dialSpecificWebSocket 等函数保持不变) ...
func pipeBinary(local net.Conn, ws *websocket.Conn) { defer ws.Close(); go func() { for { mt, r, err := ws.NextReader(); if err != nil { break }; if mt == websocket.BinaryMessage { io.Copy(local, r) } }; local.Close() }(); buf := make([]byte, 32*1024); for { n, err := local.Read(buf); if n > 0 { w, err := ws.NextWriter(websocket.BinaryMessage); if err != nil { break }; w.Write(buf[:n]); w.Close() }; if err != nil { break } } }
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) { settings, ok := proxySettingsMap[outboundTag]; if !ok { return nil, errors.New("settings not found") }; host, port, path, _ := parseServerAddr(settings.Server); wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path); requestHeader := http.Header{}; requestHeader.Add("Host", host); requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"); requestHeader.Add("Origin", fmt.Sprintf("https://%s", host)); dialer := websocket.Dialer{ TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: host}, HandshakeTimeout: 5 * time.Second, }; if settings.ForwarderSettings != nil && settings.ForwarderSettings.Socks5Address != "" { proxyAddrStr := settings.ForwarderSettings.Socks5Address; log.Printf("[Core] Using SOCKS5 proxy: %s", proxyAddrStr); var auth *proxy.Auth; var socksAddress string; if !strings.Contains(proxyAddrStr, "://") { proxyAddrStr = "socks5://" + proxyAddrStr }; proxyURL, err := url.Parse(proxyAddrStr); if err != nil { return nil, err }; socksAddress = proxyURL.Host; if proxyURL.User != nil { auth = new(proxy.Auth); auth.User = proxyURL.User.Username(); if password, ok := proxyURL.User.Password(); ok { auth.Password = password } }; socks5Dialer, err := proxy.SOCKS5("tcp", socksAddress, auth, proxy.Direct); if err != nil { return nil, err }; dialer.NetDial = socks5Dialer.Dial } else if settings.ServerIP != "" { dialer.NetDial = func(network, addr string) (net.Conn, error) { _, p, _ := net.SplitHostPort(addr); return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second) } }; if settings.Token != "" { dialer.Subprotocols = []string{settings.Token} }; conn, resp, err := dialer.Dial(wsURL, requestHeader); if err != nil { if resp != nil { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }; return nil, err }; return conn, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host = addr; port = "443"; err = nil }; return }
