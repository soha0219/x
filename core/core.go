// core/core.go (v3.5 - Smart Sequential Fallback)
// 特性：
// 1. 智能串行：按“二进制 -> 混合 -> JSON”顺序尝试，逻辑清晰，行为可预测。
// 2. 快速失败：每个阶段使用短超时，避免了 v3.2 的长时间等待。
// 3. 稳定通吃：完美兼容 v3.3, v2.7, v2.6 及所有旧版服务端。
package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/net/proxy" 
)

// ... (Structs and Helpers 保持不变) ...
// ======================== Structs ========================
type JsonEnvelope struct { ID string `json:"id"`; Type string `json:"type"`; TS int64 `json:"ts"`; Data string `json:"data"` }
type Config struct { Inbounds []Inbound `json:"inbounds"`; Outbounds []Outbound `json:"outbounds"`; Routing Routing `json:"routing"` }
type Inbound struct { Tag string `json:"tag"`; Listen string `json:"listen"`; Protocol string `json:"protocol"` }
type Outbound struct { Tag string `json:"tag"`; Protocol string `json:"protocol"`; Settings json.RawMessage `json:"settings,omitempty"` }
type ProxyForwarderSettings struct { Socks5Address string `json:"socks5_address"` }
type ProxySettings struct { Server string `json:"server"`; ServerIP string `json:"server_ip"`; Token string `json:"token"`; ForwarderSettings *ProxyForwarderSettings `json:"proxy_settings,omitempty"` }
type Routing struct { Rules []Rule `json:"rules"`; DefaultOutbound string `json:"defaultOutbound,omitempty"` }
type Rule struct { InboundTag []string `json:"inboundTag,omitempty"`; Domain []string `json:"domain,omitempty"`; GeoIP string `json:"geoip,omitempty"`; Port []int `json:"port,omitempty"`; OutboundTag string `json:"outboundTag"` }
var ( globalConfig Config; proxySettingsMap = make(map[string]ProxySettings) )
// ======================== Helpers ========================
func wrapAsJson(payload []byte) ([]byte, error) { idBytes := make([]byte, 4); rand.Read(idBytes); envelope := JsonEnvelope{ ID: fmt.Sprintf("msg_%x", idBytes), Type: "sync_data", TS: time.Now().UnixMilli(), Data: base64.StdEncoding.EncodeToString(payload) }; return json.Marshal(envelope) }
func unwrapFromJson(rawMsg []byte) ([]byte, error) { var envelope JsonEnvelope; if err := json.Unmarshal(rawMsg, &envelope); err != nil { return nil, err }; if envelope.Type == "pong" { return nil, nil }; if envelope.Type != "sync_data" { return nil, errors.New("not sync_data") }; return base64.StdEncoding.DecodeString(envelope.Data) }


// ======================== Entry Point ========================
func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}
	parseOutbounds()
	if len(globalConfig.Inbounds) == 0 {
		return nil, errors.New("no inbounds")
	}
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil {
		return nil, err
	}
	log.Printf("[Core] Titan Engine v3.5 (Smart Sequential) Listening on %s", inbound.Listen)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				break
			}
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

// 【核心改造】: handleGeneralConnection 现在使用智能串行回退
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

	// 【智能串行回退】
	var wsConn *websocket.Conn
	var proto string

	// 1. 尝试二进制
	log.Printf("[Probe] Trying Binary protocol for %s...", target)
	wsConn, err = tryHandshake(target, "proxy", firstFrame, "binary")
	if err == nil {
		proto = "binary"
	} else {
		// 2. 尝试混合
		log.Printf("[Probe] Binary failed (%v), trying Hybrid protocol...", err)
		wsConn, err = tryHandshake(target, "proxy", firstFrame, "hybrid")
		if err == nil {
			proto = "hybrid"
		} else {
			// 3. 尝试纯 JSON
			log.Printf("[Probe] Hybrid failed (%v), trying JSON protocol...", err)
			wsConn, err = tryHandshake(target, "proxy", firstFrame, "json")
			if err == nil {
				proto = "json"
			}
		}
	}

	if err != nil {
		log.Printf("[ERROR] All protocols failed for %s: %v", target, err)
		return
	}
	
	log.Printf("[Success] Tunnel for %s established via %s Protocol", target, strings.ToUpper(proto))

	if mode == 1 { conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }

	if proto == "binary" {
		pipeBinary(conn, wsConn)
	} else { // "json" or "hybrid"
		pipeJSON(conn, wsConn)
	}
}

// 【核心新增】: tryHandshake - 一个函数处理所有握手逻辑
func tryHandshake(target, outboundTag string, firstFrame []byte, proto string) (*websocket.Conn, error) {
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			wsConn.Close()
		}
	}()

	// 使用快速失败的短超时
	wsConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer wsConn.SetReadDeadline(time.Time{})

	switch proto {
	case "binary":
		buf := buildBinaryHandshake(target, firstFrame)
		err = wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
		if err != nil { return nil, err }
		
		_, msg, err := wsConn.ReadMessage()
		if err != nil { return nil, err }
		if len(msg) < 2 || msg[0] != 0x01 || msg[1] != 0x00 {
			return nil, errors.New("binary response invalid")
		}
		return wsConn, nil

	case "hybrid":
		buf := buildBinaryHandshake(target, firstFrame)
		err = wsConn.WriteMessage(websocket.BinaryMessage, buf.Bytes())
		if err != nil { return nil, err }
		
		_, msg, err := wsConn.ReadMessage()
		if err != nil { return nil, err }
		
		ok, err := unwrapFromJson(msg)
		if err != nil || string(ok) != "X-LINK-OK" {
			return nil, errors.New("hybrid response invalid")
		}
		return wsConn, nil

	case "json":
		connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
		jsonHandshake, _ := wrapAsJson([]byte(connectMsg))
		err = wsConn.WriteMessage(websocket.TextMessage, jsonHandshake)
		if err != nil { return nil, err }
		
		_, msg, err := wsConn.ReadMessage()
		if err != nil { return nil, err }
		
		ok, err := unwrapFromJson(msg)
		if err != nil || string(ok) != "X-LINK-OK" {
			return nil, errors.New("json response invalid")
		}
		return wsConn, nil
	}
	
	return nil, errors.New("unknown protocol")
}


// 辅助：构建二进制握手包
func buildBinaryHandshake(target string, firstFrame []byte) *bytes.Buffer {
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
	if len(firstFrame) > 0 { buf.Write(firstFrame) }
	return &buf
}

// ... (pipeBinary, pipeJSON, handleSOCKS5, handleHTTP, dialSpecificWebSocket 等函数与 v3.3/v3.4 保持一致) ...
func pipeBinary(local net.Conn, ws *websocket.Conn) { defer ws.Close(); go func() { for { mt, r, err := ws.NextReader(); if err != nil { break }; if mt == websocket.BinaryMessage { io.Copy(local, r) } }; local.Close() }(); buf := make([]byte, 32*1024); for { n, err := local.Read(buf); if n > 0 { w, err := ws.NextWriter(websocket.BinaryMessage); if err != nil { break }; w.Write(buf[:n]); w.Close() }; if err != nil { break } } }
func pipeJSON(local net.Conn, ws *websocket.Conn) { defer ws.Close(); go func() { for { _, msg, err := ws.ReadMessage(); if err != nil { break }; payload, _ := unwrapFromJson(msg); if payload != nil { local.Write(payload) } }; local.Close() }(); buf := make([]byte, 32*1024); for { n, err := local.Read(buf); if n > 0 { jsonData, _ := wrapAsJson(buf[:n]); ws.WriteMessage(websocket.TextMessage, jsonData) }; if err != nil { break } } }
func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) { handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf); conn.Write([]byte{0x05, 0x00}); header := make([]byte, 4); io.ReadFull(conn, header); var host string; switch header[3] { case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String(); case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d); case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String() }; portBytes := make([]byte, 2); io.ReadFull(conn, portBytes); port := binary.BigEndian.Uint16(portBytes); return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil }
func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) { reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn)); req, err := http.ReadRequest(reader); if err != nil { return "", nil, 0, err }; target := req.Host; if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }; if req.Method == "CONNECT" { return target, nil, 2, nil }; var buf bytes.Buffer; req.WriteProxy(&buf); return target, buf.Bytes(), 3, nil }
func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) { settings, ok := proxySettingsMap[outboundTag]; if !ok { return nil, errors.New("settings not found") }; host, port, path, _ := parseServerAddr(settings.Server); wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path); requestHeader := http.Header{}; requestHeader.Add("Host", host); requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"); requestHeader.Add("Origin", fmt.Sprintf("https://%s", host)); dialer := websocket.Dialer{ TLSClientConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: host}, HandshakeTimeout: 5 * time.Second, }; if settings.ForwarderSettings != nil && settings.ForwarderSettings.Socks5Address != "" { proxyAddrStr := settings.ForwarderSettings.Socks5Address; log.Printf("[Core] Using SOCKS5 proxy: %s", proxyAddrStr); var auth *proxy.Auth; var socksAddress string; if !strings.Contains(proxyAddrStr, "://") { proxyAddrStr = "socks5://" + proxyAddrStr }; proxyURL, err := url.Parse(proxyAddrStr); if err != nil { return nil, err }; socksAddress = proxyURL.Host; if proxyURL.User != nil { auth = new(proxy.Auth); auth.User = proxyURL.User.Username(); if password, ok := proxyURL.User.Password(); ok { auth.Password = password } }; socks5Dialer, err := proxy.SOCKS5("tcp", socksAddress, auth, proxy.Direct); if err != nil { return nil, err }; dialer.NetDial = socks5Dialer.Dial } else if settings.ServerIP != "" { dialer.NetDial = func(network, addr string) (net.Conn, error) { _, p, _ := net.SplitHostPort(addr); return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second) } }; if settings.Token != "" { dialer.Subprotocols = []string{settings.Token} }; conn, resp, err := dialer.Dial(wsURL, requestHeader); if err != nil { if resp != nil { return nil, fmt.Errorf("HTTP %d", resp.StatusCode) }; return nil, err }; return conn, nil }
func parseServerAddr(addr string) (host, port, path string, err error) { path = "/"; if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }; host, port, err = net.SplitHostPort(addr); if err != nil { host = addr; port = "443"; err = nil }; return }
