// core/core.go (Debug Version)
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
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

type JsonEnvelope struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	TS   int64  `json:"ts"`
	Data string `json:"data"`
}

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
type ProxySettings struct {
	Server   string `json:"server"`
	ServerIP string `json:"server_ip"`
	Token    string `json:"token"`
}
type Routing struct {
	Rules           []Rule `json:"rules"`
	DefaultOutbound string `json:"defaultOutbound,omitempty"`
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	GeoIP       string   `json:"geoip,omitempty"`
	Port        []int    `json:"port,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

var (
	globalConfig     Config
	proxySettingsMap = make(map[string]ProxySettings)
)

func wrapAsJson(payload []byte) ([]byte, error) {
	idBytes := make([]byte, 4)
	rand.Read(idBytes)
	envelope := JsonEnvelope{
		ID:   fmt.Sprintf("msg_%x", idBytes),
		Type: "sync_data",
		TS:   time.Now().UnixMilli(),
		Data: base64.StdEncoding.EncodeToString(payload),
	}
	return json.Marshal(envelope)
}

func unwrapFromJson(rawMsg []byte) ([]byte, error) {
	var envelope JsonEnvelope
	if err := json.Unmarshal(rawMsg, &envelope); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}
	if envelope.Type == "pong" { return nil, nil }
	if envelope.Type != "sync_data" { return nil, errors.New("not sync_data") }
	return base64.StdEncoding.DecodeString(envelope.Data)
}

func StartInstance(configContent []byte) (net.Listener, error) {
	proxySettingsMap = make(map[string]ProxySettings)
	if err := json.Unmarshal(configContent, &globalConfig); err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}
	parseOutbounds()

	if len(globalConfig.Inbounds) == 0 { return nil, errors.New("no inbounds") }
	inbound := globalConfig.Inbounds[0]
	listener, err := net.Listen("tcp", inbound.Listen)
	if err != nil { return nil, err }
	log.Printf("[Core] Listening on %s", inbound.Listen)

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
		// 简单处理 HTTP/其他
		target, firstFrame, mode, err = handleHTTP(conn, buf, inboundTag)
	}

	if err != nil {
		log.Printf("[ERROR] Protocol error: %v", err)
		return
	}

	log.Printf("[%s] Request -> %s", inboundTag, target)
	dispatch(conn, target, "proxy", firstFrame, mode)
}

func handleSOCKS5(conn net.Conn, inboundTag string) (string, error) {
	handshakeBuf := make([]byte, 2); io.ReadFull(conn, handshakeBuf)
	conn.Write([]byte{0x05, 0x00})
	header := make([]byte, 4); io.ReadFull(conn, header)
	var host string
	switch header[3] {
	case 1: b := make([]byte, 4); io.ReadFull(conn, b); host = net.IP(b).String()
	case 3: b := make([]byte, 1); io.ReadFull(conn, b); d := make([]byte, b[0]); io.ReadFull(conn, d); host = string(d)
	case 4: b := make([]byte, 16); io.ReadFull(conn, b); host = net.IP(b).String()
	}
	portBytes := make([]byte, 2); io.ReadFull(conn, portBytes)
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

func handleHTTP(conn net.Conn, initialData []byte, inboundTag string) (string, []byte, int, error) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader(initialData), conn))
	req, err := http.ReadRequest(reader)
	if err != nil { return "", nil, 0, err }
	target := req.Host
	if !strings.Contains(target, ":") { if req.Method == "CONNECT" { target += ":443" } else { target += ":80" } }
	if req.Method == "CONNECT" { return target, nil, 2, nil }
	var buf bytes.Buffer; req.WriteProxy(&buf)
	return target, buf.Bytes(), 3, nil
}

func dispatch(conn net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	startProxyTunnel(conn, target, outboundTag, firstFrame, mode)
}

func startProxyTunnel(local net.Conn, target, outboundTag string, firstFrame []byte, mode int) {
	// 1. 连接 WebSocket
	wsConn, err := dialSpecificWebSocket(outboundTag)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to proxy: %v", err)
		local.Close()
		return
	}
	defer wsConn.Close()

	// 2. 发送握手
	log.Printf("[Debug] Sending handshake for %s", target)
	connectMsg := fmt.Sprintf("X-LINK:%s|%s", target, base64.StdEncoding.EncodeToString(firstFrame))
	jsonHandshake, _ := wrapAsJson([]byte(connectMsg))
	if err := wsConn.WriteMessage(websocket.TextMessage, jsonHandshake); err != nil {
		log.Printf("[ERROR] Failed to send handshake: %v", err)
		return
	}

	// 3. 等待响应
	log.Printf("[Debug] Waiting for handshake response...")
	wsConn.SetReadDeadline(time.Now().Add(10 * time.Second)) // 设置10秒超时
	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		log.Printf("[ERROR] Failed to read response: %v", err)
		return
	}
	wsConn.SetReadDeadline(time.Time{}) // 取消超时

	okPayload, err := unwrapFromJson(msg)
	if err != nil {
		log.Printf("[ERROR] Invalid response format: %v", err)
		return
	}
	
	respStr := string(okPayload)
	if respStr != "X-LINK-OK" {
		log.Printf("[ERROR] Handshake rejected by server. Response: %s", respStr)
		return
	}

	log.Printf("[Success] Tunnel established for %s", target)

	// 4. 响应本地
	if mode == 1 { local.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) }
	if mode == 2 { local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")) }

	// 5. 转发
	done := make(chan bool, 2)
	go func() {
		buf := make([]byte, 16*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				jsonData, _ := wrapAsJson(buf[:n])
				if err := wsConn.WriteMessage(websocket.TextMessage, jsonData); err != nil { break }
			}
			if err != nil { break }
		}
		done <- true
	}()
	go func() {
		for {
			_, msg, err := wsConn.ReadMessage()
			if err != nil { break }
			payload, _ := unwrapFromJson(msg)
			if payload != nil { local.Write(payload) }
		}
		done <- true
	}()
	<-done
}

func dialSpecificWebSocket(outboundTag string) (*websocket.Conn, error) {
	settings, ok := proxySettingsMap[outboundTag]
	if !ok { return nil, errors.New("settings not found") }

	host, port, path, _ := parseServerAddr(settings.Server)
	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	requestHeader := http.Header{}
	requestHeader.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	requestHeader.Add("Host", host)
	// Cloudflare 对 Origin 检查很严格，部分节点需要为空或者与 Host 一致
	requestHeader.Add("Origin", fmt.Sprintf("https://%s", host))

	log.Printf("[Debug] Dialing WebSocket: %s (IP: %s)", wsURL, settings.ServerIP)

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host},
		Subprotocols:    []string{settings.Token},
		HandshakeTimeout: 10 * time.Second,
	}

	if settings.ServerIP != "" {
		dialer.NetDial = func(network, addr string) (net.Conn, error) {
			_, p, _ := net.SplitHostPort(addr)
			return net.DialTimeout(network, net.JoinHostPort(settings.ServerIP, p), 5*time.Second)
		}
	}

	conn, resp, err := dialer.Dial(wsURL, requestHeader)
	if err != nil {
		if resp != nil {
			// 【关键】打印 HTTP 状态码，这是判断失败原因的核心
			return nil, fmt.Errorf("HTTP %s (Code: %d)", resp.Status, resp.StatusCode)
		}
		return nil, err
	}
	return conn, nil
}

func parseServerAddr(addr string) (host, port, path string, err error) {
	path = "/"
	if idx := strings.Index(addr, "/"); idx != -1 { path = addr[idx:]; addr = addr[:idx] }
	host, port, err = net.SplitHostPort(addr)
	if err != nil { host = addr; port = "443"; err = nil }
	return
}
