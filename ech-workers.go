// ech-proxy-core.go - v4.0.1 Unified Engine (Full Implementation)
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"net/url"
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
type ECHProxySettings struct {
	Server    string `json:"server"`
	ServerIP  string `json:"server_ip,omitempty"`
	Token     string `json:"token"`
	ECHDomain string `json:"ech_domain"`
	DNSWorker string `json:"dns_worker,omitempty"`
	DNSPublic string `json:"dns_public"`
}
type Routing struct {
	Rules []Rule `json:"rules"`
}
type Rule struct {
	InboundTag  []string `json:"inboundTag,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	GeoIP       []string `json:"geoip,omitempty"`
	OutboundTag string   `json:"outboundTag"`
}

// ======================== Global State ========================

var (
	globalConfig      Config
	echConfigs        sync.Map // key: outboundTag, value: []byte
	chinaIPRanges     []ipRange
	chinaIPV6Ranges   []ipRangeV6
	chinaIPRangesMu   sync.RWMutex
	chinaIPV6RangesMu sync.RWMutex
)

type ipRange struct{ start, end uint32 }
type ipRangeV6 struct{ start, end [16]byte }

// ======================== Main Logic ========================

func main() {
	configPath := flag.String("c", "config.json", "Path to the configuration file")
	flag.Parse()

	log.Println("[Core] Loading configuration from", *configPath)
	file, err := os.ReadFile(*configPath)
	if err != nil { log.Fatalf("[Fatal] Failed to read config file: %v", err) }
	if err := json.Unmarshal(file, &globalConfig); err != nil { log.Fatalf("[Fatal] Failed to parse config file: %v", err) }

	log.Println("[Core] Initializing resources...")
	loadChinaListsForRouter()
	prepareAllECHConfigs()

	var wg sync.WaitGroup
	for _, inbound := range globalConfig.Inbounds {
		wg.Add(1)
		go func(ib Inbound) {
			defer wg.Done()
			runInbound(ib)
		}(inbound)
	}
	log.Println("[Core] Engine started. All inbounds are running.")
	wg.Wait()
}

func runInbound(ib Inbound) {
	listener, err := net.Listen("tcp", ib.Listen)
	if err != nil { log.Printf("[Error] [%s] Failed to listen on %s: %v", ib.Tag, ib.Listen, err); return }
	defer listener.Close()
	log.Printf("[Inbound] [%s] Listening on %s", ib.Tag, ib.Listen)

	for {
		conn, err := listener.Accept()
		if err != nil { continue }
		go handleGeneralConnection(conn, ib.Tag)
	}
}

func handleGeneralConnection(conn net.Conn, inboundTag string) {
	defer conn.Close()
	
	buf := make([]byte, 262); if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }; if _, err := conn.Write([]byte{0x05, 0x00}); err != nil { return }; if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
	var host string; switch buf[3] { case 1: if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }; host = net.IP(buf[:4]).String(); case 3: if _, err := io.ReadFull(conn, buf[:1]); err != nil { return }; domainLen := int(buf[0]); if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil { return }; host = string(buf[:domainLen]); default: return }; if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }; port := binary.BigEndian.Uint16(buf[:2]); target := fmt.Sprintf("%s:%d", host, port)

	log.Printf("[%s] -> %s", inboundTag, target)

	outboundTag := route(target, inboundTag)
	log.Printf("[%s] -> %s routed to [%s]", inboundTag, target, outboundTag)

	dispatch(conn, target, outboundTag)
}

func route(target, inboundTag string) string {
	host, _, _ := net.SplitHostPort(target); if host == "" { host = target }
	
	for _, rule := range globalConfig.Routing.Rules {
		inboundMatch := len(rule.InboundTag) == 0
		for _, tag := range rule.InboundTag { if tag == inboundTag { inboundMatch = true; break } }
		if !inboundMatch { continue }

		domainMatch := false
		if len(rule.Domain) > 0 {
			for _, d := range rule.Domain { if strings.Contains(host, d) { domainMatch = true; break } }
		}
		if domainMatch { return rule.OutboundTag }

		geoIPMatch := false
		if len(rule.GeoIP) > 0 {
			for _, geo := range rule.GeoIP {
				if geo == "cn" {
					isIPReq := net.ParseIP(host) != nil
					if isIPReq && isChinaIPForRouter(net.ParseIP(host)) {
						geoIPMatch = true; break
					}
					if !isIPReq {
						ips, err := net.LookupIP(host)
						if err == nil && len(ips) > 0 && isChinaIPForRouter(ips[0]) {
							geoIPMatch = true; break
						}
					}
				}
			}
		}
		if geoIPMatch { return rule.OutboundTag }
	}
	// Fallback to the last rule if it has no conditions
	if len(globalConfig.Routing.Rules) > 0 {
		lastRule := globalConfig.Routing.Rules[len(globalConfig.Routing.Rules)-1]
		if len(lastRule.Domain) == 0 && len(lastRule.GeoIP) == 0 {
			inboundMatch := len(lastRule.InboundTag) == 0
			for _, tag := range lastRule.InboundTag { if tag == inboundTag { inboundMatch = true; break } }
			if inboundMatch { return lastRule.OutboundTag }
		}
	}
	return "direct" 
}

func dispatch(conn net.Conn, target, outboundTag string) {
	switch outboundTag {
	case "direct": handleDirect(conn, target)
	case "block": conn.Close()
	default: 
		for _, ob := range globalConfig.Outbounds {
			if ob.Tag == outboundTag && ob.Protocol == "ech-proxy" {
				handleProxy(conn, target, ob)
				return
			}
		}
		log.Printf("[Error] Outbound tag '%s' not found or not an ech-proxy type", outboundTag)
	}
}

// ======================== Handlers ========================

func handleDirect(clientConn net.Conn, target string) {
	remote, err := net.DialTimeout("tcp", target, 5*time.Second); if err != nil { clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}); return }; defer remote.Close()
	clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	go io.Copy(remote, clientConn); io.Copy(clientConn, remote)
}

func handleProxy(clientConn net.Conn, target string, outbound Outbound) {
	var settings ECHProxySettings; if err := json.Unmarshal(outbound.Settings, &settings); err != nil { log.Printf("[Error] [%s] Invalid settings: %v", outbound.Tag, err); clientConn.Close(); return }
	echConfig, ok := echConfigs.Load(outbound.Tag); if !ok { log.Printf("[Error] [%s] ECH config not ready", outbound.Tag); clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}); return }
	wsConn, err := dialWebSocketWithECH_V4(settings, echConfig.([]byte)); if err != nil { log.Printf("[Error] [%s] Failed to dial WebSocket: %v", outbound.Tag, err); clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}); return }
	defer wsConn.Close()
	connectMsg := fmt.Sprintf("CONNECT:%s|", target)
	if err := wsConn.WriteMessage(websocket.TextMessage, []byte(connectMsg)); err != nil { return }
	_, msg, err := wsConn.ReadMessage(); if err != nil || string(msg) != "CONNECTED" { log.Printf("[Error] [%s] Handshake failed: %s", outbound.Tag, string(msg)); clientConn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0}); return }
	clientConn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan bool, 2)
	go func() { buf := make([]byte, 32*1024); for { n, err := clientConn.Read(buf); if err != nil { wsConn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")); done <- true; return }; if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil { done <- true; return } } }()
	go func() { for { _, msg, err := wsConn.ReadMessage(); if err != nil { clientConn.Close(); done <- true; return }; if _, err := clientConn.Write(msg); err != nil { done <- true; return } } }()
	<-done
}

// ======================== Resource Preparation ========================

func prepareAllECHConfigs() {
	var wg sync.WaitGroup
	for _, outbound := range globalConfig.Outbounds {
		if outbound.Protocol == "ech-proxy" {
			wg.Add(1)
			go func(ob Outbound) {
				defer wg.Done()
				var settings ECHProxySettings; if err := json.Unmarshal(ob.Settings, &settings); err != nil { log.Printf("[Error] [%s] Invalid settings: %v", ob.Tag, err); return }
				echBase64, err := queryECH_V4(settings); if err != nil { log.Printf("[Error] [%s] Failed to get ECH config: %v", ob.Tag, err); return }
				raw, err := base64.StdEncoding.DecodeString(echBase64); if err != nil { log.Printf("[Error] [%s] Failed to decode ECH config: %v", ob.Tag, err); return }
				echConfigs.Store(ob.Tag, raw); log.Printf("[ECH] [%s] ECH config loaded, length: %d bytes", ob.Tag, len(raw))
			}(outbound)
		}
	}
	wg.Wait()
}

func loadChinaListsForRouter() {
	loadIPList_V4("chn_ip.txt", &chinaIPRanges, &chinaIPRangesMu, false)
	loadIPList_V4("chn_ip_v6.txt", &chinaIPV6Ranges, &chinaIPV6RangesMu, true)
}

func isChinaIPForRouter(ip net.IP) bool {
	if ip == nil { return false }
	if ip4 := ip.To4(); ip4 != nil {
		val := binary.BigEndian.Uint32(ip4); chinaIPRangesMu.RLock(); defer chinaIPRangesMu.RUnlock()
		for _, r := range chinaIPRanges { if val >= r.start && val <= r.end { return true } }
	} else if ip16 := ip.To16(); ip16 != nil {
		var val [16]byte; copy(val[:], ip16); chinaIPV6RangesMu.RLock(); defer chinaIPV6RangesMu.RUnlock()
		for _, r := range chinaIPV6Ranges { if bytes.Compare(val[:], r.start[:]) >= 0 && bytes.Compare(val[:], r.end[:]) <= 0 { return true } }
	}
	return false
}


// ======================== Helper Functions (Full Implementation) ========================
var httpClient = &http.Client{ Timeout: 10 * time.Second, Transport: &http.Transport{ DialContext: func(ctx context.Context, n, a string) (net.Conn, error) { return (&net.Dialer{ Timeout: 5*time.Second }).DialContext(ctx, "tcp4", a) } } }
func queryECH_V4(settings ECHProxySettings) (string, error) {
	if settings.DNSWorker != "" { res, err := queryHTTPSRecord_V4(settings.ECHDomain, settings.DNSWorker); if err == nil && res != "" { return res, nil } }
	if settings.DNSPublic != "" { return queryHTTPSRecord_V4(settings.ECHDomain, settings.DNSPublic) }
	return "", errors.New("no valid DNS server provided for ECH query")
}
func queryHTTPSRecord_V4(domain, dnsServer string) (string, error) { if !strings.HasPrefix(dnsServer, "https://") && !strings.HasPrefix(dnsServer, "http://") { dnsServer = "https://" + dnsServer }; return queryDoH_V4(domain, dnsServer) }
func queryDoH_V4(domain, dohURL string) (string, error) { u, err := url.Parse(dohURL); if err != nil { return "", err }; q := u.Query(); q.Set("dns", base64.RawURLEncoding.EncodeToString(buildDNSQuery_V4(domain, 65))); u.RawQuery = q.Encode(); req, _ := http.NewRequest("GET", u.String(), nil); req.Header.Set("Accept", "application/dns-message"); resp, err := httpClient.Do(req); if err != nil { return "", err }; defer resp.Body.Close(); if resp.StatusCode != 200 { return "", errors.New(resp.Status) }; body, err := io.ReadAll(resp.Body); if err != nil { return "", err }; return parseDNSResponse_V4(body) }
func buildDNSQuery_V4(domain string, qtype uint16) []byte { var q []byte; q = append(q, []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0} ...); for _, label := range strings.Split(domain, ".") { q = append(q, byte(len(label))); q = append(q, label...) }; q = append(q, 0); q = binary.BigEndian.AppendUint16(q, qtype); q = binary.BigEndian.AppendUint16(q, 1); return q }
func parseDNSResponse_V4(r []byte) (string, error) { if len(r) < 12 || binary.BigEndian.Uint16(r[6:8]) == 0 { return "", errors.New("无应答记录") }; offset := 12; for r[offset] != 0 { offset += int(r[offset]) + 1 }; offset += 5; for { if offset+10 > len(r) { break }; offset += 2; if r[offset-2]&0xC0 == 0xC0 { } else { for r[offset-1] != 0 { offset += int(r[offset-1]) + 1 } }; rrType := binary.BigEndian.Uint16(r[offset : offset+2]); offset += 8; dataLen := binary.BigEndian.Uint16(r[offset : offset+2]); offset += 2; if offset+int(dataLen) > len(r) { break }; data := r[offset : offset+int(dataLen)]; offset += int(dataLen); if rrType == 65 { if ech := parseHTTPSRecord_V4(data); ech != "" { return ech, nil } } }; return "", errors.New("未找到HTTPS记录") }
func parseHTTPSRecord_V4(data []byte) string { if len(data) < 2 { return "" }; offset := 2; for offset < len(data) && data[offset] != 0 { offset += int(data[offset]) + 1 }; offset++; for offset+4 <= len(data) { key := binary.BigEndian.Uint16(data[offset:offset+2]); length := binary.BigEndian.Uint16(data[offset+2:offset+4]); offset += 4; if offset+int(length) > len(data) { break }; value := data[offset : offset+int(length)]; offset += int(length); if key == 5 { return base64.StdEncoding.EncodeToString(value) } }; return "" }
func dialWebSocketWithECH_V4(settings ECHProxySettings, echConfig []byte) (*websocket.Conn, error) { host, port, path, err := net.SplitHostPort(settings.Server); if err != nil { return nil, err }; wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path); tlsCfg, err := buildTLSConfigWithECH_V4(host, echConfig); if err != nil { return nil, err }; dialer := websocket.Dialer{TLSClientConfig: tlsCfg, HandshakeTimeout: 10 * time.Second, Subprotocols: []string{settings.Token}}; if settings.ServerIP != "" { dialer.NetDial = func(n, a string) (net.Conn, error) { _, p, _ := net.SplitHostPort(a); return net.DialTimeout(n, net.JoinHostPort(settings.ServerIP, p), 10*time.Second) } }; conn, _, err := dialer.Dial(wsURL, nil); return conn, err }
func buildTLSConfigWithECH_V4(serverName string, echList []byte) (*tls.Config, error) { roots, _ := x509.SystemCertPool(); config := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: serverName, RootCAs: roots}; v := reflect.ValueOf(config).Elem(); f := v.FieldByName("EncryptedClientHelloConfigList"); if !f.IsValid() || !f.CanSet() { return nil, errors.New("unsupported ECH") }; f.Set(reflect.ValueOf(echList)); return config, nil }
func getExeDir() string { p, err := os.Executable(); if err != nil { return "." }; return filepath.Dir(p) }
func downloadFile_V4(url, path string) error { resp, err := httpClient.Get(url); if err != nil { return err }; defer resp.Body.Close(); if resp.StatusCode != 200 { return fmt.Errorf("HTTP %d", resp.StatusCode) }; data, err := io.ReadAll(resp.Body); if err != nil { return err }; return os.WriteFile(path, data, 0644) }
func loadIPList_V4(filename string, target interface{}, mu *sync.RWMutex, isV6 bool) {
	filePath := filepath.Join(getExeDir(), filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		url := "https://mirror.ghproxy.com/https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/" + filename
		log.Printf("[下载] 正在下载 IP 列表: %s", filename)
		if err := downloadFile_V4(url, filePath); err != nil {
			log.Printf("[警告] 下载 %s 失败: %v", filename, err)
			return
		}
	}
	file, err := os.Open(filePath); if err != nil { log.Printf("[警告] 打开 %s 失败: %v", filename, err); return }
	defer file.Close()
	var rangesV4 []ipRange; var rangesV6 []ipRangeV6; scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text()); if len(parts) < 2 { continue }
		startIP, endIP := net.ParseIP(parts[0]), net.ParseIP(parts[1]); if startIP == nil || endIP == nil { continue }
		if isV6 {
			var s, e [16]byte; copy(s[:], startIP.To16()); copy(e[:], endIP.To16())
			rangesV6 = append(rangesV6, ipRangeV6{start: s, end: e})
		} else {
			s, e := binary.BigEndian.Uint32(startIP.To4()), binary.BigEndian.Uint32(endIP.To4())
			if s > 0 && e > 0 { rangesV4 = append(rangesV4, ipRange{start: s, end: e}) }
		}
	}
	mu.Lock(); defer mu.Unlock()
	if isV6 {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV6))
	} else {
		reflect.ValueOf(target).Elem().Set(reflect.ValueOf(rangesV4))
	}
}
