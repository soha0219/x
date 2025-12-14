// cmd/xlink-cli/main.go (v2.0 - Config File Support)
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	// 確保這個導入路徑與您的項目結構匹配
	"xlink-project/core" 
)

// parseXlinkURI 函數已經不再需要，可以完全刪除。
// 我們不再從 URI 生成配置，而是直接讀取配置文件。

func main() {
	// 1. 修改命令行參數：從 -uri 改為 -c (config)
	// 默認值可以設置為程序目錄下的 config.json
	exePath, _ := os.Executable()
	defaultConfigPath := filepath.Join(filepath.Dir(exePath), "config.json")

	configFile := flag.String("c", defaultConfigPath, "Path to the configuration file (e.g., config.json)")
	flag.Parse()

	if *configFile == "" {
		log.Fatalf("Usage: %s -c <path/to/config.json>", os.Args[0])
	}
	log.Printf("[CLI] Loading configuration from: %s", *configFile)

	// 2. 讀取配置文件內容
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[CLI] Failed to read config file: %v", err)
	}

	// 3. 直接將配置文件內容傳遞給核心
	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Println("[CLI] Engine running successfully.")

	// 優雅地關閉進程 (保持不變)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
