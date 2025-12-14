package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"xlink-project/core"
)

func main() {
	// 改动：不再接收 -uri，改为接收 -c (config file path)
	configFile := flag.String("c", "", "path to config.json")
	flag.Parse()

	if *configFile == "" {
		log.Fatalf("Usage: %s -c <config.json>", os.Args[0])
	}

	log.Printf("[CLI] Loading config from: %s", *configFile)

	// 1. 读取文件内容
	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[CLI] Failed to read config file: %v", err)
	}

	// 2. 启动核心引擎 (Core 本身就是接收 []byte 的)
	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Println("[CLI] Engine running successfully.")

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
