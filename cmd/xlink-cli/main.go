package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"xlink-project/core"
)

func main() {
	exePath, _ := os.Executable()
	defaultConfigPath := filepath.Join(filepath.Dir(exePath), "config.json")

	configFile := flag.String("c", defaultConfigPath, "Path to the configuration file")
	flag.Parse()

	if *configFile == "" {
		log.Fatalf("Usage: %s -c <path/to/config.json>", os.Args[0])
	}
	log.Printf("[CLI] Loading configuration from: %s", *configFile)

	configBytes, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("[CLI] Failed to read config file: %v", err)
	}

	log.Println("[CLI] Starting X-Link Core Engine...")
	listener, err := core.StartInstance(configBytes)
	if err != nil {
		log.Fatalf("[CLI] Failed to start core engine: %v", err)
	}

	log.Println("[CLI] Engine running successfully.")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[CLI] Shutting down...")
	if listener != nil {
		listener.Close()
	}
}
