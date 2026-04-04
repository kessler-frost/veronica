package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/fimbulwinter/veronica/internal/classifier"
	vebpf "github.com/fimbulwinter/veronica/internal/ebpf"
	"github.com/fimbulwinter/veronica/internal/event"
	vnats "github.com/fimbulwinter/veronica/internal/nats"
)

func main() {
	natsPort := 4222
	storeDir := envOr("VERONICA_STORE_DIR", "/var/veronica/nats")

	log.Printf("veronica starting")
	log.Printf("  nats port: %d", natsPort)
	log.Printf("  store: %s", storeDir)

	if err := os.MkdirAll(storeDir, 0755); err != nil {
		log.Fatalf("mkdir %s: %v", storeDir, err)
	}

	srv, err := vnats.Start(vnats.Config{
		Port:     natsPort,
		StoreDir: storeDir,
	})
	if err != nil {
		log.Fatalf("nats: %v", err)
	}
	defer srv.Close()

	cls := classifier.New()
	pub := vnats.NewPublisher(srv.JS(), cls)

	if err := vnats.RegisterToolResponders(srv.Conn(), pub); err != nil {
		log.Fatalf("register tools: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// eBPF → event channel → publisher → NATS
	events := make(chan event.Event, 256)
	go pub.Run(ctx, events)

	ebpfMgr := vebpf.New(events)
	if err := ebpfMgr.LoadAndAttach(); err != nil {
		log.Fatalf("ebpf: %v", err)
	}
	defer ebpfMgr.Close()
	log.Printf("ebpf probes attached")

	go func() {
		if err := ebpfMgr.ReadEvents(ctx); err != nil {
			log.Printf("ebpf reader stopped: %v", err)
		}
	}()

	log.Printf("veronica running. nats=%s. ctrl+c to stop.", srv.ClientURL())

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("shutting down...")
	cancel()
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
