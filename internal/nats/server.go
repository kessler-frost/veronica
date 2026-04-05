package nats

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type Server struct {
	ns   *natsserver.Server
	nc   *nats.Conn
	js   jetstream.JetStream
	port int
}

type Config struct {
	Port     int    // -1 for random (tests), 4222 for production
	StoreDir string // JetStream storage directory
}

func Start(cfg Config) (*Server, error) {
	opts := &natsserver.Options{
		Port:           cfg.Port,
		JetStream:      true,
		StoreDir:       cfg.StoreDir,
		NoLog:          false,
		NoSigs:         true,
		MaxControlLine: 4096,
	}

	ns, err := natsserver.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("create nats server: %w", err)
	}
	ns.ConfigureLogger()
	ns.Start()

	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return nil, fmt.Errorf("nats server not ready after 10s")
	}

	nc, err := nats.Connect(ns.ClientURL())
	if err != nil {
		ns.Shutdown()
		return nil, fmt.Errorf("connect to embedded nats: %w", err)
	}

	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		ns.Shutdown()
		return nil, fmt.Errorf("create jetstream: %w", err)
	}

	s := &Server{ns: ns, nc: nc, js: js, port: ns.Addr().(*net.TCPAddr).Port}

	if err := s.setupStreamsAndBuckets(context.Background()); err != nil {
		s.Close()
		return nil, err
	}

	log.Printf("nats server running on port %d with JetStream", s.port)
	return s, nil
}

func (s *Server) setupStreamsAndBuckets(ctx context.Context) error {
	// Events stream — all events.* subjects, 5 minute retention
	_, err := s.js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:     "EVENTS",
		Subjects: []string{"events.>"},
		MaxAge:   5 * time.Minute,
		Storage:  jetstream.FileStorage,
	})
	if err != nil {
		return fmt.Errorf("create events stream: %w", err)
	}

	// KV buckets
	buckets := []struct {
		name string
		ttl  time.Duration
	}{
		{"agents", 0},
		{"tasks", time.Hour},
		{"policies", 0},
		{"logs", time.Hour},
	}
	for _, b := range buckets {
		cfg := jetstream.KeyValueConfig{
			Bucket:  b.name,
			Storage: jetstream.FileStorage,
		}
		if b.ttl > 0 {
			cfg.TTL = b.ttl
		}
		_, err := s.js.CreateOrUpdateKeyValue(ctx, cfg)
		if err != nil {
			return fmt.Errorf("create KV bucket %s: %w", b.name, err)
		}
	}
	return nil
}

func (s *Server) Conn() *nats.Conn        { return s.nc }
func (s *Server) JS() jetstream.JetStream { return s.js }
func (s *Server) ClientURL() string       { return s.ns.ClientURL() }

func (s *Server) Close() {
	if s.nc != nil {
		s.nc.Close()
	}
	if s.ns != nil {
		s.ns.Shutdown()
		s.ns.WaitForShutdown()
	}
}
