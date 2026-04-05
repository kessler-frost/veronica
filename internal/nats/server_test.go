package nats

import (
	"context"
	"testing"
	"time"
)

func TestServer_StartsWithJetStream(t *testing.T) {
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()
	if srv.Conn() == nil {
		t.Fatal("nil connection")
	}
	if srv.JS() == nil {
		t.Fatal("nil jetstream")
	}
}

func TestServer_EventsStreamExists(t *testing.T) {
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := srv.JS().Stream(ctx, "EVENTS")
	if err != nil {
		t.Fatalf("get stream: %v", err)
	}
	info, _ := stream.Info(ctx)
	if info.Config.MaxAge != 5*time.Minute {
		t.Fatalf("expected 5m MaxAge, got %v", info.Config.MaxAge)
	}
}

func TestServer_KVBucketsExist(t *testing.T) {
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()

	ctx := context.Background()
	for _, name := range []string{"agents", "tasks", "policies", "logs"} {
		kv, err := srv.JS().KeyValue(ctx, name)
		if err != nil {
			t.Fatalf("get KV %s: %v", name, err)
		}
		_, err = kv.Put(ctx, "test-key", []byte(`{"hello":"world"}`))
		if err != nil {
			t.Fatalf("put %s: %v", name, err)
		}
		entry, err := kv.Get(ctx, "test-key")
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		if string(entry.Value()) != `{"hello":"world"}` {
			t.Fatalf("bad value from %s: %s", name, string(entry.Value()))
		}
	}
}

func TestServer_PublishAndConsumeEvent(t *testing.T) {
	srv, err := Start(Config{Port: -1, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	defer srv.Close()

	ctx := context.Background()
	_, err = srv.JS().Publish(ctx, "events.process_exec", []byte(`{"comm":"ls","pid":42}`))
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	stream, _ := srv.JS().Stream(ctx, "EVENTS")
	info, _ := stream.Info(ctx)
	if info.State.Msgs != 1 {
		t.Fatalf("expected 1 msg, got %d", info.State.Msgs)
	}
}
