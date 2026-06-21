package control

import (
	"testing"
	"time"
)

// findFile returns the FileEvent for path/write, or nil.
func findFile(a Activity, path string, write bool) *FileEvent {
	for i := range a.Files {
		if a.Files[i].Path == path && a.Files[i].Write == write {
			return &a.Files[i]
		}
	}
	return nil
}

func TestSnapshot_GroupsByKindWithCounts(t *testing.T) {
	now := time.Now()
	agg := NewAggregator("docker")
	agg.now = func() time.Time { return now }

	// Three writes to the same path → one FileEvent with Count 3.
	agg.Add(Event{Kind: KindFile, At: now.Add(-5 * time.Second), Path: "/data/x", Write: true})
	agg.Add(Event{Kind: KindFile, At: now.Add(-4 * time.Second), Path: "/data/x", Write: true})
	agg.Add(Event{Kind: KindFile, At: now.Add(-3 * time.Second), Path: "/data/x", Write: true})
	// A read of the same path is a distinct group.
	agg.Add(Event{Kind: KindFile, At: now.Add(-2 * time.Second), Path: "/data/x", Write: false})

	agg.Add(Event{Kind: KindNet, At: now.Add(-6 * time.Second), DestAddr: "1.2.3.4", DestPort: 443})
	agg.Add(Event{Kind: KindNet, At: now.Add(-1 * time.Second), DestAddr: "1.2.3.4", DestPort: 443})

	agg.Add(Event{Kind: KindExec, At: now.Add(-7 * time.Second), Path: "/usr/bin/ls"})

	agg.Add(Event{Kind: KindMount, At: now.Add(-8 * time.Second), Source: "/dev/sda", Target: "/mnt"})

	snap := agg.Snapshot(30 * time.Second)

	if snap.App != "docker" {
		t.Errorf("App = %q, want docker", snap.App)
	}
	if snap.Window != 30 {
		t.Errorf("Window = %d, want 30", snap.Window)
	}

	if w := findFile(snap, "/data/x", true); w == nil || w.Count != 3 {
		t.Errorf("write /data/x = %+v, want Count 3", w)
	}
	if r := findFile(snap, "/data/x", false); r == nil || r.Count != 1 {
		t.Errorf("read /data/x = %+v, want Count 1", r)
	}
	if len(snap.Files) != 2 {
		t.Errorf("len(Files) = %d, want 2", len(snap.Files))
	}

	if len(snap.Net) != 1 || snap.Net[0].Count != 2 {
		t.Errorf("Net = %+v, want one entry Count 2", snap.Net)
	}
	if len(snap.Execs) != 1 || snap.Execs[0].Count != 1 || snap.Execs[0].Path != "/usr/bin/ls" {
		t.Errorf("Execs = %+v, want one /usr/bin/ls Count 1", snap.Execs)
	}
	if len(snap.Mounts) != 1 || snap.Mounts[0].Target != "/mnt" {
		t.Errorf("Mounts = %+v, want one /mnt", snap.Mounts)
	}
}

func TestSnapshot_DropsOutOfWindow(t *testing.T) {
	now := time.Now()
	agg := NewAggregator("docker")
	agg.now = func() time.Time { return now }

	agg.Add(Event{Kind: KindFile, At: now.Add(-10 * time.Second), Path: "/in", Write: true})
	agg.Add(Event{Kind: KindFile, At: now.Add(-60 * time.Second), Path: "/old", Write: true})

	snap := agg.Snapshot(30 * time.Second)

	if findFile(snap, "/in", true) == nil {
		t.Error("in-window event /in missing from snapshot")
	}
	if findFile(snap, "/old", true) != nil {
		t.Error("out-of-window event /old should be dropped")
	}
	if len(snap.Files) != 1 {
		t.Errorf("len(Files) = %d, want 1 (out-of-window dropped)", len(snap.Files))
	}
}

func TestSnapshot_EmptyWindow(t *testing.T) {
	agg := NewAggregator("docker")
	snap := agg.Snapshot(30 * time.Second)
	if len(snap.Files)+len(snap.Net)+len(snap.Execs)+len(snap.Mounts) != 0 {
		t.Errorf("empty aggregator should yield empty snapshot, got %+v", snap)
	}
	if snap.App != "docker" || snap.Window != 30 {
		t.Errorf("App/Window = %q/%d, want docker/30", snap.App, snap.Window)
	}
}

func TestAdd_RingBufferEvicts(t *testing.T) {
	now := time.Now()
	agg := NewAggregatorSize("docker", 4)
	agg.now = func() time.Time { return now }

	// Add 6 distinct events into a 4-slot buffer; the 2 oldest are evicted.
	for i := 0; i < 6; i++ {
		agg.Add(Event{Kind: KindExec, At: now, Path: pathN(i)})
	}

	snap := agg.Snapshot(time.Hour)
	if len(snap.Execs) != 4 {
		t.Fatalf("len(Execs) = %d, want 4 (ring buffer capacity)", len(snap.Execs))
	}
	// The two oldest (exec-0, exec-1) must have been evicted.
	for _, e := range snap.Execs {
		if e.Path == pathN(0) || e.Path == pathN(1) {
			t.Errorf("evicted event %q still present", e.Path)
		}
	}
}

func pathN(i int) string {
	return "/bin/exec-" + string(rune('0'+i))
}
