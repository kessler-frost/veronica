package control

import (
	"sync"
	"time"
)

// defaultBufferSize is the rolling buffer capacity when unspecified.
const defaultBufferSize = 4096

// Aggregator is a fixed-size rolling buffer of one app's raw kernel events.
// Snapshot groups the in-window events by kind into an Activity with
// repeat-counts. The eBPF event source is VM-gated; this is the pure logic.
type Aggregator struct {
	mu   sync.Mutex
	app  string
	buf  []Event
	head int  // next write index
	full bool // whether the buffer has wrapped

	// now is overridable in tests; defaults to time.Now.
	now func() time.Time
}

// NewAggregator returns an Aggregator for app with the default buffer size.
func NewAggregator(app string) *Aggregator {
	return NewAggregatorSize(app, defaultBufferSize)
}

// NewAggregatorSize returns an Aggregator for app with a buffer of size slots.
func NewAggregatorSize(app string, size int) *Aggregator {
	return &Aggregator{
		app: app,
		buf: make([]Event, size),
		now: time.Now,
	}
}

// Add records an event, evicting the oldest if the buffer is full.
func (a *Aggregator) Add(ev Event) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.buf[a.head] = ev
	a.head = (a.head + 1) % len(a.buf)
	if a.head == 0 {
		a.full = true
	}
}

// Snapshot groups all buffered events newer than now-window by kind, deduping
// identical events into a single entry with a Count, and returns the Activity.
func (a *Aggregator) Snapshot(window time.Duration) Activity {
	a.mu.Lock()
	defer a.mu.Unlock()

	cutoff := a.now().Add(-window)
	act := Activity{App: a.app, Window: int(window.Seconds())}

	files := map[FileEvent]int{}
	nets := map[NetEvent]int{}
	execs := map[ExecEvent]int{}
	mounts := map[MountEvent]int{}

	for _, ev := range a.live() {
		if ev.At.Before(cutoff) {
			continue
		}
		switch ev.Kind {
		case KindFile:
			files[FileEvent{Path: ev.Path, Write: ev.Write}]++
		case KindNet:
			nets[NetEvent{DestAddr: ev.DestAddr, DestPort: ev.DestPort}]++
		case KindExec:
			execs[ExecEvent{Path: ev.Path}]++
		case KindMount:
			mounts[MountEvent{Source: ev.Source, Target: ev.Target}]++
		}
	}

	for k, n := range files {
		k.Count = n
		act.Files = append(act.Files, k)
	}
	for k, n := range nets {
		k.Count = n
		act.Net = append(act.Net, k)
	}
	for k, n := range execs {
		k.Count = n
		act.Execs = append(act.Execs, k)
	}
	for k, n := range mounts {
		k.Count = n
		act.Mounts = append(act.Mounts, k)
	}
	return act
}

// live returns the currently-buffered events (the caller holds the lock).
func (a *Aggregator) live() []Event {
	if !a.full {
		return a.buf[:a.head]
	}
	out := make([]Event, 0, len(a.buf))
	out = append(out, a.buf[a.head:]...)
	out = append(out, a.buf[:a.head]...)
	return out
}
