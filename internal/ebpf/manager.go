package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	json "github.com/goccy/go-json"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/fimbulwinter/veronica/internal/ebpf/bpf"
	"github.com/fimbulwinter/veronica/internal/event"
)

// Manager loads eBPF programs, attaches hooks, and reads events.
type Manager struct {
	links   []link.Link
	readers []*ringbuf.Reader
	events  chan<- event.Event
	maps    *MapManager
}

// New creates an eBPF manager that sends events to the given channel.
func New(events chan<- event.Event) *Manager {
	return &Manager{events: events, maps: NewMapManager()}
}

// Maps returns the MapManager for named eBPF map access.
func (m *Manager) Maps() *MapManager {
	return m.maps
}

// LoadAndAttach loads all eBPF programs and attaches them to hooks.
func (m *Manager) LoadAndAttach() error {
	// Process exec tracepoint
	procObjs := bpf.ProcessExecObjects{}
	if err := bpf.LoadProcessExecObjects(&procObjs, nil); err != nil {
		return fmt.Errorf("load process_exec: %w", err)
	}

	m.maps.Register("process_exec_events", procObjs.Events)

	procLink, err := link.Tracepoint("sched", "sched_process_exec", procObjs.TraceExec, nil)
	if err != nil {
		return fmt.Errorf("attach process_exec: %w", err)
	}
	m.links = append(m.links, procLink)

	procReader, err := ringbuf.NewReader(procObjs.Events)
	if err != nil {
		return fmt.Errorf("create process_exec ring buffer reader: %w", err)
	}
	m.readers = append(m.readers, procReader)

	// File open kprobe — filtered by classifier path prefixes
	fileObjs := bpf.FileOpenObjects{}
	if err := bpf.LoadFileOpenObjects(&fileObjs, nil); err != nil {
		log.Printf("WARN: load file_open: %v", err)
	} else {
		m.maps.Register("file_open_events", fileObjs.Events)
		fileLink, err := link.Kprobe("do_sys_openat2", fileObjs.TraceFileOpen, nil)
		if err != nil {
			log.Printf("WARN: attach file_open: %v", err)
		} else {
			m.links = append(m.links, fileLink)
			if fileReader, err := ringbuf.NewReader(fileObjs.Events); err == nil {
				m.readers = append(m.readers, fileReader)
			}
		}
	}

	// Net connect kprobe (non-fatal if unavailable)
	netObjs := bpf.NetConnectObjects{}
	if err := bpf.LoadNetConnectObjects(&netObjs, nil); err != nil {
		log.Printf("WARN: load net_connect: %v", err)
	} else {
		m.maps.Register("net_connect_events", netObjs.Events)
		netLink, err := link.Kprobe("tcp_v4_connect", netObjs.TraceConnect, nil)
		if err != nil {
			log.Printf("WARN: attach net_connect: %v", err)
		} else {
			m.links = append(m.links, netLink)
			if netReader, err := ringbuf.NewReader(netObjs.Events); err == nil {
				m.readers = append(m.readers, netReader)
			}
		}
	}

	// Process exit tracepoint (non-fatal if unavailable)
	exitObjs := bpf.ProcessExitObjects{}
	if err := bpf.LoadProcessExitObjects(&exitObjs, nil); err != nil {
		log.Printf("WARN: load process_exit: %v", err)
	} else {
		m.maps.Register("process_exit_events", exitObjs.Events)
		exitLink, err := link.Tracepoint("sched", "sched_process_exit", exitObjs.TraceExit, nil)
		if err != nil {
			log.Printf("WARN: attach process_exit: %v", err)
		} else {
			m.links = append(m.links, exitLink)
			if exitReader, err := ringbuf.NewReader(exitObjs.Events); err == nil {
				m.readers = append(m.readers, exitReader)
			}
		}
	}

	return nil
}

// ReadEvents reads events from all ring buffers concurrently.
// Blocks until context is cancelled.
func (m *Manager) ReadEvents(ctx context.Context) error {
	var wg sync.WaitGroup
	for _, reader := range m.readers {
		wg.Add(1)
		go func(r *ringbuf.Reader) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}

				record, err := r.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					log.Printf("ring buffer read: %v", err)
					continue
				}

				event := m.parseEvent(record.RawSample)
				if event != nil {
					m.events <- *event
				}
			}
		}(reader)
	}
	wg.Wait()
	return ctx.Err()
}

func (m *Manager) parseEvent(data []byte) *event.Event {
	if len(data) < 4 {
		return nil
	}

	eventType := EventType(binary.LittleEndian.Uint32(data[:4]))

	switch eventType {
	case EventProcessExec:
		var e ProcessExecEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		args := ArgsString(e.Args)
		if args == "" {
			args = readCmdline(e.Header.PID)
		}
		cwd := readCwd(e.Header.PID)
		payload, _ := json.Marshal(map[string]any{
			"comm": e.Header.CommString(), "filename": FilenameString(e.Filename),
			"uid": e.Header.UID, "pid": e.Header.PID, "cmdline": args, "cwd": cwd,
		})
		return &event.Event{
			Type:     "process_exec",
			Resource: fmt.Sprintf("pid:%d", e.Header.PID),
			Data:     string(payload),
		}

	case EventProcessExit:
		var e ProcessExitEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		payload, _ := json.Marshal(map[string]any{
			"comm": e.Header.CommString(), "pid": e.Header.PID,
			"uid": e.Header.UID, "exit_code": e.ExitCode,
		})
		return &event.Event{
			Type:     "process_exit",
			Resource: fmt.Sprintf("pid:%d", e.Header.PID),
			Data:     string(payload),
		}

	case EventFileOpen:
		var e FileOpenEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		payload, _ := json.Marshal(map[string]any{
			"comm": e.Header.CommString(), "pid": e.Header.PID,
			"filename": FilenameString(e.Filename), "flags": e.Flags,
		})
		return &event.Event{
			Type:     "file_open",
			Resource: fmt.Sprintf("file:%s", FilenameString(e.Filename)),
			Data:     string(payload),
		}

	case EventNetConnect:
		var e NetConnectEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", byte(e.DAddr), byte(e.DAddr>>8), byte(e.DAddr>>16), byte(e.DAddr>>24))
		payload, _ := json.Marshal(map[string]any{
			"comm": e.Header.CommString(), "pid": e.Header.PID,
			"daddr": ip, "dport": e.DPort,
		})
		return &event.Event{
			Type:     "net_connect",
			Resource: fmt.Sprintf("ip:%s:%d", ip, e.DPort),
			Data:     string(payload),
		}
	}

	return nil
}

// Close detaches all hooks and closes all ring buffer readers.
func (m *Manager) Close() error {
	for _, r := range m.readers {
		_ = r.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	return nil
}

// readCwd reads the current working directory for a process.
func readCwd(pid uint32) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return target
}

// readCmdline reads the full command line for a process from /proc/<pid>/cmdline.
// The kernel stores arguments as null-separated bytes; we convert them to spaces.
func readCmdline(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	for i, b := range data {
		if b == 0 {
			data[i] = ' '
		}
	}
	return strings.TrimSpace(string(data))
}
