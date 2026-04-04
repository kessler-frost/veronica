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

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/fimbulwinter/veronica/internal/coordinator"
	"github.com/fimbulwinter/veronica/internal/ebpf/bpf"
)

// Manager loads eBPF programs, attaches hooks, and reads events.
type Manager struct {
	links  []link.Link
	reader *ringbuf.Reader
	events chan<- coordinator.Event
}

// New creates an eBPF manager that sends events to the given channel.
func New(events chan<- coordinator.Event) *Manager {
	return &Manager{events: events}
}

// LoadAndAttach loads all eBPF programs and attaches them to hooks.
func (m *Manager) LoadAndAttach() error {
	// Process exec tracepoint
	procObjs := bpf.ProcessExecObjects{}
	if err := bpf.LoadProcessExecObjects(&procObjs, nil); err != nil {
		return fmt.Errorf("load process_exec: %w", err)
	}

	procLink, err := link.Tracepoint("sched", "sched_process_exec", procObjs.TraceExec, nil)
	if err != nil {
		return fmt.Errorf("attach process_exec: %w", err)
	}
	m.links = append(m.links, procLink)

	reader, err := ringbuf.NewReader(procObjs.Events)
	if err != nil {
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	m.reader = reader

	// File open kprobe (non-fatal if unavailable)
	fileObjs := bpf.FileOpenObjects{}
	if err := bpf.LoadFileOpenObjects(&fileObjs, nil); err != nil {
		log.Printf("WARN: load file_open: %v", err)
	} else {
		fileLink, err := link.Kprobe("do_sys_openat2", fileObjs.TraceFileOpen, nil)
		if err != nil {
			log.Printf("WARN: attach file_open: %v", err)
		} else {
			m.links = append(m.links, fileLink)
		}
	}

	// Net connect kprobe (non-fatal if unavailable)
	netObjs := bpf.NetConnectObjects{}
	if err := bpf.LoadNetConnectObjects(&netObjs, nil); err != nil {
		log.Printf("WARN: load net_connect: %v", err)
	} else {
		netLink, err := link.Kprobe("tcp_v4_connect", netObjs.TraceConnect, nil)
		if err != nil {
			log.Printf("WARN: attach net_connect: %v", err)
		} else {
			m.links = append(m.links, netLink)
		}
	}

	// Process exit tracepoint (non-fatal if unavailable)
	exitObjs := bpf.ProcessExitObjects{}
	if err := bpf.LoadProcessExitObjects(&exitObjs, nil); err != nil {
		log.Printf("WARN: load process_exit: %v", err)
	} else {
		exitLink, err := link.Tracepoint("sched", "sched_process_exit", exitObjs.TraceExit, nil)
		if err != nil {
			log.Printf("WARN: attach process_exit: %v", err)
		} else {
			m.links = append(m.links, exitLink)
		}
	}

	return nil
}

// ReadEvents reads events from the ring buffer and sends them to the coordinator.
// Blocks until context is cancelled or ring buffer is closed.
func (m *Manager) ReadEvents(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("ring buffer read: %v", err)
			continue
		}

		event := m.parseEvent(record.RawSample)
		if event != nil {
			m.events <- *event
		}
	}
}

func (m *Manager) parseEvent(data []byte) *coordinator.Event {
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
		cmdline := readCmdline(e.Header.PID)
		return &coordinator.Event{
			Type:     "process_exec",
			Resource: fmt.Sprintf("pid:%d", e.Header.PID),
			Data:     fmt.Sprintf(`{"comm":%q,"filename":%q,"uid":%d,"cmdline":%q}`, e.Header.CommString(), FilenameString(e.Filename), e.Header.UID, cmdline),
		}

	case EventProcessExit:
		var e ProcessExitEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		return &coordinator.Event{
			Type:     "process_exit",
			Resource: fmt.Sprintf("pid:%d", e.Header.PID),
			Data:     fmt.Sprintf(`{"comm":%q,"pid":%d,"uid":%d,"exit_code":%d}`, e.Header.CommString(), e.Header.PID, e.Header.UID, e.ExitCode),
		}

	case EventFileOpen:
		var e FileOpenEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		return &coordinator.Event{
			Type:     "file_open",
			Resource: fmt.Sprintf("file:%s", FilenameString(e.Filename)),
			Data:     fmt.Sprintf(`{"comm":%q,"pid":%d,"filename":%q,"flags":%d}`, e.Header.CommString(), e.Header.PID, FilenameString(e.Filename), e.Flags),
		}

	case EventNetConnect:
		var e NetConnectEvent
		if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
			return nil
		}
		ip := fmt.Sprintf("%d.%d.%d.%d", byte(e.DAddr), byte(e.DAddr>>8), byte(e.DAddr>>16), byte(e.DAddr>>24))
		return &coordinator.Event{
			Type:     "net_connect",
			Resource: fmt.Sprintf("ip:%s:%d", ip, e.DPort),
			Data:     fmt.Sprintf(`{"comm":%q,"pid":%d,"daddr":%q,"dport":%d}`, e.Header.CommString(), e.Header.PID, ip, e.DPort),
		}
	}

	return nil
}

// Close detaches all hooks and closes the ring buffer reader.
func (m *Manager) Close() error {
	if m.reader != nil {
		m.reader.Close()
	}
	for _, l := range m.links {
		l.Close()
	}
	return nil
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
