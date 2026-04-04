package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tidwall/buntdb"
)

var ErrNotFound = errors.New("not found")

// AgentMeta is metadata about an active agent goroutine.
type AgentMeta struct {
	Task      string    `json:"task"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
}

// LogEntry is a single entry in an agent's activity log.
type LogEntry struct {
	Action    string    `json:"action"`
	Result    string    `json:"result"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// Policy is an active policy on a resource.
type Policy struct {
	Rule   string    `json:"rule"`
	Value  string    `json:"value"`
	Reason string    `json:"reason"`
	SetAt  time.Time `json:"set_at"`
	SetBy  string    `json:"set_by,omitempty"`
}

// Event is a recorded eBPF event.
type Event struct {
	Type      string    `json:"type"`
	Resource  string    `json:"resource"`
	Data      string    `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}

// Store wraps buntdb for Veronica's shared state.
type Store struct {
	db *buntdb.DB
}

// Open creates or opens a state store. Use ":memory:" for in-memory mode.
func Open(path string) (*Store, error) {
	db, err := buntdb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open state db: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the state store.
func (s *Store) Close() error {
	return s.db.Close()
}

// SetAgentMeta sets metadata for an agent.
func (s *Store) SetAgentMeta(agentID string, meta AgentMeta) error {
	if meta.StartedAt.IsZero() {
		meta.StartedAt = time.Now()
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set("agent:"+agentID+":meta", string(b), &buntdb.SetOptions{
			Expires: true,
			TTL:     1 * time.Hour,
		})
		return err
	})
}

// GetAgentMeta gets metadata for an agent.
func (s *Store) GetAgentMeta(agentID string) (*AgentMeta, error) {
	var meta AgentMeta
	err := s.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get("agent:" + agentID + ":meta")
		if err == buntdb.ErrNotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &meta)
	})
	if err != nil {
		return nil, err
	}
	return &meta, nil
}

// AppendAgentLog appends a log entry to an agent's log.
func (s *Store) AppendAgentLog(agentID string, entry LogEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("agent:%s:log:%020d", agentID, entry.Timestamp.UnixNano())
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(b), &buntdb.SetOptions{
			Expires: true,
			TTL:     1 * time.Hour,
		})
		return err
	})
}

// GetAgentLog returns all log entries for an agent, oldest first.
func (s *Store) GetAgentLog(agentID string) ([]LogEntry, error) {
	var entries []LogEntry
	prefix := "agent:" + agentID + ":log:"
	err := s.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendRange("", prefix, prefix+"\xff", func(key, val string) bool {
			var entry LogEntry
			json.Unmarshal([]byte(val), &entry)
			entries = append(entries, entry)
			return true
		})
	})
	return entries, err
}

// SetPolicy sets a policy on a resource.
func (s *Store) SetPolicy(resourceType, resourceID string, policy Policy) error {
	if policy.SetAt.IsZero() {
		policy.SetAt = time.Now()
	}
	b, err := json.Marshal(policy)
	if err != nil {
		return err
	}
	key := "policy:" + resourceType + ":" + resourceID
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(b), nil)
		return err
	})
}

// GetPolicy gets a policy for a resource.
func (s *Store) GetPolicy(resourceType, resourceID string) (*Policy, error) {
	var policy Policy
	err := s.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get("policy:" + resourceType + ":" + resourceID)
		if err == buntdb.ErrNotFound {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &policy)
	})
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

// RecordEvent records an eBPF event.
func (s *Store) RecordEvent(event Event) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	key := fmt.Sprintf("event:%020d:%s", event.Timestamp.UnixNano(), event.Type)
	return s.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(key, string(b), &buntdb.SetOptions{
			Expires: true,
			TTL:     5 * time.Minute,
		})
		return err
	})
}

// RecentEvents returns the N most recent events.
func (s *Store) RecentEvents(limit int) ([]Event, error) {
	var events []Event
	err := s.db.View(func(tx *buntdb.Tx) error {
		return tx.DescendRange("", "event:\xff", "event:", func(key, val string) bool {
			if len(events) >= limit {
				return false
			}
			var event Event
			json.Unmarshal([]byte(val), &event)
			events = append(events, event)
			return true
		})
	})
	return events, err
}

// QueryByPattern returns key-value pairs matching a buntdb pattern.
func (s *Store) QueryByPattern(pattern string, limit int) (map[string]string, error) {
	results := make(map[string]string)
	err := s.db.View(func(tx *buntdb.Tx) error {
		return tx.AscendKeys(pattern, func(key, val string) bool {
			results[key] = val
			return len(results) < limit
		})
	})
	return results, err
}

// AgentContext builds a human/LLM-readable context string for an agent's activity.
func (s *Store) AgentContext(agentID string) (string, error) {
	meta, err := s.GetAgentMeta(agentID)
	if err != nil {
		return "", err
	}
	entries, err := s.GetAgentLog(agentID)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Agent: %s\nTask: %s\nStatus: %s\n", agentID, meta.Task, meta.Status)
	for _, e := range entries {
		fmt.Fprintf(&b, "- %s: %s\n", e.Action, e.Result)
	}
	return b.String(), nil
}
