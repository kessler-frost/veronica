package ebpf

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

// MapManager provides named access to loaded eBPF maps.
type MapManager struct {
	mu   sync.RWMutex
	maps map[string]*ebpf.Map
}

// NewMapManager creates an empty map manager.
func NewMapManager() *MapManager {
	return &MapManager{maps: make(map[string]*ebpf.Map)}
}

// Register adds a named map. Called by the manager after loading programs.
func (m *MapManager) Register(name string, em *ebpf.Map) {
	m.mu.Lock()
	m.maps[name] = em
	m.mu.Unlock()
}

// List returns all registered map names.
func (m *MapManager) List() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	names := make([]string, 0, len(m.maps))
	for name := range m.maps {
		names = append(names, name)
	}
	return names
}

// Lookup reads a value from a map by name.
// key and valueOut must be appropriate types for the map.
func (m *MapManager) Lookup(mapName string, key any, valueOut any) error {
	m.mu.RLock()
	em, ok := m.maps[mapName]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("map %q not found", mapName)
	}
	return em.Lookup(key, valueOut)
}

// Put writes a value to a map by name.
func (m *MapManager) Put(mapName string, key any, value any) error {
	m.mu.RLock()
	em, ok := m.maps[mapName]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("map %q not found", mapName)
	}
	return em.Put(key, value)
}

// Delete removes a key from a map by name.
func (m *MapManager) Delete(mapName string, key any) error {
	m.mu.RLock()
	em, ok := m.maps[mapName]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("map %q not found", mapName)
	}
	return em.Delete(key)
}

// DumpAll iterates all entries in a map, calling fn for each key-value pair.
// The fn receives raw bytes for key and value.
func (m *MapManager) DumpAll(mapName string) ([]MapEntry, error) {
	m.mu.RLock()
	em, ok := m.maps[mapName]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("map %q not found", mapName)
	}

	var entries []MapEntry
	iter := em.Iterate()
	var key, value []byte
	for iter.Next(&key, &value) {
		entry := MapEntry{
			Key:   make([]byte, len(key)),
			Value: make([]byte, len(value)),
		}
		copy(entry.Key, key)
		copy(entry.Value, value)
		entries = append(entries, entry)
	}
	return entries, iter.Err()
}

// MapEntry is a raw key-value pair from a map dump.
type MapEntry struct {
	Key   []byte
	Value []byte
}
