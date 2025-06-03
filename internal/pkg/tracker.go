package pkg

import (
	"sync"
	"time"
)

type FileTracker struct {
	mu        sync.RWMutex
	processed map[string]time.Time
	ttl       time.Duration
}

func NewFileTracker(ttl time.Duration) *FileTracker {
	return &FileTracker{
		processed: make(map[string]time.Time),
		ttl:       ttl,
	}
}

func (ft *FileTracker) IsProcessed(key string) bool {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	if processedTime, exists := ft.processed[key]; exists {
		if time.Since(processedTime) < ft.ttl {
			return true
		}
		delete(ft.processed, key)
	}
	return false
}

func (ft *FileTracker) MarkProcessed(key string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	ft.processed[key] = time.Now()
}

func (ft *FileTracker) Cleanup() {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := time.Now()
	for key, processedTime := range ft.processed {
		if now.Sub(processedTime) > ft.ttl {
			delete(ft.processed, key)
		}
	}
}
