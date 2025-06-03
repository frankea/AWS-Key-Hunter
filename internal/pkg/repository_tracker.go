package pkg

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// RepositoryTracker keeps track of processed repositories
type RepositoryTracker struct {
	ProcessedRepos map[string]ProcessedRepo `json:"processed_repos"`
	mu             sync.RWMutex
	filePath       string
}

// ProcessedRepo stores information about a processed repository
type ProcessedRepo struct {
	FullName      string    `json:"full_name"`
	LastProcessed time.Time `json:"last_processed"`
	FilesChecked  []string  `json:"files_checked"`
}

// NewRepositoryTracker creates a new repository tracker
func NewRepositoryTracker(filePath string) (*RepositoryTracker, error) {
	tracker := &RepositoryTracker{
		ProcessedRepos: make(map[string]ProcessedRepo),
		filePath:       filePath,
	}

	// Load existing data if file exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, err
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &tracker.ProcessedRepos); err != nil {
				return nil, err
			}
		}
	}

	return tracker, nil
}

// IsProcessed checks if a repository file has been processed recently
func (rt *RepositoryTracker) IsProcessed(repoFullName, filePath string) bool {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	repo, exists := rt.ProcessedRepos[repoFullName]
	if !exists {
		return false
	}

	// Check if we've processed this specific file
	for _, file := range repo.FilesChecked {
		if file == filePath {
			// Consider files processed within the last 24 hours as already processed
			if time.Since(repo.LastProcessed) < 24*time.Hour {
				return true
			}
		}
	}

	return false
}

// MarkProcessed marks a repository file as processed
func (rt *RepositoryTracker) MarkProcessed(repoFullName, filePath string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	repo, exists := rt.ProcessedRepos[repoFullName]
	if !exists {
		repo = ProcessedRepo{
			FullName:      repoFullName,
			LastProcessed: time.Now(),
			FilesChecked:  []string{filePath},
		}
	} else {
		repo.LastProcessed = time.Now()
		// Add file if not already in the list
		fileExists := false
		for _, file := range repo.FilesChecked {
			if file == filePath {
				fileExists = true
				break
			}
		}
		if !fileExists {
			repo.FilesChecked = append(repo.FilesChecked, filePath)
		}
	}

	rt.ProcessedRepos[repoFullName] = repo

	// Save to file
	return rt.save()
}

// save persists the tracker data to file
func (rt *RepositoryTracker) save() error {
	data, err := json.MarshalIndent(rt.ProcessedRepos, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rt.filePath, data, 0644)
}

// CleanOldEntries removes entries older than the specified duration
func (rt *RepositoryTracker) CleanOldEntries(maxAge time.Duration) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	for key, repo := range rt.ProcessedRepos {
		if time.Since(repo.LastProcessed) > maxAge {
			delete(rt.ProcessedRepos, key)
		}
	}

	return rt.save()
}