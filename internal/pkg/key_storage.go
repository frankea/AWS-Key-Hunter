package pkg

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type AWSKeyFinding struct {
	AccessKey      string    `json:"access_key"`
	SecretKey      string    `json:"secret_key"`
	Repository     string    `json:"repository"`
	FileURL        string    `json:"file_url"`
	FilePath       string    `json:"file_path"`
	DiscoveredAt   time.Time `json:"discovered_at"`
	ValidatedAt    time.Time `json:"validated_at"`
	AccountID      string    `json:"account_id,omitempty"`
	UserName       string    `json:"user_name,omitempty"`
	ARN            string    `json:"arn,omitempty"`
	Permissions    []string  `json:"permissions,omitempty"`
	CommitSHA      string    `json:"commit_sha,omitempty"`
	CommitAuthor   string    `json:"commit_author,omitempty"`
	CommitDate     time.Time `json:"commit_date,omitempty"`
	FileSize       int       `json:"file_size,omitempty"`
}

type KeyStorage struct {
	mu       sync.Mutex
	filePath string
	findings []AWSKeyFinding
}

func NewKeyStorage(filePath string) (*KeyStorage, error) {
	ks := &KeyStorage{
		filePath: filePath,
		findings: []AWSKeyFinding{},
	}

	// Load existing findings if file exists
	if _, err := os.Stat(filePath); err == nil {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read existing findings: %w", err)
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &ks.findings); err != nil {
				return nil, fmt.Errorf("failed to parse existing findings: %w", err)
			}
		}
	}

	return ks, nil
}

func (ks *KeyStorage) AddFinding(finding AWSKeyFinding) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Check if this key already exists
	for _, existing := range ks.findings {
		if existing.AccessKey == finding.AccessKey && existing.Repository == finding.Repository {
			// Already recorded
			return nil
		}
	}

	finding.DiscoveredAt = time.Now()
	ks.findings = append(ks.findings, finding)

	// Save to file
	return ks.save()
}

func (ks *KeyStorage) save() error {
	data, err := json.MarshalIndent(ks.findings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal findings: %w", err)
	}

	if err := os.WriteFile(ks.filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write findings file: %w", err)
	}

	// Also create a CSV file for easy viewing
	csvPath := ks.filePath + ".csv"
	return ks.saveCSV(csvPath)
}

func (ks *KeyStorage) saveCSV(csvPath string) error {
	file, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	// Write header
	fmt.Fprintln(file, "Access Key,Repository,File URL,File Path,Discovered At,Commit Date,Account ID,User Name,Commit SHA")

	// Write data
	for _, finding := range ks.findings {
		commitDateStr := ""
		if !finding.CommitDate.IsZero() {
			commitDateStr = finding.CommitDate.Format(time.RFC3339)
		}
		fmt.Fprintf(file, "%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			finding.AccessKey,
			finding.Repository,
			finding.FileURL,
			finding.FilePath,
			finding.DiscoveredAt.Format(time.RFC3339),
			commitDateStr,
			finding.AccountID,
			finding.UserName,
			finding.CommitSHA,
		)
	}

	return nil
}

func (ks *KeyStorage) GetFindings() []AWSKeyFinding {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	
	// Return a copy to avoid race conditions
	findings := make([]AWSKeyFinding, len(ks.findings))
	copy(findings, ks.findings)
	return findings
}