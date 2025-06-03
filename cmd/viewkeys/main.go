// Package main provides a command-line tool to view discovered AWS keys
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/frankea/AWS-Key-Hunter/internal/pkg"
)

func main() {
	// Read the findings file
	data, err := os.ReadFile("aws_keys_found.json")
	if err != nil {
		log.Fatal("Error reading aws_keys_found.json:", err)
	}

	var findings []pkg.AWSKeyFinding
	if err := json.Unmarshal(data, &findings); err != nil {
		log.Fatal("Error parsing JSON:", err)
	}

	fmt.Printf("\n🔐 AWS Keys Found: %d\n", len(findings))
	fmt.Println("=" + string(make([]byte, 80)))

	for i, finding := range findings {
		fmt.Printf("\n[%d] Repository: %s\n", i+1, finding.Repository)
		fmt.Printf("    Access Key: %s\n", finding.AccessKey)
		fmt.Printf("    Account ID: %s\n", finding.AccountID)
		if finding.UserName != "" {
			fmt.Printf("    User Name: %s\n", finding.UserName)
		}
		if len(finding.Permissions) > 0 {
			fmt.Printf("    Permissions: %v\n", finding.Permissions)
		} else {
			fmt.Printf("    Permissions: Limited/None detected\n")
		}
		fmt.Printf("    File Path: %s\n", finding.FilePath)
		fmt.Printf("    File URL: %s\n", finding.FileURL)
		if !finding.CommitDate.IsZero() {
			age := time.Since(finding.CommitDate)
			fmt.Printf("    Commit Date: %s (%s ago)\n", finding.CommitDate.Format("2006-01-02 15:04:05"), formatDuration(age))
			if finding.CommitAuthor != "" {
				fmt.Printf("    Commit Author: %s\n", finding.CommitAuthor)
			}
		}
		fmt.Printf("    Discovered: %s\n", finding.DiscoveredAt.Format("2006-01-02 15:04:05"))
		fmt.Println("-" + string(make([]byte, 80)))
	}

	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total keys found: %d\n", len(findings))

	// Count unique repositories
	repos := make(map[string]bool)
	for _, f := range findings {
		repos[f.Repository] = true
	}
	fmt.Printf("   Unique repositories: %d\n", len(repos))

	// Count unique accounts
	accounts := make(map[string]bool)
	for _, f := range findings {
		if f.AccountID != "" {
			accounts[f.AccountID] = true
		}
	}
	fmt.Printf("   Unique AWS accounts: %d\n", len(accounts))
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	if days > 0 {
		if days == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", days)
	}

	hours := int(d.Hours())
	if hours > 0 {
		if hours == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", hours)
	}

	minutes := int(d.Minutes())
	if minutes > 0 {
		if minutes == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", minutes)
	}

	return "just now"
}
