// Package main provides deduplication statistics for AWS Key Hunter
package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/frankea/AWS-Key-Hunter/internal/pkg"
)

func main() {
	// Initialize key storage
	keyStorage, err := pkg.NewKeyStorage("aws_keys_found.json")
	if err != nil {
		log.Fatal("Error initializing key storage:", err)
	}

	// Get all findings
	findings := keyStorage.GetFindings()
	if len(findings) == 0 {
		fmt.Println("No findings available for deduplication analysis.")
		return
	}

	// Initialize deduplication manager
	deduplicator := pkg.NewDeduplicationManager(pkg.DefaultDeduplicationConfig())

	// Analyze all existing findings
	fmt.Printf("🔍 Analyzing %d findings for duplicates...\n", len(findings))
	
	duplicates := 0
	for i := range findings {
		analysis := deduplicator.AnalyzeFinding(&findings[i])
		if analysis.IsDuplicate {
			duplicates++
			fmt.Printf("  📊 Finding %d: %s (confidence: %.2f)\n", 
				i+1, analysis.DuplicateType, analysis.Confidence)
		}
		// Add to tracking regardless
		deduplicator.AddFinding(&findings[i])
	}

	// Print statistics
	fmt.Printf("\n📈 Deduplication Statistics:\n")
	stats := deduplicator.GetDuplicationStats()
	
	statsJSON, _ := json.MarshalIndent(stats, "", "  ")
	fmt.Println(string(statsJSON))

	// Print account groups
	fmt.Printf("\n🏢 Account Groups:\n")
	groups := deduplicator.GetAccountGroups()
	
	for i, group := range groups {
		if i >= 10 { // Show top 10 groups
			break
		}
		fmt.Printf("  %d. Account: %s\n", i+1, group.AccountID)
		fmt.Printf("     Findings: %d, Unique Keys: %d, Repositories: %d\n",
			len(group.Findings), group.UniqueKeys, len(group.Repositories))
		fmt.Printf("     First Seen: %s, Last Seen: %s\n\n",
			group.FirstSeen.Format("2006-01-02"), group.LastSeen.Format("2006-01-02"))
	}

	fmt.Printf("Found %d duplicate patterns out of %d total findings (%.1f%% duplication rate)\n",
		duplicates, len(findings), float64(duplicates)/float64(len(findings))*100)
}