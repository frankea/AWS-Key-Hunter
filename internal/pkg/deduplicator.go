// Package pkg provides advanced deduplication for AWS key findings
package pkg

import (
	"crypto/sha256"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// DeduplicationManager handles advanced duplicate detection and grouping
type DeduplicationManager struct {
	// Account-level grouping
	accountGroups map[string]*AccountGroup
	
	// Repository relationship tracking
	repoRelations map[string]*RepositoryRelationship
	
	// Finding fingerprints for similarity detection
	findingFingerprints map[string]*FindingFingerprint
	
	// Thread safety
	mu sync.RWMutex
	
	// Configuration
	config DeduplicationConfig
}

// AccountGroup represents findings grouped by AWS account
type AccountGroup struct {
	AccountID    string
	Findings     []*AWSKeyFinding
	FirstSeen    time.Time
	LastSeen     time.Time
	UniqueKeys   int
	Repositories []string
}

// RepositoryRelationship tracks relationships between repositories
type RepositoryRelationship struct {
	Repository    string
	RelatedRepos  []string // Forks, mirrors, related projects
	Confidence    float64  // How confident we are in the relationship
	Relationship  string   // Type: "fork", "mirror", "similar", "org"
}

// FindingFingerprint represents a unique signature for a finding
type FindingFingerprint struct {
	Signature    string
	Finding      *AWSKeyFinding
	SimilarFiles []string // Files with similar patterns
	Confidence   float64  // How unique this finding is
}

// DeduplicationConfig controls deduplication behavior
type DeduplicationConfig struct {
	// Similarity thresholds
	RepoSimilarityThreshold    float64 // 0.8 = 80% similar
	FileSimilarityThreshold    float64 // 0.7 = 70% similar
	ContentSimilarityThreshold float64 // 0.9 = 90% similar
	
	// Time-based relevance
	RecentFindingBoost   time.Duration // Boost findings newer than this
	StaleFindingPenalty  time.Duration // Penalize findings older than this
	
	// Grouping preferences
	PreferRecentFindings bool
	PreferUniqueRepos    bool
	PreferHighActivity   bool
}

// DuplicateAnalysis contains the results of duplicate analysis
type DuplicateAnalysis struct {
	IsDuplicate      bool
	DuplicateType    string // "exact", "account", "repo-related", "content-similar"
	OriginalFinding  *AWSKeyFinding
	Confidence       float64
	Reasons          []string
	RecommendedAction string // "skip", "update", "keep-both"
}

// NewDeduplicationManager creates a new deduplication manager
func NewDeduplicationManager(config DeduplicationConfig) *DeduplicationManager {
	return &DeduplicationManager{
		accountGroups:       make(map[string]*AccountGroup),
		repoRelations:       make(map[string]*RepositoryRelationship),
		findingFingerprints: make(map[string]*FindingFingerprint),
		config:              config,
	}
}

// AnalyzeFinding determines if a finding is a duplicate and how to handle it
func (dm *DeduplicationManager) AnalyzeFinding(finding *AWSKeyFinding) DuplicateAnalysis {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	analysis := DuplicateAnalysis{
		IsDuplicate: false,
		Reasons:     []string{},
	}
	
	// 1. Check for exact key duplicates
	if exactDupe := dm.findExactDuplicate(finding); exactDupe != nil {
		analysis.IsDuplicate = true
		analysis.DuplicateType = "exact"
		analysis.OriginalFinding = exactDupe
		analysis.Confidence = 1.0
		analysis.Reasons = append(analysis.Reasons, "Exact key match found")
		analysis.RecommendedAction = dm.determineExactDuplicateAction(finding, exactDupe)
		return analysis
	}
	
	// 2. Check for account-level duplicates
	if accountDupe := dm.findAccountDuplicate(finding); accountDupe != nil {
		analysis.IsDuplicate = true
		analysis.DuplicateType = "account"
		analysis.OriginalFinding = accountDupe
		analysis.Confidence = 0.9
		analysis.Reasons = append(analysis.Reasons, "Same AWS account, different keys")
		analysis.RecommendedAction = "keep-both" // Different keys, keep both
	}
	
	// 3. Check for repository relationship duplicates
	if repoDupe := dm.findRepositoryRelatedDuplicate(finding); repoDupe != nil {
		confidence := dm.calculateRepoRelationConfidence(finding.Repository, repoDupe.Repository)
		if confidence >= dm.config.RepoSimilarityThreshold {
			analysis.IsDuplicate = true
			analysis.DuplicateType = "repo-related"
			analysis.OriginalFinding = repoDupe
			analysis.Confidence = confidence
			analysis.Reasons = append(analysis.Reasons, "Found in related repository")
			analysis.RecommendedAction = dm.determineRepoRelatedAction(finding, repoDupe, confidence)
		}
	}
	
	// 4. Check for content similarity duplicates
	if contentDupe := dm.findContentSimilarDuplicate(finding); contentDupe != nil {
		confidence := dm.calculateContentSimilarity(finding, contentDupe)
		if confidence >= dm.config.ContentSimilarityThreshold {
			analysis.IsDuplicate = true
			analysis.DuplicateType = "content-similar"
			analysis.OriginalFinding = contentDupe
			analysis.Confidence = confidence
			analysis.Reasons = append(analysis.Reasons, "Very similar file content/structure")
			analysis.RecommendedAction = "update" // Update original with new info
		}
	}
	
	return analysis
}

// AddFinding adds a finding to the deduplication tracking
func (dm *DeduplicationManager) AddFinding(finding *AWSKeyFinding) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	
	// Add to account grouping
	dm.addToAccountGroup(finding)
	
	// Update repository relationships
	dm.updateRepositoryRelationships(finding)
	
	// Create finding fingerprint
	dm.createFindingFingerprint(finding)
	
	log.Printf("📊 Deduplication: Added finding for account %s in repo %s", 
		finding.AccountID, finding.Repository)
}

// GetAccountGroups returns all account groups sorted by relevance
func (dm *DeduplicationManager) GetAccountGroups() []*AccountGroup {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	groups := make([]*AccountGroup, 0, len(dm.accountGroups))
	for _, group := range dm.accountGroups {
		groups = append(groups, group)
	}
	
	// Sort by relevance (recent activity, unique keys, etc.)
	sort.Slice(groups, func(i, j int) bool {
		return dm.calculateGroupRelevance(groups[i]) > dm.calculateGroupRelevance(groups[j])
	})
	
	return groups
}

// GetDuplicationStats returns statistics about duplicates found
func (dm *DeduplicationManager) GetDuplicationStats() map[string]interface{} {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	
	totalFindings := 0
	uniqueAccounts := len(dm.accountGroups)
	uniqueRepos := len(dm.repoRelations)
	
	for _, group := range dm.accountGroups {
		totalFindings += len(group.Findings)
	}
	
	return map[string]interface{}{
		"total_findings":    totalFindings,
		"unique_accounts":   uniqueAccounts,
		"unique_repos":      uniqueRepos,
		"fingerprints":      len(dm.findingFingerprints),
		"deduplication_rate": dm.calculateDeduplicationRate(),
	}
}

// findExactDuplicate looks for exact key matches
func (dm *DeduplicationManager) findExactDuplicate(finding *AWSKeyFinding) *AWSKeyFinding {
	for _, group := range dm.accountGroups {
		for _, existing := range group.Findings {
			if existing.AccessKey == finding.AccessKey && 
			   existing.SecretKey == finding.SecretKey {
				return existing
			}
		}
	}
	return nil
}

// findAccountDuplicate looks for findings from the same AWS account
func (dm *DeduplicationManager) findAccountDuplicate(finding *AWSKeyFinding) *AWSKeyFinding {
	if finding.AccountID == "" {
		return nil
	}
	
	if group, exists := dm.accountGroups[finding.AccountID]; exists {
		if len(group.Findings) > 0 {
			// Return the most recent finding from this account
			return dm.getMostRecentFinding(group.Findings)
		}
	}
	return nil
}

// findRepositoryRelatedDuplicate looks for findings in related repositories
func (dm *DeduplicationManager) findRepositoryRelatedDuplicate(finding *AWSKeyFinding) *AWSKeyFinding {
	repoName := finding.Repository
	
	// Check if we have relationship data for this repo
	if relation, exists := dm.repoRelations[repoName]; exists {
		for _, relatedRepo := range relation.RelatedRepos {
			if foundFinding := dm.findFindingInRepository(relatedRepo); foundFinding != nil {
				return foundFinding
			}
		}
	}
	
	// Check for obvious relationships (forks, org repos, etc.)
	for _, group := range dm.accountGroups {
		for _, existing := range group.Findings {
			if dm.areRepositoriesRelated(repoName, existing.Repository) {
				return existing
			}
		}
	}
	
	return nil
}

// findContentSimilarDuplicate looks for findings with very similar content patterns
func (dm *DeduplicationManager) findContentSimilarDuplicate(finding *AWSKeyFinding) *AWSKeyFinding {
	findingFingerprint := dm.generateContentFingerprint(finding)
	
	for _, existing := range dm.findingFingerprints {
		similarity := dm.compareFingerprints(findingFingerprint, existing.Signature)
		if similarity >= dm.config.ContentSimilarityThreshold {
			return existing.Finding
		}
	}
	
	return nil
}

// addToAccountGroup adds a finding to the appropriate account group
func (dm *DeduplicationManager) addToAccountGroup(finding *AWSKeyFinding) {
	accountID := finding.AccountID
	if accountID == "" {
		accountID = "unknown" // Group unknown accounts together
	}
	
	group, exists := dm.accountGroups[accountID]
	if !exists {
		group = &AccountGroup{
			AccountID:    accountID,
			Findings:     []*AWSKeyFinding{},
			FirstSeen:    finding.DiscoveredAt,
			UniqueKeys:   0,
			Repositories: []string{},
		}
		dm.accountGroups[accountID] = group
	}
	
	// Add finding to group
	group.Findings = append(group.Findings, finding)
	group.LastSeen = finding.DiscoveredAt
	
	// Update unique keys count
	group.UniqueKeys = dm.countUniqueKeysInGroup(group)
	
	// Update repositories list
	if !dm.stringInSlice(finding.Repository, group.Repositories) {
		group.Repositories = append(group.Repositories, finding.Repository)
	}
}

// updateRepositoryRelationships analyzes and updates repository relationships
func (dm *DeduplicationManager) updateRepositoryRelationships(finding *AWSKeyFinding) {
	repoName := finding.Repository
	
	if _, exists := dm.repoRelations[repoName]; !exists {
		dm.repoRelations[repoName] = &RepositoryRelationship{
			Repository:   repoName,
			RelatedRepos: []string{},
			Confidence:   1.0,
			Relationship: "primary",
		}
	}
	
	// Look for potential relationships with existing repos
	for existingRepo := range dm.repoRelations {
		if existingRepo != repoName {
			if relationship := dm.detectRepositoryRelationship(repoName, existingRepo); relationship != "" {
				dm.addRepositoryRelationship(repoName, existingRepo, relationship)
			}
		}
	}
}

// createFindingFingerprint creates a unique signature for the finding
func (dm *DeduplicationManager) createFindingFingerprint(finding *AWSKeyFinding) {
	signature := dm.generateContentFingerprint(finding)
	
	fingerprint := &FindingFingerprint{
		Signature:    signature,
		Finding:      finding,
		SimilarFiles: []string{},
		Confidence:   1.0, // Start with high confidence
	}
	
	dm.findingFingerprints[signature] = fingerprint
}

// generateContentFingerprint creates a unique signature based on file content patterns
func (dm *DeduplicationManager) generateContentFingerprint(finding *AWSKeyFinding) string {
	// Create fingerprint based on:
	// - File path structure
	// - Repository structure  
	// - Key positioning/context
	// - Account characteristics
	
	components := []string{
		dm.normalizeFilePath(finding.FilePath),
		dm.extractRepoStructure(finding.Repository),
		finding.AccountID,
		fmt.Sprintf("permissions_%d", len(finding.Permissions)),
	}
	
	// Create hash of components
	combined := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("%x", hash[:8]) // Use first 8 bytes for fingerprint
}

// Helper functions

func (dm *DeduplicationManager) determineExactDuplicateAction(new, existing *AWSKeyFinding) string {
	// If new finding has more information, update the original
	if dm.findingHasMoreInfo(new, existing) {
		return "update"
	}
	
	// If findings are from different repos, it might be worth keeping both
	if new.Repository != existing.Repository {
		return "keep-both"
	}
	
	return "skip"
}

func (dm *DeduplicationManager) determineRepoRelatedAction(new, existing *AWSKeyFinding, confidence float64) string {
	if confidence > 0.9 {
		return "skip" // Very likely the same finding
	} else if confidence > 0.8 {
		return "update" // Update with new information
	}
	return "keep-both" // Different enough to keep separate
}

func (dm *DeduplicationManager) calculateRepoRelationConfidence(repo1, repo2 string) float64 {
	// Check for obvious relationships
	if dm.areRepositoriesRelated(repo1, repo2) {
		return 0.95
	}
	
	// Check for naming similarity
	similarity := dm.calculateStringSimilarity(repo1, repo2)
	return similarity
}

func (dm *DeduplicationManager) calculateContentSimilarity(finding1, finding2 *AWSKeyFinding) float64 {
	// Compare file paths
	pathSim := dm.calculateStringSimilarity(finding1.FilePath, finding2.FilePath)
	
	// Compare repositories
	repoSim := dm.calculateStringSimilarity(finding1.Repository, finding2.Repository)
	
	// Compare account info
	accountSim := 0.0
	if finding1.AccountID == finding2.AccountID {
		accountSim = 1.0
	}
	
	// Weighted average
	return (pathSim*0.4 + repoSim*0.4 + accountSim*0.2)
}

func (dm *DeduplicationManager) areRepositoriesRelated(repo1, repo2 string) bool {
	// Check for fork patterns
	if dm.isForkRelationship(repo1, repo2) {
		return true
	}
	
	// Check for organization relationship
	if dm.isOrganizationRelationship(repo1, repo2) {
		return true
	}
	
	// Check for naming patterns
	if dm.isSimilarNaming(repo1, repo2) {
		return true
	}
	
	return false
}

func (dm *DeduplicationManager) isForkRelationship(repo1, repo2 string) bool {
	// Look for common fork patterns
	parts1 := strings.Split(repo1, "/")
	parts2 := strings.Split(repo2, "/")
	
	if len(parts1) == 2 && len(parts2) == 2 {
		// Same repo name, different owner (likely fork)
		return parts1[1] == parts2[1] && parts1[0] != parts2[0]
	}
	
	return false
}

func (dm *DeduplicationManager) isOrganizationRelationship(repo1, repo2 string) bool {
	parts1 := strings.Split(repo1, "/")
	parts2 := strings.Split(repo2, "/")
	
	if len(parts1) == 2 && len(parts2) == 2 {
		// Same organization/user, different repos
		return parts1[0] == parts2[0] && parts1[1] != parts2[1]
	}
	
	return false
}

func (dm *DeduplicationManager) isSimilarNaming(repo1, repo2 string) bool {
	similarity := dm.calculateStringSimilarity(repo1, repo2)
	return similarity >= 0.8
}

func (dm *DeduplicationManager) calculateStringSimilarity(s1, s2 string) float64 {
	// Simple Levenshtein-based similarity
	if s1 == s2 {
		return 1.0
	}
	
	longer, shorter := s1, s2
	if len(s1) < len(s2) {
		longer, shorter = s2, s1
	}
	
	longerLen := len(longer)
	if longerLen == 0 {
		return 1.0
	}
	
	editDistance := dm.levenshteinDistance(longer, shorter)
	return (float64(longerLen) - float64(editDistance)) / float64(longerLen)
}

func (dm *DeduplicationManager) levenshteinDistance(s1, s2 string) int {
	len1, len2 := len(s1), len(s2)
	matrix := make([][]int, len1+1)
	
	for i := range matrix {
		matrix[i] = make([]int, len2+1)
		matrix[i][0] = i
	}
	
	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}
	
	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			
			matrix[i][j] = min3(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}
	
	return matrix[len1][len2]
}

func min3(a, b, c int) int {
	if a <= b && a <= c {
		return a
	}
	if b <= c {
		return b
	}
	return c
}

func (dm *DeduplicationManager) normalizeFilePath(path string) string {
	// Normalize path for comparison
	normalized := strings.ToLower(path)
	// Remove common variations
	patterns := map[string]string{
		`/+`:                 "/",
		`\.env\..*`:          ".env",
		`config\d+`:          "config",
		`production|prod|prd`: "prod",
		`development|dev`:     "dev",
		`staging|stage|stg`:   "stage",
	}
	
	for pattern, replacement := range patterns {
		re := regexp.MustCompile(pattern)
		normalized = re.ReplaceAllString(normalized, replacement)
	}
	
	return normalized
}

func (dm *DeduplicationManager) extractRepoStructure(repo string) string {
	// Extract meaningful patterns from repository name
	parts := strings.Split(repo, "/")
	if len(parts) == 2 {
		return fmt.Sprintf("org:%s,name:%s", parts[0], parts[1])
	}
	return repo
}

func (dm *DeduplicationManager) countUniqueKeysInGroup(group *AccountGroup) int {
	seen := make(map[string]bool)
	for _, finding := range group.Findings {
		key := finding.AccessKey + ":" + finding.SecretKey
		seen[key] = true
	}
	return len(seen)
}

func (dm *DeduplicationManager) getMostRecentFinding(findings []*AWSKeyFinding) *AWSKeyFinding {
	if len(findings) == 0 {
		return nil
	}
	
	mostRecent := findings[0]
	for _, finding := range findings[1:] {
		if finding.DiscoveredAt.After(mostRecent.DiscoveredAt) {
			mostRecent = finding
		}
	}
	return mostRecent
}

func (dm *DeduplicationManager) findFindingInRepository(repoName string) *AWSKeyFinding {
	for _, group := range dm.accountGroups {
		for _, finding := range group.Findings {
			if finding.Repository == repoName {
				return finding
			}
		}
	}
	return nil
}

func (dm *DeduplicationManager) compareFingerprints(fp1, fp2 string) float64 {
	if fp1 == fp2 {
		return 1.0
	}
	return dm.calculateStringSimilarity(fp1, fp2)
}

func (dm *DeduplicationManager) detectRepositoryRelationship(repo1, repo2 string) string {
	if dm.isForkRelationship(repo1, repo2) {
		return "fork"
	}
	if dm.isOrganizationRelationship(repo1, repo2) {
		return "org"
	}
	if dm.isSimilarNaming(repo1, repo2) {
		return "similar"
	}
	return ""
}

func (dm *DeduplicationManager) addRepositoryRelationship(repo1, repo2, relationshipType string) {
	if relation, exists := dm.repoRelations[repo1]; exists {
		if !dm.stringInSlice(repo2, relation.RelatedRepos) {
			relation.RelatedRepos = append(relation.RelatedRepos, repo2)
		}
	}
}

func (dm *DeduplicationManager) stringInSlice(str string, slice []string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

func (dm *DeduplicationManager) findingHasMoreInfo(new, existing *AWSKeyFinding) bool {
	newScore := dm.calculateFindingInfoScore(new)
	existingScore := dm.calculateFindingInfoScore(existing)
	return newScore > existingScore
}

func (dm *DeduplicationManager) calculateFindingInfoScore(finding *AWSKeyFinding) int {
	score := 0
	if finding.AccountID != "" { score += 10 }
	if finding.UserName != "" { score += 5 }
	if finding.ARN != "" { score += 5 }
	if len(finding.Permissions) > 0 { score += len(finding.Permissions) * 2 }
	if finding.CommitSHA != "" { score += 3 }
	return score
}

func (dm *DeduplicationManager) calculateGroupRelevance(group *AccountGroup) float64 {
	relevance := 0.0
	
	// Recent activity boost
	daysSinceLastSeen := time.Since(group.LastSeen).Hours() / 24
	if daysSinceLastSeen < 7 {
		relevance += 1.0 - (daysSinceLastSeen / 7.0)
	}
	
	// Unique keys factor
	relevance += float64(group.UniqueKeys) * 0.1
	
	// Repository diversity
	relevance += float64(len(group.Repositories)) * 0.05
	
	return relevance
}

func (dm *DeduplicationManager) calculateDeduplicationRate() float64 {
	totalFingerprints := len(dm.findingFingerprints)
	if totalFingerprints == 0 {
		return 0.0
	}
	
	totalFindings := 0
	for _, group := range dm.accountGroups {
		totalFindings += len(group.Findings)
	}
	
	if totalFindings == 0 {
		return 0.0
	}
	
	return 1.0 - (float64(totalFingerprints) / float64(totalFindings))
}

// DefaultDeduplicationConfig returns sensible defaults
func DefaultDeduplicationConfig() DeduplicationConfig {
	return DeduplicationConfig{
		RepoSimilarityThreshold:    0.8,
		FileSimilarityThreshold:    0.7,
		ContentSimilarityThreshold: 0.9,
		RecentFindingBoost:         7 * 24 * time.Hour,  // 7 days
		StaleFindingPenalty:        30 * 24 * time.Hour, // 30 days
		PreferRecentFindings:       true,
		PreferUniqueRepos:          true,
		PreferHighActivity:         true,
	}
}