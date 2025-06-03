// Package pkg provides contextual AWS key extraction with confidence scoring
package pkg

import (
	"regexp"
	"strings"
)

type KeyCandidate struct {
	AccessKey  string
	SecretKey  string
	Context    string
	Confidence float64
	LineNumber int
}

// ContextualKeyExtractor extracts AWS keys with context awareness
type ContextualKeyExtractor struct {
	accessKeyRegex *regexp.Regexp
	secretKeyRegex *regexp.Regexp
	contextRegex   *regexp.Regexp
}

func NewContextualKeyExtractor() *ContextualKeyExtractor {
	return &ContextualKeyExtractor{
		// AWS Access Key pattern
		accessKeyRegex: regexp.MustCompile(`(AKIA[0-9A-Z]{16})`),

		// More specific secret key patterns with context
		secretKeyRegex: regexp.MustCompile(`(?i)(?:aws[_\s\-]*secret[_\s\-]*(?:access[_\s\-]*)?key|AWS_SECRET_ACCESS_KEY|aws_secret_access_key|secret[_\s\-]*key|SecretAccessKey)[\s:="']*([a-zA-Z0-9/+]{40})(?:["\s'$]|$)`),

		// Context indicators for higher confidence
		contextRegex: regexp.MustCompile(`(?i)(aws|amazon|credentials|secret|access[_\s\-]*key|config)`),
	}
}

// ExtractKeysWithContext extracts AWS keys with surrounding context
func (e *ContextualKeyExtractor) ExtractKeysWithContext(content string) []KeyCandidate {
	var candidates []KeyCandidate
	lines := strings.Split(content, "\n")

	// First pass: find all access keys
	accessKeyMap := make(map[string][]int) // accessKey -> line numbers
	for i, line := range lines {
		if matches := e.accessKeyRegex.FindAllString(line, -1); matches != nil {
			for _, match := range matches {
				accessKeyMap[match] = append(accessKeyMap[match], i)
			}
		}
	}

	// Second pass: find secret keys and match with access keys
	for i, line := range lines {
		secretMatches := e.secretKeyRegex.FindAllStringSubmatch(line, -1)
		for _, match := range secretMatches {
			if len(match) >= 2 {
				secretKey := match[len(match)-1] // Last capture group is the key

				// Look for nearby access keys (within 10 lines)
				for accessKey, lineNums := range accessKeyMap {
					for _, accessKeyLine := range lineNums {
						const maxLineDistance = 10
						if abs(i-accessKeyLine) <= maxLineDistance {
							candidate := KeyCandidate{
								AccessKey:  accessKey,
								SecretKey:  secretKey,
								LineNumber: i,
								Context:    e.getContext(lines, i, 2),
								Confidence: e.calculateConfidence(lines, i, accessKeyLine),
							}
							candidates = append(candidates, candidate)
						}
					}
				}
			}
		}
	}

	// Also check for inline key pairs
	candidates = append(candidates, e.extractInlineKeyPairs(content)...)

	// Deduplicate and sort by confidence
	return e.deduplicateAndSort(candidates)
}

// extractInlineKeyPairs finds keys that appear together
func (e *ContextualKeyExtractor) extractInlineKeyPairs(content string) []KeyCandidate {
	var candidates []KeyCandidate

	// Pattern for keys appearing together
	pairPattern := regexp.MustCompile(`(?i)(?:aws[_\s\-]*)?access[_\s\-]*key[_\s\-]*(?:id)?[\s:="']*?(AKIA[0-9A-Z]{16})[\s\S]{0,100}?(?:aws[_\s\-]*)?secret[_\s\-]*(?:access[_\s\-]*)?key[\s:="']*?([a-zA-Z0-9/+]{40})`)

	matches := pairPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			candidates = append(candidates, KeyCandidate{
				AccessKey:  match[1],
				SecretKey:  match[2],
				Context:    match[0],
				Confidence: 0.9, // High confidence for inline pairs
			})
		}
	}

	return candidates
}

// getContext returns surrounding lines for context
func (e *ContextualKeyExtractor) getContext(lines []string, lineNum int, radius int) string {
	start := max(0, lineNum-radius)
	end := min(len(lines), lineNum+radius+1)

	contextLines := lines[start:end]
	return strings.Join(contextLines, "\n")
}

// calculateConfidence scores based on context clues
func (e *ContextualKeyExtractor) calculateConfidence(lines []string, secretKeyLine, accessKeyLine int) float64 {
	confidence := 0.5 // Base confidence

	// Check distance between keys
	distance := abs(secretKeyLine - accessKeyLine)
	if distance == 0 {
		confidence += 0.3 // Same line
	} else if distance <= 2 {
		confidence += 0.2 // Very close
	} else if distance <= 5 {
		confidence += 0.1 // Close
	}

	// Check for AWS context keywords
	contextRadius := 5
	start := max(0, min(secretKeyLine, accessKeyLine)-contextRadius)
	end := min(len(lines), max(secretKeyLine, accessKeyLine)+contextRadius+1)

	for i := start; i < end; i++ {
		if e.contextRegex.MatchString(lines[i]) {
			confidence += 0.1
			if confidence >= 1.0 {
				confidence = 1.0
				break
			}
		}
	}

	// Check for common patterns
	for i := start; i < end; i++ {
		line := strings.ToLower(lines[i])
		if strings.Contains(line, "aws_access_key_id") ||
			strings.Contains(line, "aws_secret_access_key") ||
			strings.Contains(line, ".aws/credentials") {
			confidence = 1.0
			break
		}
	}

	return confidence
}

// deduplicateAndSort removes duplicates and sorts by confidence
func (e *ContextualKeyExtractor) deduplicateAndSort(candidates []KeyCandidate) []KeyCandidate {
	seen := make(map[string]bool)
	var unique []KeyCandidate

	// Sort by confidence (highest first)
	for _, c := range candidates {
		key := c.AccessKey + ":" + c.SecretKey
		if !seen[key] {
			seen[key] = true
			unique = append(unique, c)
		}
	}

	// Simple bubble sort by confidence
	for i := 0; i < len(unique); i++ {
		for j := i + 1; j < len(unique); j++ {
			if unique[j].Confidence > unique[i].Confidence {
				unique[i], unique[j] = unique[j], unique[i]
			}
		}
	}

	return unique
}

// Helper functions
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
