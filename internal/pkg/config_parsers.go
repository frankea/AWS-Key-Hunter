// Package pkg provides intelligent configuration file parsing for AWS credentials
package pkg

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ConfigParser interface for different file format parsers
type ConfigParser interface {
	ExtractCredentials(content []byte) []KeyCandidate
}

// JSONParser handles JSON configuration files
type JSONParser struct {
	accessKeyRegex *regexp.Regexp
	secretKeyRegex *regexp.Regexp
}

// YAMLParser handles YAML configuration files  
type YAMLParser struct {
	accessKeyRegex *regexp.Regexp
	secretKeyRegex *regexp.Regexp
}

// INIParser handles INI/properties files
type INIParser struct {
	accessKeyRegex *regexp.Regexp
	secretKeyRegex *regexp.Regexp
}

// EnvParser handles .env files
type EnvParser struct {
	accessKeyRegex *regexp.Regexp
	secretKeyRegex *regexp.Regexp
}

// DockerfileParser handles Dockerfile ENV statements
type DockerfileParser struct {
	accessKeyRegex *regexp.Regexp
	secretKeyRegex *regexp.Regexp
}

// initConfigParsers initializes all configuration file parsers
func initConfigParsers() map[string]ConfigParser {
	return map[string]ConfigParser{
		".json":       NewJSONParser(),
		".yaml":       NewYAMLParser(),
		".yml":        NewYAMLParser(),
		".ini":        NewINIParser(),
		".properties": NewINIParser(),
		".env":        NewEnvParser(),
		".conf":       NewINIParser(),
		".config":     NewINIParser(),
		"Dockerfile":  NewDockerfileParser(),
	}
}

// NewJSONParser creates a new JSON parser
func NewJSONParser() *JSONParser {
	return &JSONParser{
		accessKeyRegex: regexp.MustCompile(`"(?:aws_access_key_id|accessKeyId|access_key|AccessKey)"\s*:\s*"(AKIA[0-9A-Z]{16})"`),
		secretKeyRegex: regexp.MustCompile(`"(?:aws_secret_access_key|secretAccessKey|secret_key|SecretKey)"\s*:\s*"([a-zA-Z0-9/+]{40})"`),
	}
}

// ExtractCredentials extracts AWS credentials from JSON content
func (p *JSONParser) ExtractCredentials(content []byte) []KeyCandidate {
	var candidates []KeyCandidate
	contentStr := string(content)
	
	// Try to parse as proper JSON first
	var jsonData interface{}
	if err := json.Unmarshal(content, &jsonData); err == nil {
		candidates = append(candidates, p.extractFromParsedJSON(jsonData)...)
	}
	
	// Fall back to regex parsing for malformed JSON
	candidates = append(candidates, p.extractWithRegex(contentStr)...)
	
	return deduplicateCandidates(candidates)
}

// extractFromParsedJSON recursively searches parsed JSON for AWS credentials
func (p *JSONParser) extractFromParsedJSON(data interface{}) []KeyCandidate {
	var candidates []KeyCandidate
	
	switch v := data.(type) {
	case map[string]interface{}:
		// Look for AWS credential patterns in JSON objects
		accessKey := p.findAccessKeyInMap(v)
		secretKey := p.findSecretKeyInMap(v)
		
		if accessKey != "" && secretKey != "" {
			candidates = append(candidates, KeyCandidate{
				AccessKey:  accessKey,
				SecretKey:  secretKey,
				Context:    "JSON object",
				Confidence: 0.9,
			})
		}
		
		// Recursively search nested objects
		for _, value := range v {
			candidates = append(candidates, p.extractFromParsedJSON(value)...)
		}
		
	case []interface{}:
		// Search arrays
		for _, item := range v {
			candidates = append(candidates, p.extractFromParsedJSON(item)...)
		}
	}
	
	return candidates
}

// findAccessKeyInMap looks for access key patterns in a JSON object
func (p *JSONParser) findAccessKeyInMap(m map[string]interface{}) string {
	accessKeyFields := []string{
		"aws_access_key_id", "accessKeyId", "access_key", "AccessKey",
		"AWS_ACCESS_KEY_ID", "awsAccessKeyId", "accessKey",
	}
	
	for _, field := range accessKeyFields {
		if value, exists := m[field]; exists {
			if strValue, ok := value.(string); ok && strings.HasPrefix(strValue, "AKIA") {
				return strValue
			}
		}
	}
	return ""
}

// findSecretKeyInMap looks for secret key patterns in a JSON object
func (p *JSONParser) findSecretKeyInMap(m map[string]interface{}) string {
	secretKeyFields := []string{
		"aws_secret_access_key", "secretAccessKey", "secret_key", "SecretKey",
		"AWS_SECRET_ACCESS_KEY", "awsSecretAccessKey", "secretKey",
	}
	
	for _, field := range secretKeyFields {
		if value, exists := m[field]; exists {
			if strValue, ok := value.(string); ok && len(strValue) == 40 {
				return strValue
			}
		}
	}
	return ""
}

// extractWithRegex uses regex to find credentials in JSON-like text
func (p *JSONParser) extractWithRegex(content string) []KeyCandidate {
	var candidates []KeyCandidate
	
	accessKeys := p.accessKeyRegex.FindAllStringSubmatch(content, -1)
	secretKeys := p.secretKeyRegex.FindAllStringSubmatch(content, -1)
	
	// Pair up access and secret keys found nearby
	for _, accessMatch := range accessKeys {
		accessKey := accessMatch[1]
		
		for _, secretMatch := range secretKeys {
			secretKey := secretMatch[1]
			
			candidates = append(candidates, KeyCandidate{
				AccessKey:  accessKey,
				SecretKey:  secretKey,
				Context:    "JSON regex match",
				Confidence: 0.8,
			})
		}
	}
	
	return candidates
}

// NewYAMLParser creates a new YAML parser
func NewYAMLParser() *YAMLParser {
	return &YAMLParser{
		accessKeyRegex: regexp.MustCompile(`(?m)^\s*(?:aws_access_key_id|accessKeyId|access_key|AccessKey)\s*:\s*(AKIA[0-9A-Z]{16})`),
		secretKeyRegex: regexp.MustCompile(`(?m)^\s*(?:aws_secret_access_key|secretAccessKey|secret_key|SecretKey)\s*:\s*([a-zA-Z0-9/+]{40})`),
	}
}

// ExtractCredentials extracts AWS credentials from YAML content
func (p *YAMLParser) ExtractCredentials(content []byte) []KeyCandidate {
	var candidates []KeyCandidate
	contentStr := string(content)
	
	accessKeys := p.accessKeyRegex.FindAllStringSubmatch(contentStr, -1)
	secretKeys := p.secretKeyRegex.FindAllStringSubmatch(contentStr, -1)
	
	// Match access and secret keys that appear close together
	for _, accessMatch := range accessKeys {
		accessKey := accessMatch[1]
		accessLine := strings.Count(contentStr[:strings.Index(contentStr, accessMatch[0])], "\n")
		
		for _, secretMatch := range secretKeys {
			secretKey := secretMatch[1]
			secretLine := strings.Count(contentStr[:strings.Index(contentStr, secretMatch[0])], "\n")
			
			// Keys should be within 10 lines of each other
			if abs(accessLine-secretLine) <= 10 {
				candidates = append(candidates, KeyCandidate{
					AccessKey:  accessKey,
					SecretKey:  secretKey,
					Context:    "YAML key pair",
					Confidence: 0.9,
					LineNumber: accessLine,
				})
			}
		}
	}
	
	return candidates
}

// NewINIParser creates a new INI/properties parser
func NewINIParser() *INIParser {
	return &INIParser{
		accessKeyRegex: regexp.MustCompile(`(?m)^\s*(?:aws_access_key_id|aws\.accessKeyId|access_key|AccessKey)\s*[=:]\s*(AKIA[0-9A-Z]{16})`),
		secretKeyRegex: regexp.MustCompile(`(?m)^\s*(?:aws_secret_access_key|aws\.secretKey|secret_key|SecretKey)\s*[=:]\s*([a-zA-Z0-9/+]{40})`),
	}
}

// ExtractCredentials extracts AWS credentials from INI/properties content
func (p *INIParser) ExtractCredentials(content []byte) []KeyCandidate {
	var candidates []KeyCandidate
	contentStr := string(content)
	
	accessKeys := p.accessKeyRegex.FindAllStringSubmatch(contentStr, -1)
	secretKeys := p.secretKeyRegex.FindAllStringSubmatch(contentStr, -1)
	
	// For INI files, try to match keys within the same section
	for _, accessMatch := range accessKeys {
		accessKey := accessMatch[1]
		
		for _, secretMatch := range secretKeys {
			secretKey := secretMatch[1]
			
			candidates = append(candidates, KeyCandidate{
				AccessKey:  accessKey,
				SecretKey:  secretKey,
				Context:    "INI configuration",
				Confidence: 0.95, // INI files are very likely to have real config
			})
		}
	}
	
	return candidates
}

// NewEnvParser creates a new .env file parser
func NewEnvParser() *EnvParser {
	return &EnvParser{
		accessKeyRegex: regexp.MustCompile(`(?m)^AWS_ACCESS_KEY_ID\s*=\s*(AKIA[0-9A-Z]{16})`),
		secretKeyRegex: regexp.MustCompile(`(?m)^AWS_SECRET_ACCESS_KEY\s*=\s*([a-zA-Z0-9/+]{40})`),
	}
}

// ExtractCredentials extracts AWS credentials from .env content
func (p *EnvParser) ExtractCredentials(content []byte) []KeyCandidate {
	var candidates []KeyCandidate
	contentStr := string(content)
	
	accessKeys := p.accessKeyRegex.FindAllStringSubmatch(contentStr, -1)
	secretKeys := p.secretKeyRegex.FindAllStringSubmatch(contentStr, -1)
	
	// .env files typically have paired keys
	for _, accessMatch := range accessKeys {
		accessKey := accessMatch[1]
		
		for _, secretMatch := range secretKeys {
			secretKey := secretMatch[1]
			
			candidates = append(candidates, KeyCandidate{
				AccessKey:  accessKey,
				SecretKey:  secretKey,
				Context:    "Environment file",
				Confidence: 1.0, // .env files are very high confidence
			})
		}
	}
	
	return candidates
}

// NewDockerfileParser creates a new Dockerfile parser
func NewDockerfileParser() *DockerfileParser {
	return &DockerfileParser{
		accessKeyRegex: regexp.MustCompile(`(?m)^ENV\s+AWS_ACCESS_KEY_ID\s*[=]?\s*(AKIA[0-9A-Z]{16})`),
		secretKeyRegex: regexp.MustCompile(`(?m)^ENV\s+AWS_SECRET_ACCESS_KEY\s*[=]?\s*([a-zA-Z0-9/+]{40})`),
	}
}

// ExtractCredentials extracts AWS credentials from Dockerfile content
func (p *DockerfileParser) ExtractCredentials(content []byte) []KeyCandidate {
	var candidates []KeyCandidate
	contentStr := string(content)
	
	accessKeys := p.accessKeyRegex.FindAllStringSubmatch(contentStr, -1)
	secretKeys := p.secretKeyRegex.FindAllStringSubmatch(contentStr, -1)
	
	for _, accessMatch := range accessKeys {
		accessKey := accessMatch[1]
		
		for _, secretMatch := range secretKeys {
			secretKey := secretMatch[1]
			
			candidates = append(candidates, KeyCandidate{
				AccessKey:  accessKey,
				SecretKey:  secretKey,
				Context:    "Dockerfile ENV",
				Confidence: 0.85,
			})
		}
	}
	
	return candidates
}

// deduplicateCandidates removes duplicate key candidates
func deduplicateCandidates(candidates []KeyCandidate) []KeyCandidate {
	seen := make(map[string]bool)
	var unique []KeyCandidate
	
	for _, candidate := range candidates {
		key := candidate.AccessKey + ":" + candidate.SecretKey
		if !seen[key] {
			seen[key] = true
			unique = append(unique, candidate)
		}
	}
	
	return unique
}