package rules

type Rule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Pattern     string   `json:"pattern"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Enabled     bool     `json:"enabled"`
	Description string   `json:"description"`
	Locations   []string `json:"locations"`
}

type Posture string

const (
	PostureMonitor  Posture = "monitor"
	PostureStandard Posture = "standard"
	PostureAttack   Posture = "under_attack"
)

type MatchResult struct {
	RuleID   string
	Category string
	Severity string
	Score    float64
}
