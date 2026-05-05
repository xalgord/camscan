package minimax

// ChatRequest is the request body for the Minimax chat completions API.
type ChatRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

// Message represents a single message in the chat conversation.
type Message struct {
	Role    string `json:"role"`    // "system", "user", "assistant"
	Content string `json:"content"`
}

// ChatResponse is the response from the Minimax chat completions API.
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Created int64    `json:"created"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// Choice represents a single completion choice.
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage tracks token consumption.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Vulnerability represents a single identified security issue with evidence.
type Vulnerability struct {
	ID          string `json:"id"`          // e.g. "VULN-001"
	Title       string `json:"title"`       // Short vulnerability title
	Severity    string `json:"severity"`    // Critical, High, Medium, Low
	Detail      string `json:"detail"`      // Full description
	Evidence    string `json:"evidence"`    // Banner text/header that proves this
	Remediation string `json:"remediation"` // How to fix
}

// AttackSurface describes the exposed entry points on the device.
type AttackSurface struct {
	OpenPorts       []string `json:"open_ports"`
	ExposedServices []string `json:"exposed_services"` // e.g. ["HTTP/80", "RTSP/554"]
	AdminPanels     []string `json:"admin_panels"`      // e.g. ["/admin", "/setup.cgi"]
	StreamEndpoints []string `json:"stream_endpoints"`  // e.g. ["/live/ch0", "/mjpeg"]
}

// AuthAnalysis details the authentication posture of the device.
type AuthAnalysis struct {
	AuthRequired       bool     `json:"auth_required"`
	AuthType           string   `json:"auth_type"`            // "none", "basic", "digest", "form", "unknown"
	DefaultCredsTested []string `json:"default_creds_tested"` // e.g. ["admin:admin", "admin:12345"]
	BypassPossible     bool     `json:"bypass_possible"`
	BypassMethod       string   `json:"bypass_method,omitempty"`
}

// SecurityAssessment is the structured output from AI analysis.
type SecurityAssessment struct {
	RiskLevel          string          `json:"risk_level"`          // Critical, High, Medium, Low
	RiskScore          int             `json:"risk_score"`          // 0-100 numeric score
	IsOpen             bool            `json:"is_open"`             // No authentication required
	DefaultCreds       bool            `json:"default_creds"`       // Likely using default credentials
	Vulnerabilities    []Vulnerability `json:"vulnerabilities"`     // Structured vulnerability findings
	Recommendations    []string        `json:"recommendations"`     // Security recommendations
	Summary            string          `json:"summary"`             // One-line summary
	AttackSurface      AttackSurface   `json:"attack_surface"`      // Exposed entry points
	AuthAnalysis       AuthAnalysis    `json:"auth_analysis"`       // Authentication posture
	ExploitPaths       []string        `json:"exploit_paths"`       // Concrete attack chains
	CveReferences      []string        `json:"cve_references"`      // Related CVE IDs
	AccessInstructions []string        `json:"access_instructions"` // How to actually access/verify (tool + URL + protocol)
}

// VulnTitles returns a flat string slice of vulnerability titles for backward compatibility.
func (a *SecurityAssessment) VulnTitles() []string {
	if len(a.Vulnerabilities) == 0 {
		return nil
	}
	titles := make([]string, len(a.Vulnerabilities))
	for i, v := range a.Vulnerabilities {
		sev := ""
		if v.Severity != "" {
			sev = "[" + v.Severity + "] "
		}
		titles[i] = sev + v.Title
	}
	return titles
}
