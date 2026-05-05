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

// SecurityAssessment is the structured output from AI analysis.
type SecurityAssessment struct {
	RiskLevel       string   `json:"risk_level"`       // Critical, High, Medium, Low
	IsOpen          bool     `json:"is_open"`           // No authentication required
	DefaultCreds    bool     `json:"default_creds"`     // Likely using default credentials
	Vulnerabilities []string `json:"vulnerabilities"`   // Identified potential vulnerabilities
	Recommendations []string `json:"recommendations"`   // Security recommendations
	Summary         string   `json:"summary"`           // One-line summary
}
