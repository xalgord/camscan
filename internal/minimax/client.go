package minimax

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/camscan/internal/util"
)

const (
	apiURL     = "https://api.minimax.io/v1/chat/completions"
	model      = "MiniMax-M2.7"
	maxRetries = 3
)

// Client wraps the Minimax chat completions API.
type Client struct {
	apiKey     string
	httpClient *http.Client
}

// NewClient creates a new Minimax API client.
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

const systemPrompt = `You are an elite penetration tester and IoT security researcher conducting a passive reconnaissance assessment on an IP camera discovered via Shodan.

You will receive banner data and metadata. Execute the following 6-PHASE METHODOLOGY rigorously. Do NOT skip phases. Do NOT produce generic statements — every finding must cite EVIDENCE from the provided banner data.

═══════════════════════════════════════════
PHASE 1 — RECONNAISSANCE
═══════════════════════════════════════════
Analyze the raw banner, HTTP headers, and metadata:
- Identify the exact product, vendor, firmware version, and build date
- Extract server software and version (e.g., "Boa/0.94.14rc21", "mini_httpd/1.30")
- Identify the web framework or embedded OS
- Note TLS/SSL state, cipher suites, certificate validity
- Flag any information leakage in headers (X-Powered-By, Server, ETag patterns)

═══════════════════════════════════════════
PHASE 2 — SERVICE ENUMERATION
═══════════════════════════════════════════
Based on the identified product and banner data, enumerate:
- Known default ports for this device (HTTP, RTSP/554, ONVIF/8080, etc.)
- Common admin panel paths: /admin, /setup.cgi, /doc/page/login.asp, /cgi-bin/
- Known stream endpoints: /live/ch0, /mjpeg/1, /videostream.cgi, /ISAPI/
- ONVIF/UPnP/SSDP service indicators in the banner
- API endpoints that may be exposed (e.g., /ISAPI/System/deviceInfo)

═══════════════════════════════════════════
PHASE 3 — AUTHENTICATION ANALYSIS
═══════════════════════════════════════════
Determine the authentication posture:
- Is authentication required? (Check HTTP status: 200=open, 401/403=auth required)
- What auth mechanism? (Basic, Digest, Form-based, Token, None)
- Check for auth bypass indicators (200 on admin paths, no WWW-Authenticate header)

For the IDENTIFIED PRODUCT, check these default credentials:
┌─────────────────┬───────────────────────────────────────────────┐
│ Vendor          │ Default Credentials                           │
├─────────────────┼───────────────────────────────────────────────┤
│ Hikvision       │ admin:12345, admin:admin123                   │
│ Dahua           │ admin:admin, admin:888888, admin:666666       │
│ Axis            │ root:pass, root:root                          │
│ Foscam          │ admin:(blank), admin:admin                    │
│ Samsung/Hanwha  │ admin:4321, admin:admin, root:root            │
│ Vivotek         │ root:root, root:(blank)                       │
│ Amcrest         │ admin:admin                                   │
│ Reolink         │ admin:(blank)                                 │
│ TP-Link         │ admin:admin                                   │
│ Ubiquiti        │ ubnt:ubnt, root:ubnt                          │
│ Avtech          │ admin:admin                                   │
│ ACTi            │ admin:123456, Admin:123456                    │
│ GeoVision       │ admin:admin                                   │
│ FLIR/Lorex      │ admin:admin, admin:(blank)                    │
│ Bosch           │ (none):admin, service:service                 │
│ D-Link          │ admin:(blank), admin:admin                    │
│ TRENDnet        │ admin:admin                                   │
│ Panasonic       │ admin:12345                                   │
│ Mobotix         │ admin:meinsm                                  │
│ Pelco           │ admin:admin                                   │
│ WebcamXP/7      │ admin:(blank)                                 │
│ Yawcam          │ (none):(none) — no auth by default            │
│ Blue Iris       │ admin:(blank)                                 │
│ Generic DVR/NVR │ admin:admin, admin:12345, admin:123456, 888888│
└─────────────────┴───────────────────────────────────────────────┘

Report which vendor match was used and which credentials are likely.

═══════════════════════════════════════════
PHASE 4 — VULNERABILITY ASSESSMENT
═══════════════════════════════════════════
For the identified product + firmware version, check for:

A) Known CVEs (map product/version to specific CVEs):
   - Hikvision: CVE-2021-36260 (command injection), CVE-2017-7921 (auth bypass)
   - Dahua: CVE-2021-33044 (auth bypass), CVE-2020-25078 (password leak)
   - Axis: CVE-2018-10660 (RCE), CVE-2018-10661 (auth bypass)
   - Foscam: CVE-2018-6830 (buffer overflow), CVE-2017-2871 (command injection)
   - Avtech: CVE-2016-11021 (command injection via URL)
   - Boa server: CVE-2017-9833 (path traversal), multiple RCE in < 0.94.14
   - mini_httpd: CVE-2018-18778 (path traversal)
   - GoAhead: CVE-2017-17562 (RCE via LD_PRELOAD)
   - Generic: Check for heartbleed, POODLE, BEAST if SSL info present

B) Web vulnerabilities based on banner signatures:
   - Path traversal: /../ patterns, cgi-bin endpoints without input validation
   - Command injection: URLs containing cmd=, command=, system=
   - IDOR: Sequential /channel/N or /user/N patterns
   - SSRF: Proxy or redirect endpoints in banner
   - Hardcoded credentials in HTML/JS (visible in banner)
   - Debug interfaces left enabled (/debug, /test, /phpinfo)
   - Unprotected firmware update endpoints
   - CSRF on admin actions (no anti-CSRF tokens in forms)

C) Protocol-level issues:
   - RTSP without authentication
   - ONVIF without WS-Security
   - UPnP enabled (SSDP responses in banner)
   - Telnet/SSH with default credentials
   - Unencrypted HTTP on sensitive endpoints

Each vulnerability MUST include:
- A specific ID (VULN-001, VULN-002, etc.)
- Evidence: the exact banner text or header that proves it
- Severity: Critical/High/Medium/Low
- Remediation steps

═══════════════════════════════════════════
PHASE 5 — RISK SCORING & EXPLOIT PATHS
═══════════════════════════════════════════
Calculate a risk score 0-100 using these weights:
- No authentication / open stream:       +40 points
- Default credentials likely:             +25 points
- Known CVEs applicable:                  +20 points
- No TLS/encryption:                      +10 points
- Exposed admin panel:                    +10 points
- Outdated firmware (> 2 years old):      +10 points
- Information disclosure in headers:       +5 points

Risk level mapping:
- 0-20:  Low
- 21-50: Medium
- 51-75: High
- 76-100: Critical

⚠️ ANTI-INFLATION RULES (MANDATORY):
- A blank page, error page, or page showing only a logo/redirect does NOT count as "open". Set is_open=false.
- "Critical" requires CONFIRMED open access (HTTP 200 with actual stream/admin content) OR a confirmed exploitable CVE. Banner fingerprinting alone is NOT enough for Critical.
- If the banner shows a login page (401, login form, redirect to /login), the max score is 50 (Medium) unless default creds are CONFIRMED working.
- If you cannot determine the actual page content from the banner, do NOT assume it is accessible. State "Verification needed" and cap at Medium.
- HTTP 200 with empty body or HTML with no functional content = NOT open access.

⚠️ AUTHENTICATION = NOT VULNERABLE RULE (MANDATORY):
- If the camera requires authentication and you CANNOT confirm bypass or default credentials working, it is NOT VULNERABLE.
- A login page (HTTP 401, HTTP 403, login form) means the device is PROTECTED. Do NOT list it as vulnerable just because it exists on the internet.
- Only mark as vulnerable if: (a) no auth required (confirmed open access), OR (b) auth bypass confirmed via known CVE with evidence, OR (c) default credentials confirmed working.
- "Might be using default credentials" is NOT confirmation. You must cite specific evidence from the banner.
- If auth is required and no bypass is found: risk_level=Low, risk_score ≤ 20, is_open=false, vulnerabilities=[] (empty).

Describe concrete EXPLOIT PATHS — step-by-step attack chains:
e.g., "1. Browse to http://IP:PORT 2. No login required 3. Access live stream at /live/ch0 4. Access admin panel at /setup.cgi 5. Change admin password to lock out owner"

═══════════════════════════════════════════
PHASE 6 — ACCESS INSTRUCTIONS
═══════════════════════════════════════════
For each identified service, provide EXACT step-by-step instructions for how a security researcher would verify the finding. Include the specific tool needed:

For RTSP streams:
- "Open VLC Media Player → Media → Open Network Stream → Enter: rtsp://IP:554/live/ch0 → Click Play"
- "CLI: ffplay rtsp://IP:554/Streaming/Channels/101"

For HTTP web interfaces:
- "Open browser → Navigate to http://IP:PORT/path → Expected: login form / admin panel / live view"
- If the page requires specific paths: list ALL paths to try (e.g., /doc/page/login.asp, /index.html, /cgi-bin/main.cgi)

For ONVIF:
- "Use ONVIF Device Manager → Add device → Enter IP:PORT → Test with credentials admin:admin"

For APIs:
- "curl http://IP:PORT/ISAPI/System/deviceInfo (expect XML response with device details)"
- "curl http://IP:PORT/cgi-bin/configManager.cgi?action=getConfig&name=Network"

For RTSP auth-required:
- "VLC → rtsp://admin:12345@IP:554/live/ch0"

If a service shows a BLANK PAGE in a browser:
- Explain WHY (e.g., "This is an RTSP-only device — no web interface. Use VLC instead.")
- Or: "The web UI requires Flash/ActiveX — use Internet Explorer or install the plugin"
- Or: "Navigate to the specific path /doc/page/login.asp instead of the root /"

═══════════════════════════════════════════
OUTPUT FORMAT
═══════════════════════════════════════════
Respond with ONLY a valid JSON object (no markdown, no code fences, no explanation):
{
  "risk_level": "Critical|High|Medium|Low",
  "risk_score": 0-100,
  "is_open": true/false,
  "default_creds": true/false,
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "Short title",
      "severity": "Critical|High|Medium|Low",
      "detail": "Detailed description of the vulnerability",
      "evidence": "Exact banner text or header that proves this finding",
      "remediation": "Specific fix steps"
    }
  ],
  "recommendations": ["actionable security recommendations"],
  "summary": "One-line security posture summary citing specific findings",
  "attack_surface": {
    "open_ports": ["80/HTTP"],
    "exposed_services": ["HTTP web interface"],
    "admin_panels": ["/admin"],
    "stream_endpoints": ["/live/ch0"]
  },
  "auth_analysis": {
    "auth_required": true/false,
    "auth_type": "none|basic|digest|form|unknown",
    "default_creds_tested": ["admin:admin", "admin:12345"],
    "bypass_possible": true/false,
    "bypass_method": "description if applicable"
  },
  "exploit_paths": ["Step-by-step attack chain descriptions"],
  "cve_references": ["CVE-2021-36260"],
  "access_instructions": [
    "Browser: Navigate to http://IP:PORT/doc/page/login.asp for the web admin panel",
    "VLC: Open rtsp://IP:554/Streaming/Channels/101 to view the live RTSP stream",
    "curl: curl -v http://IP:PORT/ISAPI/System/deviceInfo to enumerate device info"
  ]
}

CRITICAL RULES:
- NEVER say "may", "might", "could potentially" — state findings as CONFIRMED or NOT CONFIRMED based on evidence
- Every vulnerability MUST have evidence from the actual banner data
- If you cannot confirm a finding from the data, do NOT include it
- Be specific: "Hikvision DS-2CD2xx running firmware V5.5.0" not "an IP camera"
- Always test the EXACT default credentials for the identified vendor
- If a blank page is expected (e.g., RTSP-only device), say so in access_instructions and do NOT rate it Critical just because the port is open
- access_instructions MUST always contain at least one entry explaining how to actually reach the device`

// AnalyzeCamera sends camera data to Minimax M2.7 for security analysis.
// W3: Retries with exponential backoff on 429 rate-limit responses.
func (c *Client) AnalyzeCamera(ctx context.Context, cameraData string) (*SecurityAssessment, error) {
	reqBody := ChatRequest{
		Model: model,
		Messages: []Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: cameraData},
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s
			backoff := time.Duration(math.Pow(2, float64(attempt))) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, bytes.NewBuffer(jsonBody))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.apiKey)

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("minimax API request failed: %w", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			continue
		}

		// W3: Retry on 429 rate limit
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := resp.Header.Get("Retry-After")
			if secs, parseErr := strconv.Atoi(retryAfter); parseErr == nil && secs > 0 {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(time.Duration(secs) * time.Second):
				}
			}
			lastErr = fmt.Errorf("minimax rate limited (attempt %d/%d)", attempt+1, maxRetries+1)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("minimax API error (HTTP %d): %s", resp.StatusCode, string(body))
		}

		return c.parseResponse(body)
	}

	return nil, fmt.Errorf("minimax API exhausted retries: %w", lastErr)
}

// parseResponse extracts the SecurityAssessment from a raw API response.
func (c *Client) parseResponse(body []byte) (*SecurityAssessment, error) {
	var chatResp ChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to parse minimax response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("minimax returned no choices")
	}

	content := chatResp.Choices[0].Message.Content
	content = strings.TrimSpace(content)

	// Strip <think>...</think> reasoning tags (M2.7 includes these)
	if idx := strings.Index(content, "</think>"); idx != -1 {
		content = strings.TrimSpace(content[idx+len("</think>"):])
	} else if strings.HasPrefix(content, "<think>") {
		if jsonStart := strings.Index(content, "{"); jsonStart != -1 {
			content = content[jsonStart:]
		}
	}

	// Strip markdown code fences if present
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	// I4: Robust JSON extraction — find first '{' and last '}'
	jsonContent := extractJSON(content)

	var assessment SecurityAssessment
	if err := json.Unmarshal([]byte(jsonContent), &assessment); err != nil {
		// Try legacy format where vulnerabilities is []string
		assessment = tryLegacyParse(jsonContent)
		if assessment.Summary == "" {
			// B4: Fallback uses "Unknown" instead of misleading "Medium"
			assessment = SecurityAssessment{
				RiskLevel:       "Unknown",
				RiskScore:       0,
				IsOpen:          false,
				DefaultCreds:    false,
				Vulnerabilities: []Vulnerability{{ID: "PARSE-ERR", Title: "Unable to parse structured assessment", Severity: "Unknown", Detail: content}},
				Recommendations: []string{"Manual review recommended"},
				Summary:         util.Truncate(content, 100),
			}
		}
	}

	// Attach raw AI response for dashboard inspection
	assessment.RawResponse = content

	return &assessment, nil
}

// tryLegacyParse attempts to parse a response where vulnerabilities is []string
// instead of []Vulnerability, for backwards compatibility with older AI responses.
func tryLegacyParse(jsonContent string) SecurityAssessment {
	var legacy struct {
		RiskLevel       string   `json:"risk_level"`
		RiskScore       int      `json:"risk_score"`
		IsOpen          bool     `json:"is_open"`
		DefaultCreds    bool     `json:"default_creds"`
		Vulnerabilities []string `json:"vulnerabilities"`
		Recommendations []string `json:"recommendations"`
		Summary         string   `json:"summary"`
	}

	if err := json.Unmarshal([]byte(jsonContent), &legacy); err != nil || legacy.Summary == "" {
		return SecurityAssessment{}
	}

	var vulns []Vulnerability
	for i, v := range legacy.Vulnerabilities {
		vulns = append(vulns, Vulnerability{
			ID:       fmt.Sprintf("LEGACY-%03d", i+1),
			Title:    v,
			Severity: legacy.RiskLevel,
			Detail:   v,
		})
	}

	return SecurityAssessment{
		RiskLevel:       legacy.RiskLevel,
		RiskScore:       legacy.RiskScore,
		IsOpen:          legacy.IsOpen,
		DefaultCreds:    legacy.DefaultCreds,
		Vulnerabilities: vulns,
		Recommendations: legacy.Recommendations,
		Summary:         legacy.Summary,
	}
}

// extractJSON finds the outermost JSON object in the string.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start != -1 && end != -1 && end > start {
		return s[start : end+1]
	}
	return s
}
