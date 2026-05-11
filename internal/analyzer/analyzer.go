package analyzer

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xalgord/camscan/internal/dashboard"
	"github.com/xalgord/camscan/internal/discord"
	"github.com/xalgord/camscan/internal/minimax"
	"github.com/xalgord/camscan/internal/risk"
	"github.com/xalgord/camscan/internal/shodan"
	"github.com/xalgord/camscan/internal/validator"

)

// Result pairs a discovered camera with its AI security assessment.
type Result struct {
	Camera             shodan.Camera
	Assessment         *minimax.SecurityAssessment
	Error              string // Non-empty if AI analysis failed for this camera
	ConfirmationType   string // One of: active_open, active_login, passive_open, passive_bypass, passive_exploit, none
	ConfirmationReason string // Human-readable explanation of the confirmation decision
}

// Analyzer orchestrates the Shodan → Minimax pipeline.
type Analyzer struct {
	shodanClient     *shodan.Client
	minimaxClient    *minimax.Client
	notifier         *discord.Notifier
	hub              *dashboard.Hub
	noAI             bool
	httpValidator    *validator.HTTPValidator
	testDefaultCreds bool
}

// Option configures optional analyzer behavior.
type Option func(*Analyzer)

func WithHTTPValidator(httpValidator *validator.HTTPValidator) Option {
	return func(a *Analyzer) {
		a.httpValidator = httpValidator
	}
}

func WithDefaultCredsTesting(enabled bool) Option {
	return func(a *Analyzer) {
		a.testDefaultCreds = enabled
	}
}

// New creates a new Analyzer instance.
func New(shodanClient *shodan.Client, minimaxClient *minimax.Client, notifier *discord.Notifier, hub *dashboard.Hub, noAI bool, opts ...Option) *Analyzer {
	a := &Analyzer{
		shodanClient:  shodanClient,
		minimaxClient: minimaxClient,
		notifier:      notifier,
		hub:           hub,
		noAI:          noAI,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Run executes the full discovery + analysis pipeline.
// B1: Discord alerts are now sent sequentially after analysis completes.
// W2: Checks Shodan query credits before scanning.
// I2: Accepts context.Context for cancellation/timeout.
func (a *Analyzer) Run(ctx context.Context, query *shodan.SearchQuery, limit int) ([]Result, int, error) {
	queryStr := query.BuildQuery()
	return a.runWithQuery(ctx, queryStr, limit)
}

// RunWithRawQuery executes the pipeline using a raw Shodan query string.
// Supports AI-powered error recovery: if Shodan returns an error, the AI
// analyzes the error and generates a corrected query (up to 2 retries).
func (a *Analyzer) RunWithRawQuery(ctx context.Context, rawQuery string, limit int) ([]Result, int, error) {
	return a.runWithQuery(ctx, rawQuery, limit)
}

func (a *Analyzer) runWithQuery(ctx context.Context, queryStr string, limit int) ([]Result, int, error) {
	scanStart := time.Now()

	log.Println("═══════════════════════════════════════════════════════════════")
	log.Println("  PHASE 1: PRE-FLIGHT CHECKS")
	log.Println("═══════════════════════════════════════════════════════════════")

	// W2: Pre-flight check — verify Shodan has enough query credits
	var shodanPlan string
	apiInfo, err := a.shodanClient.GetAPIInfo(ctx)
	if err != nil {
		log.Printf("  ⚠ Could not verify Shodan credits: %v", err)
		shodanPlan = "unknown"
	} else if apiInfo.QueryCredits <= 0 {
		return nil, 0, fmt.Errorf("shodan has 0 query credits remaining (plan: %s)", apiInfo.Plan)
	} else {
		shodanPlan = apiInfo.Plan
		log.Printf("  ├─ Shodan Plan:    %s", apiInfo.Plan)
		log.Printf("  ├─ Query Credits:  %d remaining", apiInfo.QueryCredits)
		log.Printf("  └─ Scan Credits:   %d remaining", apiInfo.ScanCredits)
	}

	// Pre-sanitize: strip corporate-only filters before sending to Shodan
	originalQuery := queryStr
	queryStr = sanitizeQuery(queryStr)
	if queryStr != originalQuery {
		log.Printf("  ⚠  Removed restricted filters from query")
		log.Printf("     Original: %s", originalQuery)
		log.Printf("     Sanitized: %s", queryStr)
		a.emitEvent(dashboard.EventLog, fmt.Sprintf("Auto-sanitized query: removed restricted filters. New query: %s", queryStr))

		// If sanitization left the query empty or too generic, use AI to rebuild it
		if strings.TrimSpace(queryStr) == "" && !a.noAI && a.minimaxClient != nil {
			log.Printf("  🤖 Query was empty after sanitization — asking AI to generate a new one...")
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("Query empty after sanitization, asking AI to regenerate from: %s", originalQuery))
			generated, genErr := a.minimaxClient.GenerateQuery(ctx, originalQuery, shodanPlan)
			if genErr != nil {
				return nil, 0, fmt.Errorf("AI query regeneration failed: %w", genErr)
			}
			queryStr = generated
			log.Printf("  ✓ AI generated replacement query: %s", queryStr)
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI regenerated query: %s", queryStr))
		}
	}

	log.Println("═══════════════════════════════════════════════════════════════")
	log.Println("  PHASE 2: SHODAN RECONNAISSANCE")
	log.Println("═══════════════════════════════════════════════════════════════")
	log.Printf("  ├─ Query:    %s", queryStr)
	log.Printf("  ├─ Limit:    %d results", limit)
	log.Printf("  └─ Sending request to api.shodan.io...")

	// Dashboard: emit scan start
	a.emitEvent(dashboard.EventScanStart, fmt.Sprintf("Scan started — query: %s, limit: %d", queryStr, limit))
	a.markScanStarted(queryStr)
	defer a.markScanFinished()

	// Step 1: Discover cameras via Shodan (with AI error-recovery loop)
	// The AI keeps retrying until it finds a working query (safety cap at 10).
	const maxQueryRetries = 10
	var searchResult *shodan.SearchResult
	var shodanDur time.Duration
	currentQuery := queryStr

	for attempt := 0; ; attempt++ {
		shodanStart := time.Now()
		result, searchErr := a.shodanClient.SearchRaw(ctx, currentQuery, limit)
		shodanDur = time.Since(shodanStart).Round(time.Millisecond)

		if searchErr == nil {
			searchResult = result
			if attempt > 0 {
				log.Printf("  ✓ AI-corrected query succeeded (attempt %d) in %s", attempt+1, shodanDur)
				a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI-corrected query succeeded on attempt %d: %s", attempt+1, currentQuery))
			}
			break
		}

		// Safety cap — give up after maxQueryRetries to avoid infinite loops
		if attempt >= maxQueryRetries {
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("Shodan search failed after %d AI fix attempts: %v", attempt, searchErr))
			return nil, 0, fmt.Errorf("shodan search failed after %d AI fix attempts: %w", attempt, searchErr)
		}
		if a.noAI || a.minimaxClient == nil {
			reason := "--no-ai flag"
			if a.minimaxClient == nil {
				reason = "no Minimax API key configured"
			}
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("Shodan search failed: %v (AI recovery unavailable: %s)", searchErr, reason))
			return nil, 0, fmt.Errorf("shodan search failed: %w (AI recovery unavailable: %s)", searchErr, reason)
		}

		// AI error recovery: feed the error to the AI to fix the query
		log.Printf("  ⚠  Shodan query failed: %v", searchErr)
		log.Printf("  🤖 Asking AI to fix the query (attempt %d/%d)...", attempt+1, maxQueryRetries)
		a.emitEvent(dashboard.EventLog, fmt.Sprintf("Shodan error: %v — AI fixing query (attempt %d/%d)", searchErr, attempt+1, maxQueryRetries))

		fixedQuery, fixErr := a.minimaxClient.FixQuery(ctx, currentQuery, searchErr.Error(), shodanPlan)
		if fixErr != nil {
			log.Printf("  ⚠  AI query fix failed: %v", fixErr)
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI query fix failed: %v", fixErr))
			return nil, 0, fmt.Errorf("shodan search failed: %w (AI fix also failed: %v)", searchErr, fixErr)
		}

		log.Printf("  ✓ AI generated corrected query: %s", fixedQuery)
		a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI corrected query: %s", fixedQuery))
		currentQuery = fixedQuery
	}

	total := searchResult.Total
	cameras := searchResult.Matches

	if len(cameras) == 0 {
		log.Println("  ⚠  No cameras found matching your query.")
		a.emitEvent(dashboard.EventScanComplete, "No cameras found matching query.")
		return nil, total, nil
	}

	log.Printf("  ✓ Found %d cameras (total in Shodan: %d) in %s", len(cameras), total, shodanDur)
	a.emitEvent(dashboard.EventCameraFound, fmt.Sprintf("Discovered %d cameras (total in Shodan: %d)", len(cameras), total))

	// Print discovered cameras summary
	for i, cam := range cameras {
		product := cam.Product
		if product == "" {
			product = "Unknown"
		}
		loc := cam.Location.City
		if loc != "" && cam.Location.Country != "" {
			loc += ", " + cam.Location.Country
		} else if cam.Location.Country != "" {
			loc = cam.Location.Country
		}
		prefix := "├"
		if i == len(cameras)-1 {
			prefix = "└"
		}
		log.Printf("  %s─ [%d] %s:%d  %s  (%s)", prefix, i+1, cam.IP, cam.Port, product, loc)
	}

	// Step 2: If AI analysis is disabled, return raw results
	if a.noAI {
		log.Println("  ℹ  AI analysis skipped (--no-ai flag)")
		results := make([]Result, len(cameras))
		for i, cam := range cameras {
			results[i] = Result{Camera: cam}
		}
		return results, total, nil
	}

	// Step 3: Analyze each camera with Minimax M2.7
	log.Println("═══════════════════════════════════════════════════════════════")
	log.Printf("  PHASE 3: AI SECURITY ANALYSIS (%d cameras)", len(cameras))
	log.Println("═══════════════════════════════════════════════════════════════")
	log.Printf("  Engine: Minimax M2.7 | Concurrency: 3 | Methodology: 6-phase pentest")

	results := make([]Result, len(cameras))
	var alertedCount int32 // atomic counter for real-time alerts
	var wg sync.WaitGroup
	sem := make(chan struct{}, 3) // Concurrency limit to avoid rate limiting

	for i, cam := range cameras {
		wg.Add(1)
		go func(idx int, camera shodan.Camera) {
			defer wg.Done()

			// Respect context cancellation
			select {
			case <-ctx.Done():
				results[idx] = Result{Camera: camera, Error: "cancelled"}
				return
			case sem <- struct{}{}: // Acquire
			}
			defer func() { <-sem }() // Release

			aiStart := time.Now()
			prompt := buildCameraPrompt(camera)
			assessment, analyzeErr := a.minimaxClient.AnalyzeCamera(ctx, prompt)
			aiDur := time.Since(aiStart).Round(time.Millisecond)

			product := camera.Product
			if product == "" {
				product = "Unknown"
			}

			if analyzeErr != nil {
				results[idx] = Result{
					Camera: camera,
					Error:  analyzeErr.Error(),
				}
				log.Printf("  [%d/%d] %s:%d (%s)", idx+1, len(cameras), camera.IP, camera.Port, product)
				log.Printf("         ❌ AI analysis failed (%s): %s", aiDur, analyzeErr.Error())
				a.emitEvent(dashboard.EventAnalysis, fmt.Sprintf("[%d/%d] %s:%d — ❌ AI analysis failed: %s", idx+1, len(cameras), camera.IP, camera.Port, analyzeErr.Error()))
				a.incrementErrorStats()
			} else {
				if validation, ok := a.validateHTTP(ctx, camera, assessment); ok {
					a.emitValidation(camera, validation)
				}
				decision := enforceReportableAssessment(camera, assessment)
				results[idx] = Result{
					Camera:             camera,
					Assessment:         assessment,
					ConfirmationType:   confirmationType(decision, assessment),
					ConfirmationReason: decision.Reason,
				}
				icon := risk.Icon(assessment.RiskLevel)
				vulnCount := len(assessment.Vulnerabilities)
				cveCount := len(assessment.CveReferences)

				// Main status line
				log.Printf("  [%d/%d] %s:%d (%s)", idx+1, len(cameras), camera.IP, camera.Port, product)

				if !decision.Reportable {
					log.Printf("         ⚪ Not vulnerable  Score: %d/100  Open: %v  DefCreds: %v  Exploitable: %v",
						assessment.RiskScore, assessment.IsOpen, assessment.DefaultCreds, assessment.Exploitable)
					log.Printf("         Reason: %s", decision.Reason)
					log.Printf("         ⏱ %s", aiDur)
					a.emitEvent(dashboard.EventAnalysis, fmt.Sprintf("[%d/%d] %s:%d — Not vulnerable: %s",
						idx+1, len(cameras), camera.IP, camera.Port, decision.Reason))
					return
				}

				log.Printf("         %s %s  Score: %d/100  Open: %v  DefCreds: %v",
					icon, assessment.RiskLevel, assessment.RiskScore, assessment.IsOpen, assessment.DefaultCreds)

				// Vulnerability summary
				if vulnCount > 0 || cveCount > 0 {
					cvePart := ""
					if cveCount > 0 {
						cvePart = "  CVEs: " + strings.Join(assessment.CveReferences, ", ")
					}
					log.Printf("         Vulns: %d found%s", vulnCount, cvePart)
				}

				// Exploit paths
				if len(assessment.ExploitPaths) > 0 {
					for _, ep := range assessment.ExploitPaths {
						log.Printf("         ⚔ %s", ep)
					}
				}

				log.Printf("         ⏱ %s", aiDur)

				a.emitEvent(dashboard.EventAnalysis, fmt.Sprintf("[%d/%d] %s:%d — %s %s (%d/100) vulns=%d cves=%d",
					idx+1, len(cameras), camera.IP, camera.Port, icon, assessment.RiskLevel, assessment.RiskScore, vulnCount, cveCount))

				// Emit full structured analysis for the interactive dashboard
				a.emitDetailEvent(idx+1, len(cameras), camera, assessment)
				a.incrementFindingStats(assessment)

				// REAL-TIME Discord alert — send immediately after each camera analysis
				if a.notifier != nil {
					if sent := a.sendSingleAlert(camera, assessment); sent {
						atomic.AddInt32(&alertedCount, 1)
						a.incrementAlertStats()
					}
				}
			}
		}(i, cam)
	}

	wg.Wait()
	log.Println()

	reportedResults := reportableResults(results)

	// Send scan summary after all analysis is done
	alerted := int(atomic.LoadInt32(&alertedCount))
	if a.notifier != nil {
		log.Println("═══════════════════════════════════════════════════════════════")
		log.Println("  PHASE 4: DISCORD SUMMARY")
		log.Println("═══════════════════════════════════════════════════════════════")
		a.sendScanSummary(results, reportedResults, queryStr, total, alerted, scanStart)
		log.Printf("  ✓ Sent %d real-time alerts + scan summary", alerted)
		a.emitEvent(dashboard.EventAlertSent, fmt.Sprintf("Dispatched %d real-time Discord alerts", alerted))
	}

	scanDuration := time.Since(scanStart).Round(time.Second)

	log.Println("═══════════════════════════════════════════════════════════════")
	log.Println("  SCAN COMPLETE")
	log.Println("═══════════════════════════════════════════════════════════════")

	// Count by risk level for summary
	var critN, highN, medN, lowN, errN int
	for _, r := range results {
		if r.Error != "" {
			errN++
		}
	}
	for _, r := range reportedResults {
		if r.Assessment != nil {
			switch strings.ToLower(r.Assessment.RiskLevel) {
			case "critical":
				critN++
			case "high":
				highN++
			case "medium":
				medN++
			case "low":
				lowN++
			}
		}
	}

	log.Printf("  ├─ Duration:    %s", scanDuration)
	log.Printf("  ├─ Analyzed:    %d cameras", len(results))
	log.Printf("  ├─ Reported:    %d accessible/exploitable cameras", len(reportedResults))
	if critN > 0 {
		log.Printf("  ├─ Critical:    %d", critN)
	}
	if highN > 0 {
		log.Printf("  ├─ High:        %d", highN)
	}
	if medN > 0 {
		log.Printf("  ├─ Medium:      %d", medN)
	}
	if lowN > 0 {
		log.Printf("  ├─ Low:         %d", lowN)
	}
	if errN > 0 {
		log.Printf("  ├─ Errors:      %d", errN)
	}
	log.Printf("  └─ Dashboard:   http://localhost:9847")

	a.markScanFinished()
	a.emitEvent(dashboard.EventScanComplete, fmt.Sprintf("Scan finished — %d cameras analyzed, %d reported in %s (crit=%d high=%d med=%d low=%d err=%d)",
		len(results), len(reportedResults), scanDuration, critN, highN, medN, lowN, errN))

	return reportedResults, total, nil
}

// sendSingleAlert sends a real-time Discord alert for a single camera result.
// Called inline during analysis to provide immediate notifications.
// I3: Triggers on "Critical", "High", open access, or default credentials.
// Returns true if an alert was successfully sent.
func (a *Analyzer) sendSingleAlert(camera shodan.Camera, assessment *minimax.SecurityAssessment) bool {
	if assessment == nil {
		return false
	}
	if !isReportableAssessment(camera, assessment) {
		return false
	}

	level := strings.ToLower(assessment.RiskLevel)
	shouldAlert := assessment.IsOpen ||
		assessment.DefaultCreds ||
		assessment.Exploitable ||
		assessment.AuthAnalysis.BypassPossible ||
		level == "critical" ||
		level == "high"

	if !shouldAlert {
		return false
	}

	location := camera.Location.City
	if location != "" && camera.Location.Country != "" {
		location += ", " + camera.Location.Country
	} else if camera.Location.Country != "" {
		location = camera.Location.Country
	}

	confType := confirmationType(enforceReportableAssessment(camera, assessment), assessment)
	confReason := ""
	if assessment.ActiveValidation != nil {
		if assessment.ActiveValidation.LoginSucceeded && assessment.ActiveValidation.OpenContent {
			confReason = "Rod rendered camera content after supplied-credential login"
		} else if assessment.ActiveValidation.OpenContent {
			confReason = "Rod rendered camera content without authentication"
		}
	}
	if confReason == "" {
		confReason = assessReportability(camera, assessment).Reason
	}

	alert := discord.CameraAlert{
		IP:                 camera.IP,
		Port:               camera.Port,
		Product:            camera.Product,
		Location:           location,
		Org:                camera.Org,
		RiskLevel:          assessment.RiskLevel,
		RiskScore:          assessment.RiskScore,
		IsOpen:             assessment.IsOpen,
		DefaultCreds:       assessment.DefaultCreds,
		Summary:            assessment.Summary,
		Vulnerabilities:    assessment.VulnTitles(),
		ExploitPaths:       assessment.ExploitPaths,
		CveReferences:      assessment.CveReferences,
		AccessInstructions: assessment.AccessInstructions,
		ConfirmationType:   confType,
		ConfirmationReason: confReason,
	}

	if err := a.notifier.SendAlert(alert); err != nil {
		log.Printf("  ├─ ⚠ Alert FAILED for %s:%d: %v", camera.IP, camera.Port, err)
		return false
	}

	log.Printf("  📨 %s:%d → %s %s (Score: %d) — sent to Discord",
		camera.IP, camera.Port, risk.Icon(assessment.RiskLevel), assessment.RiskLevel, assessment.RiskScore)
	return true
}

// sendScanSummary counts risk levels from results and sends a completion
// notification to Discord.
func (a *Analyzer) sendScanSummary(results, reportedResults []Result, query string, totalShodan, alerted int, scanStart time.Time) {
	var crit, high, med, low, unknown, errors int
	for _, r := range results {
		if r.Error != "" {
			errors++
		}
	}
	for _, r := range reportedResults {
		if r.Assessment == nil {
			continue
		}
		switch strings.ToLower(r.Assessment.RiskLevel) {
		case "critical":
			crit++
		case "high":
			high++
		case "medium":
			med++
		case "low":
			low++
		default:
			unknown++
		}
	}

	summary := discord.ScanSummary{
		Query:       query,
		TotalShodan: totalShodan,
		Scanned:     len(results),
		Findings:    len(reportedResults),
		Alerted:     alerted,
		Critical:    crit,
		High:        high,
		Medium:      med,
		Low:         low,
		Unknown:     unknown,
		Errors:      errors,
		Duration:    time.Since(scanStart),
	}

	if err := a.notifier.SendScanSummary(summary); err != nil {
		log.Printf("  └─ ⚠ Scan summary FAILED: %v", err)
	} else {
		log.Println("  └─ 📋 Scan summary sent")
	}
}

// buildCameraPrompt creates a detailed prompt from camera banner data for AI analysis.
func buildCameraPrompt(cam shodan.Camera) string {
	var sb strings.Builder

	sb.WriteString("=== IP CAMERA BANNER DATA ===\n")
	sb.WriteString(fmt.Sprintf("IP: %s\n", cam.IP))
	sb.WriteString(fmt.Sprintf("Port: %d/%s\n", cam.Port, cam.Transport))
	sb.WriteString(fmt.Sprintf("Product: %s\n", cam.Product))
	sb.WriteString(fmt.Sprintf("Organization: %s\n", cam.Org))
	sb.WriteString(fmt.Sprintf("Location: %s, %s (%s)\n", cam.Location.City, cam.Location.Country, cam.Location.CountryCode))

	if cam.OS != "" {
		sb.WriteString(fmt.Sprintf("OS: %s\n", cam.OS))
	}

	if len(cam.Hostnames) > 0 {
		sb.WriteString(fmt.Sprintf("Hostnames: %s\n", strings.Join(cam.Hostnames, ", ")))
	}

	if cam.HTTP != nil {
		sb.WriteString(fmt.Sprintf("HTTP Title: %s\n", cam.HTTP.Title))
		sb.WriteString(fmt.Sprintf("HTTP Server: %s\n", cam.HTTP.Server))
		sb.WriteString(fmt.Sprintf("HTTP Status: %d\n", cam.HTTP.Status))
	}

	if cam.Title != "" {
		sb.WriteString(fmt.Sprintf("Title: %s\n", cam.Title))
	}

	if cam.SSL != nil {
		sb.WriteString(fmt.Sprintf("SSL Version: %s\n", cam.SSL.Version))
		sb.WriteString("TLS: Enabled\n")
	} else {
		sb.WriteString("TLS: Not detected\n")
	}

	sb.WriteString(fmt.Sprintf("Timestamp: %s\n", cam.Timestamp))

	// Include raw banner (truncated for token efficiency)
	banner := cam.Banner
	if len([]rune(banner)) > 1500 {
		banner = string([]rune(banner)[:1500]) + "\n... [truncated]"
	}
	sb.WriteString(fmt.Sprintf("\n=== RAW BANNER ===\n%s\n", banner))

	return sb.String()
}

func (a *Analyzer) validateHTTP(ctx context.Context, camera shodan.Camera, assessment *minimax.SecurityAssessment) (*validator.HTTPValidation, bool) {
	if a.httpValidator == nil || assessment == nil || !validator.SupportsHTTP(camera) {
		return nil, false
	}

	validation := a.httpValidator.Validate(ctx, camera)
	applyHTTPValidation(assessment, validation)

	// Build a composite banner for vendor matching (used by both endpoint probing and default creds)
	banner := strings.ToLower(camera.Product + " " + camera.Banner + " " + camera.Title)
	if camera.HTTP != nil {
		banner += " " + strings.ToLower(camera.HTTP.Title+" "+camera.HTTP.Server)
	}
	if validation.Title != "" {
		banner += " " + strings.ToLower(validation.Title)
	}

	// Probe known vendor-specific endpoints (CGI streams, snapshots, config)
	// These often bypass the login page entirely.
	if !validation.OpenContent || validation.LoginDetected || validation.AuthRequired {
		probeResults := validator.ProbeVendorEndpoints(ctx, camera, banner, a.httpValidator.Timeout())
		if len(probeResults) > 0 {
			var accessibleStreams []validator.EndpointProbeResult
			var accessibleConfigs []validator.EndpointProbeResult

			for _, pr := range probeResults {
				if pr.Accessible && pr.IsStream {
					accessibleStreams = append(accessibleStreams, pr)
				} else if pr.Accessible && pr.IsConfig {
					accessibleConfigs = append(accessibleConfigs, pr)
				}
			}

			if len(accessibleStreams) > 0 {
				log.Printf("         📹 Found %d accessible stream endpoint(s)!", len(accessibleStreams))
				for _, s := range accessibleStreams {
					log.Printf("         📹   %s — %s (%s, %d bytes)", s.Path, s.Description, s.ContentType, s.ContentLength)
					validation.Evidence = append(validation.Evidence,
						fmt.Sprintf("Unauthenticated %s endpoint: %s (HTTP %d, %s)", s.StreamType, s.Path, s.StatusCode, s.ContentType))
				}
				// Override — the camera has open stream access
				validation.OpenContent = true
				validation.Reachable = true
				validation.Evidence = append(validation.Evidence,
					fmt.Sprintf("%d vendor-specific stream endpoint(s) accessible without authentication", len(accessibleStreams)))
				applyHTTPValidation(assessment, validation)
				assessment.IsOpen = true
				assessment.Exploitable = true
				assessment.ExploitEvidence = fmt.Sprintf("Unauthenticated stream access confirmed on %d vendor endpoint(s)", len(accessibleStreams))
				assessment.AuthAnalysis.AuthRequired = false
				assessment.AuthAnalysis.AuthType = "none"
				if assessment.RiskScore < 80 {
					assessment.RiskScore = 80
					assessment.RiskLevel = "Critical"
				}
				assessment.Summary = fmt.Sprintf("Camera exposes %d unauthenticated stream endpoint(s) despite login page on web UI", len(accessibleStreams))
				appendUniqueString(&assessment.AccessInstructions,
					fmt.Sprintf("Browser: Open http://%s:%d%s for live stream",
						camera.IP, camera.Port, accessibleStreams[0].Path))
				return &validation, true
			}

			if len(accessibleConfigs) > 0 {
				log.Printf("         ⚙️  Found %d accessible config endpoint(s)", len(accessibleConfigs))
				for _, c := range accessibleConfigs {
					log.Printf("         ⚙️    %s — %s", c.Path, c.Description)
					validation.Evidence = append(validation.Evidence,
						fmt.Sprintf("Unauthenticated config endpoint: %s (HTTP %d, %s)", c.Path, c.StatusCode, c.ContentType))
				}
				applyHTTPValidation(assessment, validation)
				// Config exposure alone doesn't make it "open content" for camera,
				// but it's still a significant info disclosure finding.
				assessment.Vulnerabilities = append(assessment.Vulnerabilities, minimax.Vulnerability{
					ID:          "ENDPOINT-INFO-DISCLOSURE",
					Title:       "Unauthenticated Configuration Endpoint Access",
					Severity:    "Medium",
					Detail:      fmt.Sprintf("%d config endpoint(s) accessible without authentication", len(accessibleConfigs)),
					Evidence:    accessibleConfigs[0].Path + " returns " + accessibleConfigs[0].ContentType,
					Remediation: "Restrict access to configuration endpoints via authentication or network ACLs",
				})
			}
		}
	}

	// If a login page was detected and default-creds testing is enabled,
	// try known vendor default credentials automatically.
	if a.testDefaultCreds && (validation.LoginDetected || validation.AuthRequired) && !validation.LoginSucceeded {
		defaultCreds, vendor := validator.DefaultCredsForBanner(banner)
		if len(defaultCreds) > 0 {
			log.Printf("         🔑 Login detected on %s vendor — trying %d default credential(s)", vendor, len(defaultCreds))
			for i, cred := range defaultCreds {
				log.Printf("         🔑 [%d/%d] Trying %s:***", i+1, len(defaultCreds), cred.Username)
				credValidator := validator.NewHTTPValidator(a.httpValidator.Timeout(), validator.WithCredentials(cred))
				credValidation := credValidator.Validate(ctx, camera)
				credValidator.Close()

				if credValidation.LoginSucceeded && credValidation.OpenContent {
					log.Printf("         ✅ Default credential worked: %s:*** on %s vendor", cred.Username, vendor)
					credValidation.Evidence = append(credValidation.Evidence,
						fmt.Sprintf("Vendor default credential for %s confirmed camera access", vendor))
					applyHTTPValidation(assessment, credValidation)
					// Mark as default creds confirmed
					assessment.DefaultCreds = true
					return &credValidation, true
				}
				log.Printf("         ❌ Credential %s:*** failed", cred.Username)
			}
			log.Printf("         🔑 No default credentials worked for %s vendor", vendor)
		}
	}

	return &validation, true
}

func applyHTTPValidation(assessment *minimax.SecurityAssessment, validation validator.HTTPValidation) {
	assessment.ActiveValidation = &minimax.ActiveValidation{
		Method:         validation.Method,
		TargetURL:      validation.TargetURL,
		FinalURL:       validation.FinalURL,
		Attempted:      validation.Attempted,
		Reachable:      validation.Reachable,
		AuthRequired:   validation.AuthRequired,
		LoginDetected:  validation.LoginDetected,
		LoginAttempted: validation.LoginAttempted,
		LoginSucceeded: validation.LoginSucceeded,
		LoginUsername:  validation.LoginUsername,
		BlankPage:      validation.BlankPage,
		OpenContent:    validation.OpenContent,
		Title:          validation.Title,
		TextSample:     validation.TextSample,
		Evidence:       validation.Evidence,
		LoginError:     validation.LoginError,
		Error:          validation.Error,
	}

	if validation.LoginSucceeded && validation.OpenContent {
		assessment.IsOpen = false
		assessment.DefaultCreds = false
		assessment.Exploitable = true
		assessment.ExploitEvidence = validationEvidence(validation)
		assessment.AuthAnalysis.AuthRequired = true
		if assessment.AuthAnalysis.AuthType == "" || assessment.AuthAnalysis.AuthType == "none" || assessment.AuthAnalysis.AuthType == "unknown" {
			assessment.AuthAnalysis.AuthType = "form"
		}
		if assessment.RiskScore < 70 {
			assessment.RiskScore = 70
			assessment.RiskLevel = "High"
		}
		assessment.Summary = fmt.Sprintf("Active Rod validation confirmed camera access at %s after logging in with the supplied credential.", validation.TargetURL)
		appendActiveLoginVulnerability(assessment, validation)
		if validation.LoginUsername != "" {
			appendUniqueString(&assessment.AccessInstructions, fmt.Sprintf("Browser: Login at %s using the supplied credential for username %q; Rod rendered camera content after authentication", validation.TargetURL, validation.LoginUsername))
		} else {
			appendUniqueString(&assessment.AccessInstructions, fmt.Sprintf("Browser: Login at %s using the supplied credential; Rod rendered camera content after authentication", validation.TargetURL))
		}
		return
	}

	if validation.OpenContent {
		assessment.IsOpen = true
		assessment.DefaultCreds = false
		assessment.Exploitable = true
		assessment.ExploitEvidence = validationEvidence(validation)
		assessment.AuthAnalysis.AuthRequired = false
		assessment.AuthAnalysis.AuthType = "none"
		if assessment.RiskScore < 60 {
			assessment.RiskScore = 60
			assessment.RiskLevel = "High"
		}
		if assessment.Summary == "" || strings.HasPrefix(strings.ToLower(assessment.Summary), "not vulnerable") {
			assessment.Summary = fmt.Sprintf("Active Rod validation confirmed unauthenticated camera content at %s.", validation.TargetURL)
		}
		appendActiveOpenVulnerability(assessment, validation)
		appendUniqueString(&assessment.AccessInstructions, fmt.Sprintf("Browser: Open %s to verify unauthenticated camera content rendered by active Rod validation", validation.TargetURL))
		return
	}

	if isBrowserSetupError(validation) {
		// Rod failed to start — suppress ALL passive AI claims for HTTP targets.
		// Falling back to AI-only would re-introduce the false positives we're eliminating.
		assessment.IsOpen = false
		assessment.DefaultCreds = false
		assessment.Exploitable = false
		assessment.ExploitEvidence = ""
		assessment.Summary = "Not assessed: Rod/Chromium browser unavailable for active validation; passive AI claims suppressed."
		appendUniqueString(&assessment.Recommendations, "Install Chromium or configure Rod to enable active HTTP validation.")
		return
	}

	assessment.IsOpen = false
	assessment.DefaultCreds = false
	assessment.Exploitable = false
	assessment.ExploitEvidence = ""

	if validation.AuthRequired || validation.LoginDetected {
		assessment.AuthAnalysis.AuthRequired = true
		if assessment.AuthAnalysis.AuthType == "" || assessment.AuthAnalysis.AuthType == "none" || assessment.AuthAnalysis.AuthType == "unknown" {
			assessment.AuthAnalysis.AuthType = "form"
		}
		assessment.Summary = "Not vulnerable: active Rod validation found an authentication/login wall."
		return
	}

	if validation.BlankPage {
		assessment.Summary = "Not vulnerable: active Rod validation rendered a blank or minimal page, not accessible camera content."
		return
	}

	if validation.Error != "" {
		assessment.Summary = "Not vulnerable: active Rod validation could not reach/render accessible camera content: " + validation.Error
		return
	}

	assessment.Summary = "Not vulnerable: active Rod validation did not confirm accessible camera content."
}

func appendActiveOpenVulnerability(assessment *minimax.SecurityAssessment, validation validator.HTTPValidation) {
	for _, vuln := range assessment.Vulnerabilities {
		if vuln.ID == "ACTIVE-HTTP-OPEN" {
			return
		}
	}
	assessment.Vulnerabilities = append(assessment.Vulnerabilities, minimax.Vulnerability{
		ID:          "ACTIVE-HTTP-OPEN",
		Title:       "Unauthenticated camera web content accessible",
		Severity:    "High",
		Detail:      "Active browser validation rendered camera-related content without a login form or authentication wall.",
		Evidence:    validationEvidence(validation),
		Remediation: "Require authentication for camera web interfaces and restrict internet exposure.",
	})
}

func appendActiveLoginVulnerability(assessment *minimax.SecurityAssessment, validation validator.HTTPValidation) {
	for _, vuln := range assessment.Vulnerabilities {
		if vuln.ID == "ACTIVE-HTTP-AUTH-LOGIN" {
			return
		}
	}
	assessment.Vulnerabilities = append(assessment.Vulnerabilities, minimax.Vulnerability{
		ID:          "ACTIVE-HTTP-AUTH-LOGIN",
		Title:       "Camera content accessible with supplied credential",
		Severity:    "High",
		Detail:      "Active browser validation submitted the operator-supplied credential and rendered camera-related content after authentication.",
		Evidence:    validationEvidence(validation),
		Remediation: "Rotate weak/default credentials, require unique strong passwords, and restrict camera web interfaces to trusted networks.",
	})
}

func validationEvidence(validation validator.HTTPValidation) string {
	var evidence []string
	if validation.TargetURL != "" {
		evidence = append(evidence, "target="+validation.TargetURL)
	}
	if validation.LoginSucceeded && validation.LoginUsername != "" {
		evidence = append(evidence, "authenticated_username="+validation.LoginUsername)
	}
	if validation.FinalURL != "" && validation.FinalURL != validation.TargetURL {
		evidence = append(evidence, "final="+validation.FinalURL)
	}
	evidence = append(evidence, validation.Evidence...)
	return strings.Join(evidence, "; ")
}

func isBrowserSetupError(validation validator.HTTPValidation) bool {
	return strings.HasPrefix(validation.Error, "Rod browser unavailable") ||
		strings.HasPrefix(validation.Error, "create page:")
}

// confirmationType maps an assessmentDecision to a standard confirmation type label.
// Used in JSON output, Discord alerts, and file logs for auditable evidence tagging.
func confirmationType(decision assessmentDecision, assessment *minimax.SecurityAssessment) string {
	if !decision.Reportable {
		return "none"
	}
	hasActive := assessment != nil && assessment.ActiveValidation != nil

	switch {
	case hasActive && assessment.ActiveValidation.LoginSucceeded && assessment.ActiveValidation.OpenContent:
		return "active_login"
	case hasActive && assessment.ActiveValidation.OpenContent:
		return "active_open"
	case strings.Contains(decision.Reason, "bypass"):
		return "passive_bypass"
	case strings.Contains(decision.Reason, "exploitable"):
		return "passive_exploit"
	case strings.Contains(decision.Reason, "default credentials"):
		return "passive_creds"
	case strings.Contains(decision.Reason, "open access"):
		return "passive_open"
	default:
		return "passive_other"
	}
}

func appendUniqueString(values *[]string, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	for _, existing := range *values {
		if existing == value {
			return
		}
	}
	*values = append(*values, value)
}

func (a *Analyzer) emitValidation(camera shodan.Camera, validation *validator.HTTPValidation) {
	if validation == nil {
		return
	}

	message := fmt.Sprintf("%s:%d — active HTTP validation inconclusive", camera.IP, camera.Port)
	switch {
	case validation.LoginSucceeded:
		message = fmt.Sprintf("%s:%d — active HTTP validation confirmed camera content after supplied credential login", camera.IP, camera.Port)
	case validation.OpenContent:
		message = fmt.Sprintf("%s:%d — active HTTP validation confirmed open camera content", camera.IP, camera.Port)
	case validation.LoginAttempted:
		message = fmt.Sprintf("%s:%d — active HTTP validation tried supplied credential but did not confirm camera content", camera.IP, camera.Port)
	case validation.AuthRequired || validation.LoginDetected:
		message = fmt.Sprintf("%s:%d — active HTTP validation found authentication/login wall", camera.IP, camera.Port)
	case validation.BlankPage:
		message = fmt.Sprintf("%s:%d — active HTTP validation rendered blank/minimal page", camera.IP, camera.Port)
	case validation.Error != "":
		message = fmt.Sprintf("%s:%d — active HTTP validation failed: %s", camera.IP, camera.Port, validation.Error)
	}
	a.emitEvent(dashboard.EventAnalysis, message)
}

// emitEvent sends a named event to the dashboard hub, if configured.
func (a *Analyzer) emitEvent(eventType dashboard.EventType, message string) {
	if a.hub == nil {
		return
	}
	a.hub.Broadcast(dashboard.Event{
		Type: eventType,
		Data: message,
	})
}

func (a *Analyzer) markScanStarted(query string) {
	if a.hub == nil {
		return
	}
	a.hub.UpdateStats(func(s *dashboard.Stats) {
		s.TotalScans++
		s.TotalCameras = 0
		s.TotalAlerts = 0
		s.Critical = 0
		s.High = 0
		s.Medium = 0
		s.Low = 0
		s.Errors = 0
		s.ActiveScan = true
		s.CurrentQuery = query
	})
}

func (a *Analyzer) incrementFindingStats(assessment *minimax.SecurityAssessment) {
	if a.hub == nil || assessment == nil {
		return
	}
	a.hub.UpdateStats(func(s *dashboard.Stats) {
		s.TotalCameras++
		switch strings.ToLower(assessment.RiskLevel) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		}
	})
}

func (a *Analyzer) incrementAlertStats() {
	if a.hub == nil {
		return
	}
	a.hub.UpdateStats(func(s *dashboard.Stats) {
		s.TotalAlerts++
	})
}

func (a *Analyzer) incrementErrorStats() {
	if a.hub == nil {
		return
	}
	a.hub.UpdateStats(func(s *dashboard.Stats) {
		s.Errors++
	})
}

func (a *Analyzer) markScanFinished() {
	if a.hub == nil {
		return
	}
	a.hub.UpdateStats(func(s *dashboard.Stats) {
		s.ActiveScan = false
	})
}

// AnalysisPayload is the structured payload for analysis_detail events.
type AnalysisPayload struct {
	Index      int                         `json:"index"`
	Total      int                         `json:"total"`
	Camera     shodan.Camera               `json:"camera"`
	Assessment *minimax.SecurityAssessment `json:"assessment"`
}

// emitDetailEvent sends a full structured analysis payload for dashboard drill-down.
func (a *Analyzer) emitDetailEvent(index, total int, camera shodan.Camera, assessment *minimax.SecurityAssessment) {
	if a.hub == nil {
		return
	}
	a.hub.Broadcast(dashboard.Event{
		Type: dashboard.EventAnalysisDetail,
		Data: AnalysisPayload{
			Index:      index,
			Total:      total,
			Camera:     camera,
			Assessment: assessment,
		},
	})
}

type assessmentDecision struct {
	Reportable bool
	Reason     string
}

func reportableResults(results []Result) []Result {
	filtered := make([]Result, 0, len(results))
	for _, r := range results {
		if r.Assessment == nil || r.Error != "" {
			continue
		}
		if isReportableAssessment(r.Camera, r.Assessment) {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func enforceReportableAssessment(camera shodan.Camera, assessment *minimax.SecurityAssessment) assessmentDecision {
	decision := assessReportability(camera, assessment)
	if assessment == nil {
		return decision
	}
	assessment.RiskScore = clampScore(assessment.RiskScore)

	// Programmatic anti-FP: strip CVEs that don't match the camera vendor
	stripCrossVendorCVEs(camera, assessment)

	if decision.Reportable {
		if strings.TrimSpace(assessment.RiskLevel) == "" || strings.EqualFold(assessment.RiskLevel, "unknown") {
			assessment.RiskLevel = riskLevelForScore(assessment.RiskScore)
		}
		return decision
	}

	if assessment.RiskScore > 20 {
		assessment.RiskScore = 20
	}
	assessment.RiskLevel = "Low"
	assessment.IsOpen = false
	assessment.DefaultCreds = false
	assessment.Exploitable = false
	assessment.ExploitEvidence = ""
	assessment.Vulnerabilities = nil
	assessment.ExploitPaths = nil
	assessment.CveReferences = nil
	assessment.AuthAnalysis.BypassPossible = false
	assessment.AuthAnalysis.BypassMethod = ""
	assessment.Summary = "Not vulnerable: " + decision.Reason
	return decision
}

func isReportableAssessment(camera shodan.Camera, assessment *minimax.SecurityAssessment) bool {
	return assessReportability(camera, assessment).Reportable
}

func assessReportability(camera shodan.Camera, assessment *minimax.SecurityAssessment) assessmentDecision {
	if assessment == nil {
		return assessmentDecision{Reason: "no assessment available"}
	}

	// Active confirmation: either (1) logged in successfully + saw content,
	// or (2) endpoint probe confirmed open content without needing login
	hasActiveConfirmation := assessment.ActiveValidation != nil &&
		((assessment.ActiveValidation.LoginSucceeded && assessment.ActiveValidation.OpenContent) ||
			(assessment.ActiveValidation.OpenContent && assessment.IsOpen && assessment.Exploitable))

	isKnownVendor := knownCameraVendor(camera)
	log.Printf("         [DEBUG] assessReportability: product=%q isKnownVendor=%v hasActiveConfirmation=%v activeValidation=%v",
		camera.Product, isKnownVendor, hasActiveConfirmation, assessment.ActiveValidation != nil)
	if assessment.ActiveValidation != nil {
		log.Printf("         [DEBUG]   ActiveValidation: LoginSucceeded=%v OpenContent=%v LoginDetected=%v AuthRequired=%v",
			assessment.ActiveValidation.LoginSucceeded, assessment.ActiveValidation.OpenContent,
			assessment.ActiveValidation.LoginDetected, assessment.ActiveValidation.AuthRequired)
	}

	// HARD VENDOR OVERRIDE — highest priority guard.
	// Known camera vendors (Hikvision, Dahua, Axis, etc.) ALWAYS ship with
	// authentication-protected web UIs. Shodan's passive banner data contains
	// HTTP headers but NOT the HTML body (which has the login.asp/login.html form).
	// The AI sees "HTTP 200" + product name and hallucinates "open access / critical".
	// Without active validation (rod) confirming we actually got past the login page,
	// ALL passive AI claims are rejected for these vendors — no exceptions.
	if isKnownVendor && !hasActiveConfirmation {
		log.Printf("         🔒 Known vendor %s — rejecting ALL passive AI claims (no active validation)", camera.Product)
		return assessmentDecision{
			Reason: "known camera vendor with authentication-protected UI; no active validation confirms open access",
		}
	}

	authRequired := requiresAuthentication(camera, assessment)
	hasLoginPage := bannerShowsLoginPage(camera)

	// When the banner clearly shows a login page (e.g. Hikvision login.asp redirect),
	// reject ALL passive-only AI claims (default creds, bypass, exploitable).
	// Only active validation can override a visible login page.
	if hasLoginPage && !hasActiveConfirmation {
		log.Printf("         🛡️ Banner login page detected — rejecting passive AI claims")
		return assessmentDecision{
			Reason: "login page detected in banner, no active validation confirms access",
		}
	}

	confirmedDefaultCreds := assessment.DefaultCreds && !hasUnconfirmedDefaultCredsLanguage(assessment)
	confirmedBypass := assessment.AuthAnalysis.BypassPossible && hasBypassEvidence(assessment)
	confirmedExploitable := assessment.Exploitable && hasExploitEvidence(assessment)
	confirmedLogin := hasActiveConfirmation
	confirmedOpen := assessment.IsOpen && !authRequired

	if authRequired && !confirmedDefaultCreds && !confirmedBypass && !confirmedExploitable && !confirmedLogin {
		return assessmentDecision{
			Reason: "authentication required and no confirmed bypass, working default credentials, or exploitable issue",
		}
	}
	if confirmedOpen {
		return assessmentDecision{Reportable: true, Reason: "confirmed open access"}
	}
	if confirmedDefaultCreds {
		return assessmentDecision{Reportable: true, Reason: "confirmed working default credentials"}
	}
	if confirmedBypass {
		return assessmentDecision{Reportable: true, Reason: "confirmed authentication bypass"}
	}
	if confirmedLogin {
		return assessmentDecision{Reportable: true, Reason: "confirmed login with supplied credential"}
	}
	if confirmedExploitable {
		return assessmentDecision{Reportable: true, Reason: "confirmed exploitable issue"}
	}

	return assessmentDecision{
		Reason: "no confirmed open access, working credentials, auth bypass, or exploitable path",
	}
}

func requiresAuthentication(camera shodan.Camera, assessment *minimax.SecurityAssessment) bool {
	// CRITICAL: Known camera vendors ALWAYS have login pages by default.
	// Shodan's banner data only contains HTTP headers + parsed product info,
	// NOT the HTML body (which contains the login.asp/login.html redirect).
	// The AI sees "HTTP 200" and wrongly concludes "open access".
	// For known vendors, always assume auth unless active validation proves otherwise.
	if knownCameraVendor(camera) {
		log.Printf("         🔒 Known camera vendor detected — assuming auth required")
		return true
	}

	if assessment.AuthAnalysis.AuthRequired {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(assessment.AuthAnalysis.AuthType)) {
	case "basic", "digest", "form", "token":
		return true
	}

	if camera.HTTP != nil && (camera.HTTP.Status == 401 || camera.HTTP.Status == 403) {
		return true
	}

	return containsAny(strings.ToLower(strings.Join([]string{
		camera.Title,
		camera.Banner,
		httpTitle(camera),
		httpServer(camera),
		assessment.Summary,
	}, " ")), []string{
		"401 unauthorized",
		"403 forbidden",
		"www-authenticate",
		"basic realm",
		"digest realm",
		"/login",
		"login page",
		"login form",
		"sign in",
		"auth required",
		"authentication required",
		"requires authentication",
		`type="password"`,
		`type='password'`,
		"password required",
		"enter password",
		// Banner-level login page indicators the AI frequently ignores
		"login.asp",
		"login.html",
		"login.php",
		"login.cgi",
		"login.htm",
		"user name",
		"username",
		"<input",
		"please respect other people",
	})
}

// knownCameraVendor returns true if the camera is from a vendor whose products
// universally ship with authentication-protected web interfaces.
// These vendors' cameras always redirect to login pages (login.asp, login.html, etc.)
// but Shodan's banner data doesn't include the HTML body showing the redirect.
var knownAuthVendors = []string{
	"hikvision",
	"dahua",
	"axis",
	"foscam",
	"avtech",
	"reolink",
	"amcrest",
	"uniview",
	"hanwha",
	"vivotek",
	"bosch",
	"pelco",
	"honeywell",
	"tyco",
	"flir",
	"geovision",
	"cp plus",
	"cp-plus",
	"cpplus",
	"samsung wisenet",
	"wisenet",
	"huawei",
	"tiandy",
}

func knownCameraVendor(camera shodan.Camera) bool {
	combined := strings.ToLower(camera.Product + " " + camera.Banner + " " + camera.Title)
	if camera.HTTP != nil {
		combined += " " + strings.ToLower(camera.HTTP.Title + " " + camera.HTTP.Server)
	}
	for _, vendor := range knownAuthVendors {
		if strings.Contains(combined, vendor) {
			return true
		}
	}
	return false
}

func hasUnconfirmedDefaultCredsLanguage(assessment *minimax.SecurityAssessment) bool {
	return containsAny(assessmentEvidenceText(assessment), []string{
		"likely default",
		"likely using default",
		"suspected default",
		"possible default",
		"potential default",
		"default credentials likely",
		"not confirmed",
		"unconfirmed",
		"cannot confirm",
		"verification needed",
	})
}

func hasBypassEvidence(assessment *minimax.SecurityAssessment) bool {
	method := strings.TrimSpace(assessment.AuthAnalysis.BypassMethod)
	if method == "" {
		return false
	}
	// Reject speculative bypass claims from the AI
	if isSpeculativeEvidence(method) {
		return false
	}
	return true
}

func hasExploitEvidence(assessment *minimax.SecurityAssessment) bool {
	if ev := strings.TrimSpace(assessment.ExploitEvidence); ev != "" {
		if !isSpeculativeEvidence(ev) {
			return true
		}
	}
	for _, path := range assessment.ExploitPaths {
		if !isSpeculativeEvidence(path) {
			return true
		}
	}
	for _, vuln := range assessment.Vulnerabilities {
		if ev := strings.TrimSpace(vuln.Evidence); ev != "" {
			if !isSpeculativeEvidence(ev) {
				return true
			}
		}
	}
	return false
}

// isSpeculativeEvidence detects AI hallucination patterns — phrases that
// describe theoretical risk rather than confirmed exploitation.
func isSpeculativeEvidence(text string) bool {
	return containsAny(strings.ToLower(text), speculativePatterns)
}

var speculativePatterns = []string{
	"may be vulnerable",
	"could be vulnerable",
	"might be vulnerable",
	"potentially vulnerable",
	"possibly vulnerable",
	"likely vulnerable",
	"could allow",
	"may allow",
	"might allow",
	"potentially exploitable",
	"possibly exploitable",
	"may be exploitable",
	"could be exploited",
	"may be exposed",
	"suggested by",
	"indicates possible",
	"suspected",
	"unverified",
	"not confirmed",
	"not verified",
	"cannot confirm",
	"unable to confirm",
	"unable to verify",
	"needs verification",
	"verification needed",
	"requires further",
	"further analysis",
	"further investigation",
	"based on firmware version",
	"based on the firmware",
	"based on version",
	"based on banner",
	"version-based",
	"firmware suggests",
	"firmware indicates",
	"firmware version",
	"outdated firmware",
	"older firmware",
	"appears to",
	"appears vulnerable",
	"typically",
	"commonly",
	"historically",
	"known to be",
	"known to have",
	"often",
	"usually",
	"default credentials are common",
	"common default",
	"standard default",
	"factory default",
	"well-known",
	"widely known",
}

// bannerShowsLoginPage checks if the Shodan banner data contains evidence
// of a login page redirect or login form, which definitively proves
// the camera requires authentication regardless of what the AI claims.
func bannerShowsLoginPage(camera shodan.Camera) bool {
	combined := strings.ToLower(camera.Banner + " " + camera.Title)
	if camera.HTTP != nil {
		combined += " " + strings.ToLower(camera.HTTP.Title)
	}
	return containsAny(combined, []string{
		"login.asp",
		"login.html",
		"login.php",
		"login.cgi",
		"login.htm",
		"login.jsp",
		"weblogin.htm",
		"user login",
		"doc/page/login",
		"/login?",
		"type=\"password\"",
		"type='password'",
		"password field",
		"<input type=\"password",
		"<input type='password",
	})
}

func assessmentEvidenceText(assessment *minimax.SecurityAssessment) string {
	if assessment == nil {
		return ""
	}
	var parts []string
	parts = append(parts, assessment.Summary, assessment.ExploitEvidence, assessment.AuthAnalysis.BypassMethod)
	parts = append(parts, assessment.ExploitPaths...)
	parts = append(parts, assessment.AccessInstructions...)
	for _, vuln := range assessment.Vulnerabilities {
		parts = append(parts, vuln.Title, vuln.Detail, vuln.Evidence)
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func httpTitle(camera shodan.Camera) string {
	if camera.HTTP == nil {
		return ""
	}
	return camera.HTTP.Title
}

func httpServer(camera shodan.Camera) string {
	if camera.HTTP == nil {
		return ""
	}
	return camera.HTTP.Server
}

func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func riskLevelForScore(score int) string {
	switch {
	case score >= 76:
		return "Critical"
	case score >= 51:
		return "High"
	case score >= 21:
		return "Medium"
	default:
		return "Low"
	}
}

// corporateFilterRe matches Shodan filters that require Corporate/Enterprise plans.
// Covers: tag:"value", vuln:"value", ssl.cert.fingerprint:"value", has_screenshot:true/false
var corporateFilterRe = regexp.MustCompile(`(?i)\b(?:tag|vuln|ssl\.cert\.fingerprint|has_screenshot)\s*:\s*(?:"[^"]*"|[^\s]+)`)

// sanitizeQuery removes known Corporate-only Shodan filters from a query string.
// This prevents 400 errors from the Shodan API for non-Corporate plan users.
// It preserves all free-plan-compatible filters (title, product, country, city, etc.)
func sanitizeQuery(query string) string {
	cleaned := corporateFilterRe.ReplaceAllString(query, "")
	// Collapse multiple spaces and trim
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	return cleaned
}

// vendorCVEMap defines which CVEs belong to which vendor. Any CVE listed
// under one vendor must NOT appear in results for a different vendor.
var vendorCVEMap = map[string][]string{
	"hikvision": {"CVE-2021-36260", "CVE-2017-7921"},
	"dahua":     {"CVE-2021-33044", "CVE-2020-25078"},
	"axis":      {"CVE-2018-10660", "CVE-2018-10661"},
	"foscam":    {"CVE-2018-6830", "CVE-2017-2871"},
	"avtech":    {"CVE-2016-11021"},
	"huawei":    {},
	"tiandy":    {},
}

// stripCrossVendorCVEs removes CVEs that belong to a different vendor than the
// identified camera product. This prevents the AI from applying e.g. Dahua CVEs
// to Hikvision cameras (a common hallucination pattern).
func stripCrossVendorCVEs(camera shodan.Camera, assessment *minimax.SecurityAssessment) {
	if assessment == nil {
		return
	}

	productLower := strings.ToLower(camera.Product)

	// Determine which vendor this camera belongs to
	detectedVendor := ""
	for vendor := range vendorCVEMap {
		if strings.Contains(productLower, vendor) {
			detectedVendor = vendor
			break
		}
	}
	if detectedVendor == "" {
		// Also check banner and title
		combined := strings.ToLower(camera.Banner + " " + camera.Title + " " + httpTitle(camera))
		for vendor := range vendorCVEMap {
			if strings.Contains(combined, vendor) {
				detectedVendor = vendor
				break
			}
		}
	}
	if detectedVendor == "" {
		return // unknown vendor, can't filter
	}

	// Build a set of CVEs that belong to OTHER vendors
	forbiddenCVEs := make(map[string]bool)
	for vendor, cves := range vendorCVEMap {
		if vendor == detectedVendor {
			continue
		}
		for _, cve := range cves {
			forbiddenCVEs[strings.ToUpper(cve)] = true
		}
	}

	// Filter cve_references
	stripped := 0
	filtered := make([]string, 0, len(assessment.CveReferences))
	for _, cve := range assessment.CveReferences {
		if forbiddenCVEs[strings.ToUpper(cve)] {
			stripped++
			continue
		}
		filtered = append(filtered, cve)
	}
	assessment.CveReferences = filtered

	// Filter vulnerabilities that reference forbidden CVEs
	filteredVulns := make([]minimax.Vulnerability, 0, len(assessment.Vulnerabilities))
	for _, vuln := range assessment.Vulnerabilities {
		isForbidden := false
		vulnUpper := strings.ToUpper(vuln.Title + " " + vuln.Detail + " " + vuln.Evidence)
		for cve := range forbiddenCVEs {
			if strings.Contains(vulnUpper, cve) {
				isForbidden = true
				stripped++
				break
			}
		}
		if !isForbidden {
			filteredVulns = append(filteredVulns, vuln)
		}
	}
	assessment.Vulnerabilities = filteredVulns

	if stripped > 0 {
		log.Printf("         🛡️ Stripped %d cross-vendor CVE(s) from %s camera", stripped, detectedVendor)
	}
}
