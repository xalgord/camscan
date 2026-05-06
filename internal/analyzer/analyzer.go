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

	"github.com/fatih/color"
)

// Result pairs a discovered camera with its AI security assessment.
type Result struct {
	Camera     shodan.Camera
	Assessment *minimax.SecurityAssessment
	Error      string // Non-empty if AI analysis failed for this camera
}

// Analyzer orchestrates the Shodan → Minimax pipeline.
type Analyzer struct {
	shodanClient  *shodan.Client
	minimaxClient *minimax.Client
	notifier      *discord.Notifier
	hub           *dashboard.Hub
	noAI          bool
}

// New creates a new Analyzer instance.
func New(shodanClient *shodan.Client, minimaxClient *minimax.Client, notifier *discord.Notifier, hub *dashboard.Hub, noAI bool) *Analyzer {
	return &Analyzer{
		shodanClient:  shodanClient,
		minimaxClient: minimaxClient,
		notifier:      notifier,
		hub:           hub,
		noAI:          noAI,
	}
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
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	dim := color.New(color.FgHiBlack)

	cyan.Println("\n═══════════════════════════════════════════════════════════════")
	cyan.Println("  PHASE 1: PRE-FLIGHT CHECKS")
	cyan.Println("═══════════════════════════════════════════════════════════════")

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
		fmt.Printf("  ├─ Shodan Plan:    %s\n", apiInfo.Plan)
		fmt.Printf("  ├─ Query Credits:  %d remaining\n", apiInfo.QueryCredits)
		fmt.Printf("  └─ Scan Credits:   %d remaining\n", apiInfo.ScanCredits)
	}

	// Pre-sanitize: strip corporate-only filters before sending to Shodan
	originalQuery := queryStr
	queryStr = sanitizeQuery(queryStr)
	if queryStr != originalQuery {
		yellow.Printf("\n  ⚠  Removed restricted filters from query\n")
		yellow.Printf("     Original: %s\n", originalQuery)
		green.Printf("     Sanitized: %s\n", queryStr)
		a.emitEvent(dashboard.EventLog, fmt.Sprintf("Auto-sanitized query: removed restricted filters. New query: %s", queryStr))

		// If sanitization left the query empty or too generic, use AI to rebuild it
		if strings.TrimSpace(queryStr) == "" && !a.noAI && a.minimaxClient != nil {
			yellow.Printf("  🤖 Query was empty after sanitization — asking AI to generate a new one...\n")
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("Query empty after sanitization, asking AI to regenerate from: %s", originalQuery))
			generated, genErr := a.minimaxClient.GenerateQuery(ctx, originalQuery, shodanPlan)
			if genErr != nil {
				return nil, 0, fmt.Errorf("AI query regeneration failed: %w", genErr)
			}
			queryStr = generated
			green.Printf("  ✓ AI generated replacement query: %s\n", queryStr)
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI regenerated query: %s", queryStr))
		}
	}

	cyan.Println("\n═══════════════════════════════════════════════════════════════")
	cyan.Println("  PHASE 2: SHODAN RECONNAISSANCE")
	cyan.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("  ├─ Query:    %s\n", queryStr)
	fmt.Printf("  ├─ Limit:    %d results\n", limit)
	dim.Printf("  └─ Sending request to api.shodan.io...\n")

	// Dashboard: emit scan start
	a.emitEvent(dashboard.EventScanStart, fmt.Sprintf("Scan started — query: %s, limit: %d", queryStr, limit))

	// Step 1: Discover cameras via Shodan (with AI error-recovery loop)
	const maxQueryRetries = 2
	var searchResult *shodan.SearchResult
	var shodanDur time.Duration
	currentQuery := queryStr

	for attempt := 0; attempt <= maxQueryRetries; attempt++ {
		shodanStart := time.Now()
		result, searchErr := a.shodanClient.SearchRaw(ctx, currentQuery, limit)
		shodanDur = time.Since(shodanStart).Round(time.Millisecond)

		if searchErr == nil {
			searchResult = result
			if attempt > 0 {
				green.Printf("  ✓ AI-corrected query succeeded (attempt %d) in %s\n", attempt+1, shodanDur)
				a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI-corrected query succeeded on attempt %d: %s", attempt+1, currentQuery))
			}
			break
		}

		// If this is the last attempt or AI is disabled, fail
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
		yellow.Printf("  ⚠  Shodan query failed: %v\n", searchErr)
		yellow.Printf("  🤖 Asking AI to fix the query (attempt %d/%d)...\n", attempt+1, maxQueryRetries)
		a.emitEvent(dashboard.EventLog, fmt.Sprintf("Shodan error: %v — AI fixing query (attempt %d/%d)", searchErr, attempt+1, maxQueryRetries))

		fixedQuery, fixErr := a.minimaxClient.FixQuery(ctx, currentQuery, searchErr.Error(), shodanPlan)
		if fixErr != nil {
			yellow.Printf("  ⚠  AI query fix failed: %v\n", fixErr)
			a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI query fix failed: %v", fixErr))
			return nil, 0, fmt.Errorf("shodan search failed: %w (AI fix also failed: %v)", searchErr, fixErr)
		}

		green.Printf("  ✓ AI generated corrected query: %s\n", fixedQuery)
		a.emitEvent(dashboard.EventLog, fmt.Sprintf("AI corrected query: %s", fixedQuery))
		currentQuery = fixedQuery
	}

	total := searchResult.Total
	cameras := searchResult.Matches

	if len(cameras) == 0 {
		yellow.Println("  ⚠  No cameras found matching your query.")
		a.emitEvent(dashboard.EventScanComplete, "No cameras found matching query.")
		return nil, total, nil
	}

	green.Printf("  ✓ Found %d cameras (total in Shodan: %d) in %s\n", len(cameras), total, shodanDur)
	a.emitEvent(dashboard.EventCameraFound, fmt.Sprintf("Discovered %d cameras (total in Shodan: %d)", len(cameras), total))

	// Print discovered cameras summary
	fmt.Println()
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
		dim.Printf("  %s─ [%d] %s:%d  %s  (%s)\n", prefix, i+1, cam.IP, cam.Port, product, loc)
	}

	// Step 2: If AI analysis is disabled, return raw results
	if a.noAI {
		yellow.Println("\n  ℹ  AI analysis skipped (--no-ai flag)")
		results := make([]Result, len(cameras))
		for i, cam := range cameras {
			results[i] = Result{Camera: cam}
		}
		return results, total, nil
	}

	// Step 3: Analyze each camera with Minimax M2.7
	cyan.Println("\n═══════════════════════════════════════════════════════════════")
	cyan.Printf("  PHASE 3: AI SECURITY ANALYSIS (%d cameras)\n", len(cameras))
	cyan.Println("═══════════════════════════════════════════════════════════════")
	dim.Printf("  Engine: Minimax M2.7 | Concurrency: 3 | Methodology: 6-phase pentest\n\n")

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
				fmt.Printf("  [%d/%d] %s:%d (%s)\n", idx+1, len(cameras), camera.IP, camera.Port, product)
				color.Red("         ❌ AI analysis failed (%s): %s\n", aiDur, analyzeErr.Error())
				a.emitEvent(dashboard.EventAnalysis, fmt.Sprintf("[%d/%d] %s:%d — ❌ AI analysis failed: %s", idx+1, len(cameras), camera.IP, camera.Port, analyzeErr.Error()))
			} else {
				results[idx] = Result{
					Camera:     camera,
					Assessment: assessment,
				}
				icon := risk.Icon(assessment.RiskLevel)
				vulnCount := len(assessment.Vulnerabilities)
				cveCount := len(assessment.CveReferences)

				// Main status line
				fmt.Printf("  [%d/%d] %s:%d (%s)\n", idx+1, len(cameras), camera.IP, camera.Port, product)
				fmt.Printf("         %s %s  Score: %d/100  Open: %v  DefCreds: %v\n",
					icon, assessment.RiskLevel, assessment.RiskScore, assessment.IsOpen, assessment.DefaultCreds)

				// Vulnerability summary
				if vulnCount > 0 || cveCount > 0 {
					fmt.Printf("         Vulns: %d found", vulnCount)
					if cveCount > 0 {
						fmt.Printf("  CVEs: %s", strings.Join(assessment.CveReferences, ", "))
					}
					fmt.Println()
				}

				// Exploit paths
				if len(assessment.ExploitPaths) > 0 {
					for _, ep := range assessment.ExploitPaths {
						dim.Printf("         ⚔ %s\n", ep)
					}
				}

				dim.Printf("         ⏱ %s\n\n", aiDur)

				a.emitEvent(dashboard.EventAnalysis, fmt.Sprintf("[%d/%d] %s:%d — %s %s (%d/100) vulns=%d cves=%d",
					idx+1, len(cameras), camera.IP, camera.Port, icon, assessment.RiskLevel, assessment.RiskScore, vulnCount, cveCount))

				// Emit full structured analysis for the interactive dashboard
				a.emitDetailEvent(idx+1, len(cameras), camera, assessment)

				// REAL-TIME Discord alert — send immediately after each camera analysis
				if a.notifier != nil {
					if sent := a.sendSingleAlert(camera, assessment); sent {
						atomic.AddInt32(&alertedCount, 1)
					}
				}
			}
		}(i, cam)
	}

	wg.Wait()
	fmt.Println()

	// Send scan summary after all analysis is done
	alerted := int(atomic.LoadInt32(&alertedCount))
	if a.notifier != nil {
		cyan.Println("═══════════════════════════════════════════════════════════════")
		cyan.Println("  PHASE 4: DISCORD SUMMARY")
		cyan.Println("═══════════════════════════════════════════════════════════════")
		a.sendScanSummary(results, queryStr, total, alerted, scanStart)
		green.Printf("  ✓ Sent %d real-time alerts + scan summary\n", alerted)
		a.emitEvent(dashboard.EventAlertSent, fmt.Sprintf("Dispatched %d real-time Discord alerts", alerted))
	}

	scanDuration := time.Since(scanStart).Round(time.Second)

	cyan.Println("\n═══════════════════════════════════════════════════════════════")
	cyan.Println("  SCAN COMPLETE")
	cyan.Println("═══════════════════════════════════════════════════════════════")

	// Count by risk level for summary
	var critN, highN, medN, lowN, errN int
	for _, r := range results {
		if r.Error != "" {
			errN++
			continue
		}
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

	fmt.Printf("  ├─ Duration:    %s\n", scanDuration)
	fmt.Printf("  ├─ Analyzed:    %d cameras\n", len(results))
	if critN > 0 {
		color.Red("  ├─ Critical:    %d\n", critN)
	}
	if highN > 0 {
		color.Yellow("  ├─ High:        %d\n", highN)
	}
	if medN > 0 {
		color.HiYellow("  ├─ Medium:      %d\n", medN)
	}
	if lowN > 0 {
		color.Green("  ├─ Low:         %d\n", lowN)
	}
	if errN > 0 {
		color.Red("  ├─ Errors:      %d\n", errN)
	}
	fmt.Printf("  └─ Dashboard:   http://localhost:9847\n")

	a.emitEvent(dashboard.EventScanComplete, fmt.Sprintf("Scan finished — %d cameras analyzed in %s (crit=%d high=%d med=%d low=%d err=%d)",
		len(results), scanDuration, critN, highN, medN, lowN, errN))

	return results, total, nil
}

// sendSingleAlert sends a real-time Discord alert for a single camera result.
// Called inline during analysis to provide immediate notifications.
// I3: Triggers on "Critical", "High", open access, or default credentials.
// Returns true if an alert was successfully sent.
func (a *Analyzer) sendSingleAlert(camera shodan.Camera, assessment *minimax.SecurityAssessment) bool {
	if assessment == nil {
		return false
	}

	level := strings.ToLower(assessment.RiskLevel)
	shouldAlert := assessment.IsOpen ||
		assessment.DefaultCreds ||
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
	}

	if err := a.notifier.SendAlert(alert); err != nil {
		log.Printf("  ├─ ⚠ Alert FAILED for %s:%d: %v", camera.IP, camera.Port, err)
		return false
	}

	fmt.Printf("  📨 %s:%d → %s %s (Score: %d) — sent to Discord\n",
		camera.IP, camera.Port, risk.Icon(assessment.RiskLevel), assessment.RiskLevel, assessment.RiskScore)
	return true
}

// sendScanSummary counts risk levels from results and sends a completion
// notification to Discord.
func (a *Analyzer) sendScanSummary(results []Result, query string, totalShodan, alerted int, scanStart time.Time) {
	var crit, high, med, low, unknown, errors int
	for _, r := range results {
		if r.Error != "" {
			errors++
			continue
		}
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
		fmt.Println("  └─ 📋 Scan summary sent")
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

// AnalysisPayload is the structured payload for analysis_detail events.
type AnalysisPayload struct {
	Index      int                        `json:"index"`
	Total      int                        `json:"total"`
	Camera     shodan.Camera              `json:"camera"`
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
