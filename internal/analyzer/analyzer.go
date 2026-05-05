package analyzer

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

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
	noAI          bool
}

// New creates a new Analyzer instance.
func New(shodanClient *shodan.Client, minimaxClient *minimax.Client, notifier *discord.Notifier, noAI bool) *Analyzer {
	return &Analyzer{
		shodanClient:  shodanClient,
		minimaxClient: minimaxClient,
		notifier:      notifier,
		noAI:          noAI,
	}
}

// Run executes the full discovery + analysis pipeline.
// B1: Discord alerts are now sent sequentially after analysis completes.
// W2: Checks Shodan query credits before scanning.
// I2: Accepts context.Context for cancellation/timeout.
func (a *Analyzer) Run(ctx context.Context, query *shodan.SearchQuery, limit int) ([]Result, int, error) {
	scanStart := time.Now()
	cyan := color.New(color.FgCyan, color.Bold)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)

	// W2: Pre-flight check — verify Shodan has enough query credits
	apiInfo, err := a.shodanClient.GetAPIInfo(ctx)
	if err != nil {
		log.Printf("⚠ Could not verify Shodan credits: %v", err)
	} else if apiInfo.QueryCredits <= 0 {
		return nil, 0, fmt.Errorf("shodan has 0 query credits remaining (plan: %s)", apiInfo.Plan)
	} else {
		log.Printf("ℹ Shodan credits remaining: %d (plan: %s)", apiInfo.QueryCredits, apiInfo.Plan)
	}

	queryStr := query.BuildQuery()
	cyan.Printf("\n🔍 Searching Shodan: %s\n", queryStr)

	// Step 1: Discover cameras via Shodan
	searchResult, err := a.shodanClient.Search(ctx, query, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("shodan search failed: %w", err)
	}

	total := searchResult.Total
	cameras := searchResult.Matches

	if len(cameras) == 0 {
		yellow.Println("⚠  No cameras found matching your query.")
		return nil, total, nil
	}

	green.Printf("✓  Found %d cameras (total in Shodan: %d)\n", len(cameras), total)

	// Step 2: If AI analysis is disabled, return raw results
	if a.noAI {
		yellow.Println("ℹ  AI analysis skipped (--no-ai flag)")
		results := make([]Result, len(cameras))
		for i, cam := range cameras {
			results[i] = Result{Camera: cam}
		}
		return results, total, nil
	}

	// Step 3: Analyze each camera with Minimax M2.7
	cyan.Printf("🤖 Analyzing %d cameras with Minimax M2.7...\n\n", len(cameras))

	results := make([]Result, len(cameras))
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

			prompt := buildCameraPrompt(camera)
			assessment, analyzeErr := a.minimaxClient.AnalyzeCamera(ctx, prompt)

			if analyzeErr != nil {
				results[idx] = Result{
					Camera: camera,
					Error:  analyzeErr.Error(),
				}
				fmt.Printf("  [%d/%d] %s:%d — ❌ AI analysis failed\n", idx+1, len(cameras), camera.IP, camera.Port)
			} else {
				results[idx] = Result{
					Camera:     camera,
					Assessment: assessment,
				}
				icon := risk.Icon(assessment.RiskLevel)
				fmt.Printf("  [%d/%d] %s:%d — %s %s\n", idx+1, len(cameras), camera.IP, camera.Port, icon, assessment.RiskLevel)
			}
		}(i, cam)
	}

	wg.Wait()
	fmt.Println()

	// B1: Send Discord alerts sequentially AFTER all analysis is done.
	// This avoids concurrent goroutines hammering the Discord API.
	if a.notifier != nil {
		alerted := a.sendAlerts(results)
		a.sendScanSummary(results, query.BuildQuery(), total, alerted, scanStart)
	}

	return results, total, nil
}

// sendAlerts iterates analyzed results and sends Discord notifications
// for cameras matching alert criteria. Called sequentially after analysis.
// I3: Triggers on "Critical", "High", open access, or default credentials.
// Returns the count of successfully sent alerts.
func (a *Analyzer) sendAlerts(results []Result) int {
	alerted := 0
	for _, r := range results {
		if r.Assessment == nil {
			continue
		}

		level := strings.ToLower(r.Assessment.RiskLevel)
		shouldAlert := r.Assessment.IsOpen ||
			r.Assessment.DefaultCreds ||
			level == "critical" ||
			level == "high"

		if !shouldAlert {
			continue
		}

		location := r.Camera.Location.City
		if location != "" && r.Camera.Location.Country != "" {
			location += ", " + r.Camera.Location.Country
		} else if r.Camera.Location.Country != "" {
			location = r.Camera.Location.Country
		}

		alert := discord.CameraAlert{
			IP:              r.Camera.IP,
			Port:            r.Camera.Port,
			Product:         r.Camera.Product,
			Location:        location,
			Org:             r.Camera.Org,
			RiskLevel:       r.Assessment.RiskLevel,
			IsOpen:          r.Assessment.IsOpen,
			DefaultCreds:    r.Assessment.DefaultCreds,
			Summary:         r.Assessment.Summary,
			Vulnerabilities: r.Assessment.Vulnerabilities,
		}

		if err := a.notifier.SendAlert(alert); err != nil {
			log.Printf("  ⚠ Discord alert failed for %s:%d: %v", r.Camera.IP, r.Camera.Port, err)
		} else {
			fmt.Printf("  📨 Discord alert sent for %s:%d\n", r.Camera.IP, r.Camera.Port)
			alerted++
		}
	}
	return alerted
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
		log.Printf("  ⚠ Discord scan summary failed: %v", err)
	} else {
		log.Println("  📋 Discord scan summary sent")
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
