package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xalgord/camscan/config"
	"github.com/xalgord/camscan/internal/analyzer"
	"github.com/xalgord/camscan/internal/dashboard"
	"github.com/xalgord/camscan/internal/discord"
	"github.com/xalgord/camscan/internal/minimax"
	"github.com/xalgord/camscan/internal/output"
	"github.com/xalgord/camscan/internal/shodan"
	"github.com/xalgord/camscan/internal/validator"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// version is set at build time via ldflags:
//
//	go build -ldflags "-X github.com/xalgord/camscan/cmd.version=v1.2.0"
var version string

// Version returns the build version, preferring ldflags > go install module info > "dev".
var Version = func() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}()

var (
	country         string
	state           string
	city            string
	cameraType      string
	rawQuery        string
	limit           int
	outputFmt       string
	outputFile      string
	verbose         bool
	noAI            bool
	webhookURL      string
	daemon          bool
	interval        string
	validateHTTP    bool
	passiveOnly     bool
	validateTimeout time.Duration
	loginCredential  string
	authorizedLogin  bool
	testDefaultCreds bool
)

var rootCmd = &cobra.Command{
	Use:   "camscan",
	Short: "IP Camera Security Scanner",
	Long: `CamScan discovers IP cameras via Shodan and uses Minimax M2.7 AI
to assess their security posture.

Supports filtering by country, state, city, and camera type.
Use --query for raw Shodan dorks or natural-language queries (AI-powered).
By default, HTTP/HTTPS targets are actively validated with Rod/Chromium to
confirm camera content vs. login walls — eliminating AI false positives.
Use --passive-only to disable active connections and rely on Shodan banner data only.
Use --login-credential only on authorized scopes; it tests one supplied credential once after a login wall is detected.`,
	Example: `  camscan --country IN --limit 10
  camscan --country US --city "New York" --type hikvision
  camscan -c RU --city Moscow -v --limit 5
  camscan --country JP --no-ai --output json
  camscan --query 'product:"Hikvision" country:IN'
  camscan --query "find hikvision cameras in mumbai" --limit 10
  camscan --query 'product:"Hikvision" country:PK' --passive-only
  CAMSCAN_LOGIN_CREDENTIAL='admin:admin' camscan --query 'net:"192.0.2.0/24" product:"Hikvision"' --authorized-login-test
  camscan --country IN --daemon --webhook https://discord.com/api/webhooks/...
  camscan --country IN --daemon --interval 30m --webhook https://discord.com/api/webhooks/...`,
	RunE:    runScan,
	Version: Version,
}

func init() {
	rootCmd.Flags().StringVarP(&country, "country", "c", "", "2-letter country code (e.g., IN, US, RU)")
	rootCmd.Flags().StringVarP(&state, "state", "s", "", "State or region name")
	rootCmd.Flags().StringVar(&city, "city", "", "City name")
	rootCmd.Flags().StringVarP(&cameraType, "type", "t", "", "Camera type: hikvision, dahua, huawei, tiandy, axis, rtsp, dvr, nvr, avtech, geovision, webcamxp, yawcam, blueiris, all (default: broad CCTV search)")
	rootCmd.Flags().StringVarP(&rawQuery, "query", "q", "", "Raw Shodan query or natural-language search (AI-powered). When set, --country is optional.")
	rootCmd.Flags().IntVarP(&limit, "limit", "l", 25, "Maximum number of results")
	rootCmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table, json")
	rootCmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Append results to this file in JSONL format (each scan = one JSON line)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed results with full banner data")
	rootCmd.Flags().BoolVar(&noAI, "no-ai", false, "Skip Minimax AI analysis, show Shodan results only")
	rootCmd.Flags().StringVar(&webhookURL, "webhook", "", "Discord webhook URL for alerts (overrides DISCORD_WEBHOOK_URL env)")
	rootCmd.Flags().BoolVar(&daemon, "daemon", false, "Run continuously in daemon mode (for systemd)")
	rootCmd.Flags().StringVar(&interval, "interval", "0", "Scan interval in daemon mode (0 = single scan + dashboard only, e.g., 15m, 1h)")
	rootCmd.Flags().BoolVar(&validateHTTP, "validate-http", true, "Actively render HTTP/HTTPS web interfaces with Rod before reporting findings (default: on)")
	rootCmd.Flags().BoolVar(&passiveOnly, "passive-only", false, "Disable active HTTP validation; rely on Shodan banners and AI analysis only")
	rootCmd.Flags().DurationVar(&validateTimeout, "validate-timeout", 8*time.Second, "Timeout per active HTTP validation attempt")
	rootCmd.Flags().StringVar(&loginCredential, "login-credential", "", "Authorized single credential to try after Rod detects a login wall, format user:pass (or CAMSCAN_LOGIN_CREDENTIAL)")
	rootCmd.Flags().BoolVar(&authorizedLogin, "authorized-login-test", false, "Confirm you are authorized to test the supplied credential on every scan target")
	rootCmd.Flags().BoolVar(&testDefaultCreds, "test-default-creds", false, "Automatically test known vendor default credentials when a login page is detected (requires --authorized-login-test)")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// isShodanDork returns true if the input looks like a raw Shodan query (contains filters).
func isShodanDork(input string) bool {
	filters := []string{"title:", "product:", "server:", "port:", "country:", "city:", "state:",
		"org:", "net:", "os:", "http.title:", "http.html:", "http.status:", "ssl:",
		"has_ssl:", "hostname:", "isp:", "asn:", "before:", "after:"}
	lower := strings.ToLower(input)
	for _, f := range filters {
		if strings.Contains(lower, f) {
			return true
		}
	}
	// Also check for quoted exact-match strings (common in Shodan dorks)
	if strings.Count(input, "\"") >= 2 {
		return true
	}
	return false
}

func parseLoginCredential(raw string) (validator.Credentials, error) {
	raw = strings.TrimSpace(raw)
	user, pass, ok := strings.Cut(raw, ":")
	user = strings.TrimSpace(user)
	if !ok || user == "" || pass == "" {
		return validator.Credentials{}, fmt.Errorf("login credential must use user:pass format")
	}
	return validator.Credentials{Username: user, Password: pass}, nil
}

func runScan(cmd *cobra.Command, args []string) error {
	// W5: In daemon mode, disable color output for clean systemd journal
	if daemon {
		color.NoColor = true
	}

	// Banner (skip in daemon mode for cleaner logs)
	if !daemon {
		printBanner()
	} else {
		log.Printf("CamScan %s starting in daemon mode", Version)
	}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	// Validate Minimax key if AI analysis is requested
	if !noAI {
		if err := cfg.ValidateMinimaxKey(); err != nil {
			return err
		}
	}

	// Validate: either --query or --country must be provided
	if rawQuery == "" && country == "" {
		return fmt.Errorf("either --country (-c) or --query (-q) is required")
	}
	if country != "" && len(country) != 2 {
		return fmt.Errorf("country must be a 2-letter code (e.g., IN, US, RU)")
	}

	// --passive-only overrides --validate-http
	if passiveOnly {
		validateHTTP = false
	}

	credentialValue := loginCredential
	if credentialValue == "" {
		credentialValue = os.Getenv("CAMSCAN_LOGIN_CREDENTIAL")
	}
	var loginCred *validator.Credentials
	if credentialValue != "" {
		if !validateHTTP {
			return fmt.Errorf("--login-credential/CAMSCAN_LOGIN_CREDENTIAL requires active validation (do not use --passive-only)")
		}
		if !authorizedLogin {
			return fmt.Errorf("--login-credential requires --authorized-login-test to confirm you are authorized to test every scan target")
		}
		parsed, parseErr := parseLoginCredential(credentialValue)
		if parseErr != nil {
			return parseErr
		}
		loginCred = &parsed
	}
	if testDefaultCreds {
		if !validateHTTP {
			return fmt.Errorf("--test-default-creds requires active validation (do not use --passive-only)")
		}
		if !authorizedLogin {
			return fmt.Errorf("--test-default-creds requires --authorized-login-test to confirm you are authorized to test every scan target")
		}
	}

	// Build search query (structured mode, used when --query is not set)
	var query *shodan.SearchQuery
	if rawQuery == "" {
		query = &shodan.SearchQuery{
			CameraType: cameraType,
			Country:    strings.ToUpper(country),
			State:      state,
			City:       city,
		}
	}

	// Initialize clients
	shodanClient := shodan.NewClient(cfg.ShodanAPIKey)

	var minimaxClient *minimax.Client
	if !noAI {
		minimaxClient = minimax.NewClient(cfg.MinimaxAPIKey)
	}

	// Initialize Discord notifier (flag overrides env)
	var notifier *discord.Notifier
	wurl := webhookURL
	if wurl == "" {
		wurl = cfg.DiscordWebhookURL
	}
	if wurl != "" {
		notifier = discord.NewNotifier(wurl)
	}

	// Start the real-time dashboard
	hub := dashboard.NewHub()
	dashServer := dashboard.NewServer(hub, 9847)
	dashServer.Start()

	// Log component status
	if !daemon {
		dim := color.New(color.FgHiBlack)
		green := color.New(color.FgGreen)
		dim.Println("┌─────────────────────────────────────────────────┐")
		if rawQuery != "" {
			dim.Printf("│  %-47s│\n", fmt.Sprintf("Query: %s", rawQuery))
		} else {
			dim.Printf("│  %-47s│\n", fmt.Sprintf("Country: %s  Limit: %d  Type: %s", strings.ToUpper(country), limit, func() string {
				if cameraType == "" {
					return "default"
				}
				return cameraType
			}()))
		}
		dim.Printf("│  %-47s│\n", "Shodan:    ✓ connected")
		if noAI {
			dim.Printf("│  %-47s│\n", "Minimax:   ✗ disabled (--no-ai)")
		} else {
			dim.Printf("│  %-47s│\n", "Minimax:   ✓ M2.7 engine")
		}
		if notifier != nil {
			dim.Printf("│  %-47s│\n", "Discord:   ✓ alerts enabled")
		} else {
			dim.Printf("│  %-47s│\n", "Discord:   ✗ no webhook configured")
		}
		if validateHTTP {
			dim.Printf("│  %-47s│\n", fmt.Sprintf("Validate:  ✓ Rod HTTP (%s)", validateTimeout))
			if loginCred != nil {
				dim.Printf("│  %-47s│\n", "LoginTest: ✓ one supplied credential")
			}
			if testDefaultCreds {
				dim.Printf("│  %-47s│\n", "DefCreds:  ✓ vendor defaults enabled")
			}
		} else {
			dim.Printf("│  %-47s│\n", "Validate:  ✗ passive only (--passive-only)")
		}
		dim.Printf("│  %-47s│\n", "Dashboard: ✓ http://localhost:9847")
		if outputFile != "" {
			dim.Printf("│  %-47s│\n", fmt.Sprintf("SaveFile:  ✓ %s (append)", outputFile))
		}
		dim.Println("└─────────────────────────────────────────────────┘")
		_ = green // suppress unused
	}

	// Run analysis
	var analyzerOpts []analyzer.Option
	if validateHTTP {
		var validatorOpts []validator.Option
		if loginCred != nil {
			validatorOpts = append(validatorOpts, validator.WithCredentials(*loginCred))
		}
		httpValidator := validator.NewHTTPValidator(validateTimeout, validatorOpts...)
		defer httpValidator.Close()
		analyzerOpts = append(analyzerOpts, analyzer.WithHTTPValidator(httpValidator))
	}
	if testDefaultCreds {
		analyzerOpts = append(analyzerOpts, analyzer.WithDefaultCredsTesting(true))
	}
	a := analyzer.New(shodanClient, minimaxClient, notifier, hub, noAI, analyzerOpts...)

	// Determine output format
	format := output.FormatTable
	if strings.ToLower(outputFmt) == "json" {
		format = output.FormatJSON
	}

	// I2: Create a context with signal-based cancellation
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Handle --query mode: AI-generated or raw Shodan query
	if rawQuery != "" {
		resolvedQuery := rawQuery

		// If it looks like natural language (not a Shodan dork), use AI to generate the query
		if !isShodanDork(rawQuery) && !noAI && minimaxClient != nil {
			fmt.Println()
			color.New(color.FgCyan, color.Bold).Println("  🤖 AI QUERY GENERATION")
			color.New(color.FgHiBlack).Printf("  └─ Translating: %q\n", rawQuery)

			generated, genErr := minimaxClient.GenerateQuery(ctx, rawQuery, "")
			if genErr != nil {
				return fmt.Errorf("AI query generation failed: %w", genErr)
			}
			resolvedQuery = generated
			color.New(color.FgGreen).Printf("  ✓ Generated: %s\n", resolvedQuery)
		}

		if daemon {
			return runDaemonRaw(ctx, a, resolvedQuery, format)
		}
		return runOnceRaw(ctx, a, resolvedQuery, format)
	}

	// Structured query mode (--country based)
	if daemon {
		return runDaemon(ctx, a, query, format)
	}

	return runOnce(ctx, a, query, format)
}

func runOnce(ctx context.Context, a *analyzer.Analyzer, query *shodan.SearchQuery, format output.Format) error {
	results, total, err := a.Run(ctx, query, limit)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		return nil
	}

	output.Render(results, total, format, verbose)
	if outputFile != "" {
		if ferr := output.RenderToFile(results, total, outputFile); ferr != nil {
			log.Printf("  ⚠ File output error: %v", ferr)
		}
	}
	return nil
}

// seenCache tracks recently-alerted camera IPs to prevent duplicate notifications.
// W1: Prevents daemon mode from re-alerting the same IP:port every cycle.
type seenCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
}

func newSeenCache(ttl time.Duration) *seenCache {
	return &seenCache{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// MarkSeen records an IP:port as recently seen. Returns true if it was already seen (not expired).
func (c *seenCache) MarkSeen(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if t, ok := c.seen[key]; ok {
		if time.Since(t) < c.ttl {
			return true // Already seen and not expired
		}
	}
	c.seen[key] = time.Now()
	return false
}

// Prune removes expired entries to prevent memory growth.
func (c *seenCache) Prune() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, t := range c.seen {
		if time.Since(t) >= c.ttl {
			delete(c.seen, k)
		}
	}
}

func runDaemon(ctx context.Context, a *analyzer.Analyzer, query *shodan.SearchQuery, format output.Format) error {
	var duration time.Duration
	var periodic bool

	if interval != "0" {
		var err error
		duration, err = time.ParseDuration(interval)
		if err != nil {
			return fmt.Errorf("invalid interval %q: %w", interval, err)
		}
		periodic = true
	}

	log.Println("┌─────────────────────────────────────────────────┐")
	if periodic {
		log.Printf("│  DAEMON MODE — scanning every %-18s│", duration)
	} else {
		log.Printf("│  DAEMON MODE — single scan + dashboard          │")
	}
	log.Printf("│  Query:  %-39s│", query.BuildQuery())
	log.Printf("│  Limit:  %-39d│", limit)
	log.Printf("│  Dashboard: http://localhost:%-20s│", "9847")
	log.Println("└─────────────────────────────────────────────────┘")

	// W1: Cache with 24h TTL — won't re-alert the same IP within a day
	cache := newSeenCache(24 * time.Hour)

	// Run initial scan
	log.Println()
	log.Printf("━━━ SCAN #1 ━━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", time.Now().Format("2006-01-02 15:04:05"))

	scanStart := time.Now()
	results, total, scanErr := a.Run(ctx, query, limit)
	if scanErr != nil {
		log.Printf("  ✗ Initial scan failed after %s: %v", time.Since(scanStart).Round(time.Second), scanErr)
	} else {
		var newResults []analyzer.Result
		for _, r := range results {
			key := fmt.Sprintf("%s:%d", r.Camera.IP, r.Camera.Port)
			if !cache.MarkSeen(key) {
				newResults = append(newResults, r)
			}
		}
		if len(newResults) > 0 {
			log.Printf("  ├─ Cameras found: %d / Total in Shodan: %d", len(newResults), total)
			output.Render(newResults, total, format, verbose)
			if outputFile != "" {
				if ferr := output.RenderToFile(newResults, total, outputFile); ferr != nil {
					log.Printf("  ⚠ File output error: %v", ferr)
				}
			}
		} else {
			log.Printf("  └─ No cameras found")
		}
	}

	// If no periodic interval, keep dashboard alive and wait for shutdown
	if !periodic {
		log.Println()
		log.Println("  📊 Dashboard is live — waiting for shutdown signal (Ctrl+C / SIGTERM)")
		<-ctx.Done()
		log.Println()
		log.Println("┌─────────────────────────────────────────────────┐")
		log.Println("│  SHUTTING DOWN GRACEFULLY                       │")
		log.Println("└─────────────────────────────────────────────────┘")
		return nil
	}

	// Periodic mode — continue scanning on interval
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	scanNum := 2
	for {
		nextAt := time.Now().Add(duration).Format("15:04:05")
		log.Printf("  ⏰ Next scan at %s (in %s)", nextAt, duration)

		select {
		case <-ctx.Done():
			log.Println()
			log.Println("┌─────────────────────────────────────────────────┐")
			log.Println("│  SHUTTING DOWN GRACEFULLY                       │")
			log.Printf("│  Completed %d scan cycles                        │", scanNum-1)
			log.Println("└─────────────────────────────────────────────────┘")
			return nil
		case <-ticker.C:
			// next scan
		}

		log.Println()
		log.Printf("━━━ SCAN #%d ━━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", scanNum, time.Now().Format("2006-01-02 15:04:05"))

		scanStart = time.Now()
		results, total, scanErr = a.Run(ctx, query, limit)
		if scanErr != nil {
			log.Printf("  ✗ Scan #%d failed after %s: %v", scanNum, time.Since(scanStart).Round(time.Second), scanErr)
		} else {
			var newResults []analyzer.Result
			skipped := 0
			for _, r := range results {
				key := fmt.Sprintf("%s:%d", r.Camera.IP, r.Camera.Port)
				if cache.MarkSeen(key) {
					skipped++
					continue
				}
				newResults = append(newResults, r)
			}

			if skipped > 0 {
				log.Printf("  ├─ Skipped %d already-seen cameras (24h dedup)", skipped)
			}

			if len(newResults) > 0 {
				log.Printf("  ├─ New cameras: %d / Total in Shodan: %d", len(newResults), total)
				output.Render(newResults, total, format, verbose)
				if outputFile != "" {
					if ferr := output.RenderToFile(newResults, total, outputFile); ferr != nil {
						log.Printf("  ⚠ File output error: %v", ferr)
					}
				}
			} else {
				log.Printf("  └─ No new cameras found this cycle")
			}
		}

		cache.Prune()
		scanNum++
	}
}

func printBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	dim := color.New(color.FgHiBlack)

	cyan.Println(`
   ____                ____                  
  / ___|__ _ _ __ ___ / ___|  ___ __ _ _ __  
 | |   / _  |  _   _ \___ \ / __/ _  |  _ \ 
 | |__| (_| | | | | | |___) | (_| (_| | | | |
  \____\__,_|_| |_| |_|____/ \___\__,_|_| |_|`)
	dim.Println("  IP Camera Security Scanner — Shodan + Minimax M2.7")
	dim.Printf("  Version %s — https://github.com/xalgord/camscan\n", Version)
	fmt.Println()
}

func runOnceRaw(ctx context.Context, a *analyzer.Analyzer, rawQuery string, format output.Format) error {
	results, total, err := a.RunWithRawQuery(ctx, rawQuery, limit)
	if err != nil {
		return err
	}

	if len(results) == 0 {
		return nil
	}

	output.Render(results, total, format, verbose)
	if outputFile != "" {
		if ferr := output.RenderToFile(results, total, outputFile); ferr != nil {
			log.Printf("  ⚠ File output error: %v", ferr)
		}
	}
	return nil
}

func runDaemonRaw(ctx context.Context, a *analyzer.Analyzer, rawQuery string, format output.Format) error {
	var duration time.Duration
	var periodic bool

	if interval != "0" {
		var err error
		duration, err = time.ParseDuration(interval)
		if err != nil {
			return fmt.Errorf("invalid interval %q: %w", interval, err)
		}
		periodic = true
	}

	log.Println("┌─────────────────────────────────────────────────┐")
	if periodic {
		log.Printf("│  DAEMON MODE — scanning every %-18s│", duration)
	} else {
		log.Printf("│  DAEMON MODE — single scan + dashboard          │")
	}
	log.Printf("│  Query:  %-39s│", rawQuery)
	log.Printf("│  Limit:  %-39d│", limit)
	log.Printf("│  Dashboard: http://localhost:%-20s│", "9847")
	log.Println("└─────────────────────────────────────────────────┘")

	// W1: Cache with 24h TTL — won't re-alert the same IP within a day
	cache := newSeenCache(24 * time.Hour)

	// Run initial scan
	log.Println()
	log.Printf("━━━ SCAN #1 ━━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", time.Now().Format("2006-01-02 15:04:05"))

	scanStart := time.Now()
	results, total, scanErr := a.RunWithRawQuery(ctx, rawQuery, limit)
	if scanErr != nil {
		log.Printf("  ✗ Initial scan failed after %s: %v", time.Since(scanStart).Round(time.Second), scanErr)
	} else {
		var newResults []analyzer.Result
		for _, r := range results {
			key := fmt.Sprintf("%s:%d", r.Camera.IP, r.Camera.Port)
			if !cache.MarkSeen(key) {
				newResults = append(newResults, r)
			}
		}
		if len(newResults) > 0 {
			log.Printf("  ├─ Cameras found: %d / Total in Shodan: %d", len(newResults), total)
			output.Render(newResults, total, format, verbose)
			if outputFile != "" {
				if ferr := output.RenderToFile(newResults, total, outputFile); ferr != nil {
					log.Printf("  ⚠ File output error: %v", ferr)
				}
			}
		} else {
			log.Printf("  └─ No cameras found")
		}
	}

	// If no periodic interval, keep dashboard alive and wait for shutdown
	if !periodic {
		log.Println()
		log.Println("  📊 Dashboard is live — waiting for shutdown signal (Ctrl+C / SIGTERM)")
		<-ctx.Done()
		log.Println()
		log.Println("┌─────────────────────────────────────────────────┐")
		log.Println("│  SHUTTING DOWN GRACEFULLY                       │")
		log.Println("└─────────────────────────────────────────────────┘")
		return nil
	}

	// Periodic mode — continue scanning on interval
	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	scanNum := 2
	for {
		nextAt := time.Now().Add(duration).Format("15:04:05")
		log.Printf("  ⏰ Next scan at %s (in %s)", nextAt, duration)

		select {
		case <-ctx.Done():
			log.Println()
			log.Println("┌─────────────────────────────────────────────────┐")
			log.Println("│  SHUTTING DOWN GRACEFULLY                       │")
			log.Printf("│  Completed %d scan cycles                        │", scanNum-1)
			log.Println("└─────────────────────────────────────────────────┘")
			return nil
		case <-ticker.C:
			// next scan
		}

		log.Println()
		log.Printf("━━━ SCAN #%d ━━━ %s ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", scanNum, time.Now().Format("2006-01-02 15:04:05"))

		scanStart = time.Now()
		results, total, scanErr = a.RunWithRawQuery(ctx, rawQuery, limit)
		if scanErr != nil {
			log.Printf("  ✗ Scan #%d failed after %s: %v", scanNum, time.Since(scanStart).Round(time.Second), scanErr)
		} else {
			var newResults []analyzer.Result
			skipped := 0
			for _, r := range results {
				key := fmt.Sprintf("%s:%d", r.Camera.IP, r.Camera.Port)
				if cache.MarkSeen(key) {
					skipped++
					continue
				}
				newResults = append(newResults, r)
			}

			if skipped > 0 {
				log.Printf("  ├─ Skipped %d already-seen cameras (24h dedup)", skipped)
			}

			if len(newResults) > 0 {
				log.Printf("  ├─ New cameras: %d / Total in Shodan: %d", len(newResults), total)
				output.Render(newResults, total, format, verbose)
				if outputFile != "" {
					if ferr := output.RenderToFile(newResults, total, outputFile); ferr != nil {
						log.Printf("  ⚠ File output error: %v", ferr)
					}
				}
			} else {
				log.Printf("  └─ No new cameras found this cycle")
			}
		}

		cache.Prune()
		scanNum++
	}
}
