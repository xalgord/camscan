package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xalgord/camscan/config"
	"github.com/xalgord/camscan/internal/analyzer"
	"github.com/xalgord/camscan/internal/discord"
	"github.com/xalgord/camscan/internal/minimax"
	"github.com/xalgord/camscan/internal/output"
	"github.com/xalgord/camscan/internal/shodan"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "dev"

var (
	country    string
	state      string
	city       string
	cameraType string
	limit      int
	outputFmt  string
	verbose    bool
	noAI       bool
	webhookURL string
	daemon     bool
	interval   string
)

var rootCmd = &cobra.Command{
	Use:   "camscan",
	Short: "IP Camera Security Scanner",
	Long: `CamScan discovers IP cameras via Shodan and uses Minimax M2.7 AI
to assess their security posture.

Supports filtering by country, state, city, and camera type.
All analysis is passive — no connections are made to discovered devices.`,
	Example: `  camscan --country IN --limit 10
  camscan --country US --city "New York" --type hikvision
  camscan -c RU --city Moscow -v --limit 5
  camscan --country JP --no-ai --output json
  camscan --country IN --daemon --interval 30m --webhook https://discord.com/api/webhooks/...`,
	RunE:    runScan,
	Version: Version,
}

func init() {
	rootCmd.Flags().StringVarP(&country, "country", "c", "", "2-letter country code (e.g., IN, US, RU)")
	rootCmd.Flags().StringVarP(&state, "state", "s", "", "State or region name")
	rootCmd.Flags().StringVar(&city, "city", "", "City name")
	rootCmd.Flags().StringVarP(&cameraType, "type", "t", "", "Camera type: hikvision, dahua, axis, rtsp, dvr, nvr, avtech, geovision, webcamxp, yawcam, blueiris, all (default: broad CCTV search)")
	rootCmd.Flags().IntVarP(&limit, "limit", "l", 25, "Maximum number of results")
	rootCmd.Flags().StringVarP(&outputFmt, "output", "o", "table", "Output format: table, json")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Show detailed results with full banner data")
	rootCmd.Flags().BoolVar(&noAI, "no-ai", false, "Skip Minimax AI analysis, show Shodan results only")
	rootCmd.Flags().StringVar(&webhookURL, "webhook", "", "Discord webhook URL for alerts (overrides DISCORD_WEBHOOK_URL env)")
	rootCmd.Flags().BoolVar(&daemon, "daemon", false, "Run continuously in daemon mode (for systemd)")
	rootCmd.Flags().StringVar(&interval, "interval", "30m", "Scan interval in daemon mode (e.g., 15m, 1h, 2h30m)")

	rootCmd.MarkFlagRequired("country")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
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

	// Validate country code
	if len(country) != 2 {
		return fmt.Errorf("country must be a 2-letter code (e.g., IN, US, RU)")
	}

	// Build search query
	query := &shodan.SearchQuery{
		CameraType: cameraType,
		Country:    strings.ToUpper(country),
		State:      state,
		City:       city,
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
		log.Println("Discord alerts enabled")
	}

	// Run analysis
	a := analyzer.New(shodanClient, minimaxClient, notifier, noAI)

	// Determine output format
	format := output.FormatTable
	if strings.ToLower(outputFmt) == "json" {
		format = output.FormatJSON
	}

	// I2: Create a context with signal-based cancellation
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Single run or daemon mode
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
	duration, err := time.ParseDuration(interval)
	if err != nil {
		return fmt.Errorf("invalid interval %q: %w", interval, err)
	}

	log.Printf("Daemon mode — scanning every %s", duration)

	// W1: Cache with 24h TTL — won't re-alert the same IP within a day
	cache := newSeenCache(24 * time.Hour)

	ticker := time.NewTicker(duration)
	defer ticker.Stop()

	scanNum := 1
	for {
		log.Printf("--- Scan #%d starting at %s ---", scanNum, time.Now().Format("2006-01-02 15:04:05"))

		results, total, scanErr := a.Run(ctx, query, limit)
		if scanErr != nil {
			log.Printf("Scan #%d failed: %v", scanNum, scanErr)
		} else {
			// W1: Filter out previously seen results before output
			var newResults []analyzer.Result
			for _, r := range results {
				key := fmt.Sprintf("%s:%d", r.Camera.IP, r.Camera.Port)
				if cache.MarkSeen(key) {
					log.Printf("  Skipping already-seen: %s", key)
					continue
				}
				newResults = append(newResults, r)
			}

			if len(newResults) > 0 {
				output.Render(newResults, total, format, verbose)
			} else {
				log.Printf("  No new cameras found this cycle")
			}
		}

		// Periodically prune the cache
		cache.Prune()
		scanNum++

		log.Printf("Next scan at %s", time.Now().Add(duration).Format("15:04:05"))

		select {
		case <-ctx.Done():
			log.Println("Shutting down gracefully...")
			return nil
		case <-ticker.C:
			// next iteration
		}
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
