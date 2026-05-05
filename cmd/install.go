package cmd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var installUser string

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install CamScan as a systemd service",
	Long: `Installs CamScan as a production systemd service.

This command will:
  1. Copy the binary to /usr/local/bin/camscan
  2. Create /etc/camscan/camscan.env with API key placeholders
  3. Create /var/log/camscan/ for logs
  4. Install a systemd unit file
  5. Enable the service to start on boot

Must be run as root (sudo camscan install).`,
	Example: `  sudo camscan install
  sudo camscan install --user deploy`,
	RunE: runInstall,
}

func init() {
	installCmd.Flags().StringVar(&installUser, "user", "root", "System user to run the service as")
	rootCmd.AddCommand(installCmd)
}

const serviceTemplate = `[Unit]
Description=CamScan — IP Camera Security Scanner
Documentation=https://github.com/xalgord/camscan
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
EnvironmentFile=/etc/camscan/camscan.env
ExecStart=/usr/local/bin/camscan $CAMSCAN_ARGS
Restart=on-failure
RestartSec=30
StartLimitIntervalSec=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/log/camscan

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=camscan

[Install]
WantedBy=multi-user.target
`

const envTemplate = `# CamScan Environment Configuration
# Edit this file with your real API keys before starting the service.

# Required: Shodan API key for camera discovery
SHODAN_API_KEY=your_shodan_api_key_here

# Required: Minimax API key for AI security analysis
MINIMAX_API_KEY=your_minimax_api_key_here

# Optional: Discord webhook for real-time alerts
DISCORD_WEBHOOK_URL=

# Scan arguments — customize what the daemon scans
# These args are passed directly to the camscan binary by systemd
CAMSCAN_ARGS=--country IN --daemon --interval 30m --limit 50 --type all
`

func runInstall(cmd *cobra.Command, args []string) error {
	// Must be root
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root: sudo camscan install")
	}

	// Validate user exists
	if _, err := user.Lookup(installUser); err != nil {
		return fmt.Errorf("user %q not found: %w", installUser, err)
	}

	fmt.Println("🔧 Installing CamScan as a systemd service...")
	fmt.Println()

	// 1. Copy binary to /usr/local/bin
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot find own binary: %w", err)
	}
	selfPath, _ = filepath.EvalSymlinks(selfPath)

	dst := "/usr/local/bin/camscan"
	if selfPath != dst {
		fmt.Printf("  → Copying binary to %s\n", dst)
		input, err := os.ReadFile(selfPath)
		if err != nil {
			return fmt.Errorf("read binary: %w", err)
		}
		if err := os.WriteFile(dst, input, 0755); err != nil {
			return fmt.Errorf("write binary: %w", err)
		}
	} else {
		fmt.Printf("  → Binary already at %s\n", dst)
	}

	// 2. Create env config
	envPath := "/etc/camscan/camscan.env"
	if _, err := os.Stat(envPath); os.IsNotExist(err) {
		fmt.Printf("  → Creating %s\n", envPath)
		if err := os.MkdirAll("/etc/camscan", 0755); err != nil {
			return err
		}
		if err := os.WriteFile(envPath, []byte(envTemplate), 0600); err != nil {
			return err
		}
	} else {
		fmt.Printf("  → %s already exists, skipping\n", envPath)
	}

	// 3. Create log directory
	logDir := "/var/log/camscan"
	fmt.Printf("  → Creating %s\n", logDir)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}
	// chown to service user
	if u, err := user.Lookup(installUser); err == nil {
		chownCmd := exec.Command("chown", "-R", u.Uid+":"+u.Gid, logDir)
		chownCmd.Run()
	}

	// 4. Install systemd unit
	unitPath := "/etc/systemd/system/camscan.service"
	fmt.Printf("  → Writing %s (User=%s)\n", unitPath, installUser)
	unit := fmt.Sprintf(serviceTemplate, installUser, installUser)
	if err := os.WriteFile(unitPath, []byte(unit), 0644); err != nil {
		return err
	}

	// 5. Reload systemd and enable
	fmt.Println("  → Reloading systemd daemon")
	exec.Command("systemctl", "daemon-reload").Run()

	fmt.Println("  → Enabling camscan.service")
	exec.Command("systemctl", "enable", "camscan").Run()

	fmt.Println()
	fmt.Println("✅ CamScan service installed!")
	fmt.Println()
	fmt.Println(strings.Repeat("─", 50))
	fmt.Println("Next steps:")
	fmt.Println()
	fmt.Printf("  1. Edit API keys:     sudo nano %s\n", envPath)
	fmt.Println("  2. Start the service: sudo systemctl start camscan")
	fmt.Println("  3. Check status:      sudo systemctl status camscan")
	fmt.Println("  4. View logs:         journalctl -u camscan -f")
	fmt.Println("  5. Dashboard:         http://localhost:9847")
	fmt.Println(strings.Repeat("─", 50))

	// Check if env still has placeholders
	envData, _ := os.ReadFile(envPath)
	if strings.Contains(string(envData), "your_shodan_api_key_here") {
		log.Println()
		log.Println("⚠  WARNING: /etc/camscan/camscan.env still has placeholder keys!")
		log.Println("   Edit it before starting the service.")
	}

	return nil
}
