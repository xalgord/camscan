package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

var purge bool

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Remove CamScan systemd service",
	Long: `Removes the CamScan systemd service and optionally purges all config.

By default, keeps /etc/camscan/ (your API keys) and /var/log/camscan/.
Use --purge to remove everything.`,
	Example: `  sudo camscan uninstall
  sudo camscan uninstall --purge`,
	RunE: runUninstall,
}

func init() {
	uninstallCmd.Flags().BoolVar(&purge, "purge", false, "Also remove config and log files")
	rootCmd.AddCommand(uninstallCmd)
}

func runUninstall(cmd *cobra.Command, args []string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this command must be run as root: sudo camscan uninstall")
	}

	fmt.Println("🗑  Removing CamScan service...")

	// Stop and disable service
	exec.Command("systemctl", "stop", "camscan").Run()
	exec.Command("systemctl", "disable", "camscan").Run()

	// Remove unit file
	unitPath := "/etc/systemd/system/camscan.service"
	if _, err := os.Stat(unitPath); err == nil {
		fmt.Printf("  → Removing %s\n", unitPath)
		os.Remove(unitPath)
	}

	exec.Command("systemctl", "daemon-reload").Run()

	// Remove binary (only from /usr/local/bin, not go/bin)
	binPath := "/usr/local/bin/camscan"
	if _, err := os.Stat(binPath); err == nil {
		fmt.Printf("  → Removing %s\n", binPath)
		os.Remove(binPath)
	}

	if purge {
		fmt.Println("  → Purging /etc/camscan/")
		os.RemoveAll("/etc/camscan")

		fmt.Println("  → Purging /var/log/camscan/")
		os.RemoveAll("/var/log/camscan")
	} else {
		fmt.Println("  → Keeping /etc/camscan/ and /var/log/camscan/ (use --purge to remove)")
	}

	fmt.Println()
	fmt.Println("✅ CamScan service removed.")
	return nil
}
