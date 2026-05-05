package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/xalgord/camscan/internal/analyzer"
	"github.com/xalgord/camscan/internal/risk"
	"github.com/xalgord/camscan/internal/util"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// Format controls the output style.
type Format string

const (
	FormatTable Format = "table"
	FormatJSON  Format = "json"
)

// Render outputs the results in the requested format.
func Render(results []analyzer.Result, total int, format Format, verbose bool) {
	switch format {
	case FormatJSON:
		renderJSON(results)
	default:
		renderTable(results, total, verbose)
	}
}

func renderJSON(results []analyzer.Result) {
	type jsonResult struct {
		IP         string   `json:"ip"`
		Port       int      `json:"port"`
		Product    string   `json:"product"`
		Org        string   `json:"org"`
		City       string   `json:"city"`
		Country    string   `json:"country"`
		Transport  string   `json:"transport"`
		Hostnames  []string `json:"hostnames,omitempty"`
		RiskLevel  string   `json:"risk_level,omitempty"`
		IsOpen     bool     `json:"is_open,omitempty"`
		DefaultCreds bool   `json:"default_creds,omitempty"`
		Vulns      []string `json:"vulnerabilities,omitempty"`
		Recommendations []string `json:"recommendations,omitempty"`
		Summary    string   `json:"summary,omitempty"`
		Error      string   `json:"error,omitempty"`
		Banner     string   `json:"banner,omitempty"`
	}

	out := make([]jsonResult, len(results))
	for i, r := range results {
		jr := jsonResult{
			IP:        r.Camera.IP,
			Port:      r.Camera.Port,
			Product:   r.Camera.Product,
			Org:       r.Camera.Org,
			City:      r.Camera.Location.City,
			Country:   r.Camera.Location.Country,
			Transport: r.Camera.Transport,
			Hostnames: r.Camera.Hostnames,
			Error:     r.Error,
		}
		if r.Assessment != nil {
			jr.RiskLevel = r.Assessment.RiskLevel
			jr.IsOpen = r.Assessment.IsOpen
			jr.DefaultCreds = r.Assessment.DefaultCreds
			jr.Vulns = r.Assessment.VulnTitles()
			jr.Recommendations = r.Assessment.Recommendations
			jr.Summary = r.Assessment.Summary
		}
		out[i] = jr
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

func renderTable(results []analyzer.Result, total int, verbose bool) {
	bold := color.New(color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)

	cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"#", "IP", "Port", "Product", "Location", "Risk", "Summary"})
	table.SetBorder(true)
	table.SetRowLine(false)
	table.SetAutoWrapText(true)
	table.SetColWidth(35)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderColor(
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
		tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiCyanColor},
	)

	var critCount, highCount, medCount, lowCount int

	for i, r := range results {
		product := r.Camera.Product
		if product == "" {
			product = "Unknown"
		}

		location := r.Camera.Location.City
		if location == "" {
			location = r.Camera.Location.Country
		}
		if location == "" {
			location = r.Camera.Location.CountryCode
		}

		riskStr := "—"
		summary := "—"

		if r.Error != "" {
			riskStr = "⚠ ERR"
			summary = "AI analysis failed"
		} else if r.Assessment != nil {
			riskStr = formatRisk(r.Assessment.RiskLevel)
			summary = util.Truncate(r.Assessment.Summary, 50)

			switch strings.ToLower(r.Assessment.RiskLevel) {
			case "critical":
				critCount++
			case "high":
				highCount++
			case "medium":
				medCount++
			case "low":
				lowCount++
			}
		}

		table.Append([]string{
			fmt.Sprintf("%d", i+1),
			r.Camera.IP,
			fmt.Sprintf("%d", r.Camera.Port),
			util.Truncate(product, 18),
			util.Truncate(location, 15),
			riskStr,
			summary,
		})
	}

	table.Render()

	// Summary line
	fmt.Println()
	bold.Printf("📊 Summary: ")
	if critCount > 0 {
		color.New(color.FgRed, color.Bold).Printf("%d Critical ", critCount)
	}
	if highCount > 0 {
		color.New(color.FgYellow, color.Bold).Printf("| %d High ", highCount)
	}
	if medCount > 0 {
		color.New(color.FgHiYellow).Printf("| %d Medium ", medCount)
	}
	if lowCount > 0 {
		color.New(color.FgGreen).Printf("| %d Low ", lowCount)
	}
	fmt.Printf("| Total in Shodan: %d\n", total)

	// Verbose: print full details per camera
	if verbose {
		fmt.Println()
		cyan.Println("━━━ DETAILED RESULTS ━━━")
		for i, r := range results {
			bold.Printf("\n[%d] %s:%d\n", i+1, r.Camera.IP, r.Camera.Port)
			fmt.Printf("    Product:   %s\n", r.Camera.Product)
			fmt.Printf("    Org:       %s\n", r.Camera.Org)
			fmt.Printf("    OS:        %s\n", r.Camera.OS)
			fmt.Printf("    Location:  %s, %s\n", r.Camera.Location.City, r.Camera.Location.Country)
			fmt.Printf("    Transport: %s\n", r.Camera.Transport)

			if r.Assessment != nil {
				fmt.Printf("    Risk:      %s %s\n", risk.Icon(r.Assessment.RiskLevel), r.Assessment.RiskLevel)
				fmt.Printf("    Score:     %d/100\n", r.Assessment.RiskScore)
				fmt.Printf("    Open:      %v\n", r.Assessment.IsOpen)
				fmt.Printf("    DefCreds:  %v\n", r.Assessment.DefaultCreds)

				if len(r.Assessment.Vulnerabilities) > 0 {
					fmt.Printf("    Vulns:     (%d found)\n", len(r.Assessment.Vulnerabilities))
					for _, v := range r.Assessment.Vulnerabilities {
						fmt.Printf("      • %s\n", v)
					}
				}

				if len(r.Assessment.ExploitPaths) > 0 {
					fmt.Printf("    Exploits:\n")
					for _, ep := range r.Assessment.ExploitPaths {
						fmt.Printf("      ⚔ %s\n", ep)
					}
				}

				if len(r.Assessment.CveReferences) > 0 {
					fmt.Printf("    CVEs:      %s\n", strings.Join(r.Assessment.CveReferences, ", "))
				}

				if len(r.Assessment.AccessInstructions) > 0 {
					fmt.Printf("    Access:\n")
					for j, inst := range r.Assessment.AccessInstructions {
						fmt.Printf("      %d. %s\n", j+1, inst)
					}
				}

				if len(r.Assessment.Recommendations) > 0 {
					fmt.Printf("    Fixes:\n")
					for _, rec := range r.Assessment.Recommendations {
						fmt.Printf("      → %s\n", rec)
					}
				}
			}

			if r.Error != "" {
				color.Red("    Error: %s\n", r.Error)
			}

			// Banner excerpt
			banner := r.Camera.Banner
			if len([]rune(banner)) > 300 {
				banner = string([]rune(banner)[:300]) + "..."
			}
			fmt.Printf("    Banner:    %s\n", strings.ReplaceAll(banner, "\n", "\n               "))
		}
	}

	fmt.Println()
}

func formatRisk(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return color.RedString("🔴 CRIT")
	case "high":
		return color.YellowString("🟠 HIGH")
	case "medium":
		return color.HiYellowString("🟡 MED")
	case "low":
		return color.GreenString("🟢 LOW")
	default:
		return "⚪ ???"
	}
}

// riskIcon and truncate removed — now using shared risk.Icon() and util.Truncate()
