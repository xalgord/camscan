<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.21+">
  <img src="https://img.shields.io/badge/Shodan-API-C63A16?style=for-the-badge&logo=shodan&logoColor=white" alt="Shodan">
  <img src="https://img.shields.io/badge/Minimax-M2.7_AI-7B61FF?style=for-the-badge" alt="Minimax M2.7">
  <img src="https://img.shields.io/badge/Discord-Webhooks-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
</p>

<h1 align="center">CamScan</h1>

<p align="center">
  <b>CCTV & IP Camera Security Scanner — Discover, Analyze, Alert</b><br>
  Enumerate IP cameras via <a href="https://shodan.io">Shodan</a> and assess their security posture with <a href="https://platform.minimax.io/">Minimax M2.7</a> AI.
</p>

```
   ____                ____
  / ___|__ _ _ __ ___ / ___|  ___ __ _ _ __
 | |   / _` | '_ ` _ \\___ \ / __/ _` | '_ \
 | |__| (_| | | | | | |___) | (_| (_| | | | |
  \____\__,_|_| |_| |_|____/ \___\__,_|_| |_|
```

---

## Features

| Feature | Description |
|---|---|
| 🔍 **Shodan Discovery** | Find CCTV & IP cameras by country, state, or city |
| 🤖 **AI Security Analysis** | Minimax M2.7 evaluates each camera's security posture passively |
| 🔔 **Discord Alerts** | Real-time webhook notifications for High/Critical risk cameras with default credentials |
| 🔄 **Daemon Mode** | Run as a 24/7 systemd service with configurable scan intervals |
| 🛡️ **Deduplication** | In-memory 24h TTL cache prevents duplicate alerts across scan cycles |
| 🎯 **Camera Type Filters** | Hikvision, Dahua, Axis, DVR, NVR, AVTech, GeoVision, RTSP, and more |
| 📊 **Risk Scoring** | Color-coded risk levels — Critical, High, Medium, Low |
| 📦 **Output Formats** | Pretty table or JSON |
| ⚡ **Concurrent Analysis** | Parallel AI processing with built-in rate limiting |
| 🔁 **Resilient Retries** | Exponential backoff with `Retry-After` handling for all APIs |

---

## Quick Start

### Prerequisites

- **Go 1.21+**
- [Shodan API Key](https://account.shodan.io/) (paid membership recommended for search)
- [Minimax API Key](https://platform.minimax.io/) (Token Plan or Pay-As-You-Go)
- [Discord Webhook](https://support.discord.com/hc/en-us/articles/228383668) (optional, for alerts)

### Install

**One-liner** (requires Go 1.21+):

```bash
go install github.com/xalgord/camscan@latest
```

**From source:**

```bash
git clone https://github.com/xalgord/camscan.git
cd camscan
go build -ldflags "-X github.com/xalgord/camscan/cmd.Version=1.0.0" -o camscan .
```

### Configure

Set your API keys as environment variables:

```bash
export SHODAN_API_KEY="your_shodan_key"
export MINIMAX_API_KEY="your_minimax_key"
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."  # optional
```

Or copy the example env file:

```bash
cp .env.example .env
# Edit .env with your keys — sourced automatically if present
```

---

## Usage

### Basic Scans

```bash
# Scan CCTV cameras in India (default: broad CCTV search, limit 25)
camscan --country IN

# Scan Hikvision cameras in Mumbai
camscan --country IN --city Mumbai --type hikvision

# Scan DVR/NVR devices in Delhi
camscan --country IN --city Delhi --type dvr

# Scan RTSP streams in California, limit 10
camscan --country US --state California --type rtsp --limit 10

# Scan all camera types in Germany
camscan --country DE --type all --limit 15
```

### Output Options

```bash
# JSON output
camscan --country JP --output json

# Verbose mode with full banner data
camscan --country DE --city Berlin -v --limit 5

# Skip AI analysis, raw Shodan results only
camscan --country RU --no-ai
```

### Discord Alerts

```bash
# Send alerts for critical/high-risk cameras to Discord
camscan --country IN --webhook https://discord.com/api/webhooks/...

# Or set it via environment variable
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
camscan --country IN
```

### Daemon Mode (24/7 Monitoring)

```bash
# Run continuously, scan every 30 minutes
camscan --country IN --daemon --interval 30m

# Custom interval with Discord alerts
camscan --country US --type hikvision --daemon --interval 1h \
  --webhook https://discord.com/api/webhooks/...
```

In daemon mode:
- ANSI colors and emojis are disabled for clean `journald` output
- A deduplication cache prevents re-alerting the same camera within 24 hours
- Shodan credits are checked before each scan cycle
- Graceful shutdown on `SIGINT`/`SIGTERM`

---

## CLI Reference

### Flags

| Flag | Short | Description | Default |
|---|---|---|---|
| `--country` | `-c` | 2-letter country code (**required**) | — |
| `--state` | `-s` | State or region name | — |
| `--city` | | City name | — |
| `--type` | `-t` | Camera type filter (see below) | broad CCTV |
| `--limit` | `-l` | Max results per scan | `25` |
| `--output` | `-o` | Output format: `table`, `json` | `table` |
| `--verbose` | `-v` | Show detailed results with full banner | `false` |
| `--no-ai` | | Skip Minimax AI analysis | `false` |
| `--webhook` | | Discord webhook URL (overrides `DISCORD_WEBHOOK_URL` env) | — |
| `--daemon` | | Run continuously in daemon mode | `false` |
| `--interval` | | Scan interval in daemon mode | `30m` |
| `--version` | | Print version and exit | — |

### Camera Types

| Type | Search Query |
|---|---|
| *(default)* | Broad CCTV — IP Camera, Network Camera, DVR, NVR, Hikvision, Dahua |
| `hikvision` | Hikvision IP cameras |
| `dahua` | Dahua cameras |
| `axis` | AXIS network cameras |
| `dvr` | Digital video recorders |
| `nvr` | Network video recorders |
| `avtech` | AVTech DVR systems |
| `geovision` | GeoVision surveillance |
| `rtsp` | RTSP streaming devices |
| `webcamxp` | WebcamXP servers |
| `yawcam` | Yawcam devices |
| `blueiris` | Blue Iris surveillance |
| `all` | All camera types combined |

### Environment Variables

| Variable | Required | Description |
|---|---|---|
| `SHODAN_API_KEY` | ✅ | Shodan API key for camera discovery |
| `MINIMAX_API_KEY` | ✅ | Minimax API key for AI security analysis |
| `DISCORD_WEBHOOK_URL` | ❌ | Discord webhook for real-time alerts |
| `CAMSCAN_ARGS` | ❌ | CLI arguments for systemd daemon mode |

---

## Example Output

```
🔍 Searching Shodan: (title:"IP Camera" OR title:"DVR" ...) country:IN city:"Mumbai"
✓  Found 25 cameras (total in Shodan: 142)
🤖 Analyzing 25 cameras with Minimax M2.7...

┌────┬─────────────────┬──────┬──────────────┬───────────┬──────────────────────────────┐
│ #  │ IP              │ Port │ Product      │ Risk      │ Summary                      │
├────┼─────────────────┼──────┼──────────────┼───────────┼──────────────────────────────┤
│ 1  │ 103.xx.xx.xx    │ 80   │ Hikvision    │ 🔴 CRIT  │ No auth, default admin panel  │
│ 2  │ 49.xx.xx.xx     │ 554  │ RTSP Stream  │ 🟠 HIGH  │ Open RTSP, no credentials    │
│ 3  │ 122.xx.xx.xx    │ 8080 │ Dahua        │ 🟡 MED   │ Outdated firmware detected   │
│ 4  │ 14.xx.xx.xx     │ 443  │ Axis Camera  │ 🟢 LOW   │ TLS enabled, auth required   │
└────┴─────────────────┴──────┴──────────────┴───────────┴──────────────────────────────┘

📊 Summary: 1 Critical | 1 High | 1 Medium | 1 Low | Total in Shodan: 142
```

---

## Deploying as a systemd Service

CamScan can run as a hardened systemd service for continuous monitoring.

### 1. Build and Install

```bash
sudo ./deploy/install-service.sh
```

The install script:
- Builds the binary to `/usr/local/bin/camscan`
- Creates a `camscan` system user (or uses `$SUDO_USER`)
- Sets up `/etc/camscan/camscan.env` with `600` permissions
- Installs and enables the systemd unit

### 2. Configure

Edit the environment file:

```bash
sudo nano /etc/camscan/camscan.env
```

```bash
SHODAN_API_KEY=your_key
MINIMAX_API_KEY=your_key
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Define what to scan — these are the CLI args passed to the binary
CAMSCAN_ARGS=--country IN --type hikvision --daemon --interval 1h --limit 50
```

### 3. Start the Service

```bash
sudo systemctl start camscan
sudo systemctl status camscan

# View logs
journalctl -u camscan -f
```

### Security Hardening

The systemd unit includes these hardening directives:

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
```

---

## Architecture

```
camscan/
├── main.go                        # Entry point
├── cmd/
│   └── root.go                    # CLI flags, daemon loop, signal handling
├── config/
│   └── config.go                  # Environment variable loader
├── internal/
│   ├── shodan/
│   │   ├── client.go              # Shodan API client (search + credit check)
│   │   └── types.go               # Shodan response types
│   ├── minimax/
│   │   ├── client.go              # Minimax M2.7 AI client (retry + JSON extraction)
│   │   └── types.go               # AI request/response types
│   ├── discord/
│   │   └── notifier.go            # Discord webhook (retry + rate-limit handling)
│   ├── analyzer/
│   │   └── analyzer.go            # Orchestrator: parallel AI + sequential alerts
│   ├── output/
│   │   └── formatter.go           # Table/JSON formatters
│   ├── risk/
│   │   └── risk.go                # Shared risk display utilities
│   └── util/
│       └── util.go                # Rune-safe string truncation
└── deploy/
    ├── camscan.service             # systemd unit file
    ├── camscan.env.example         # Environment template
    └── install-service.sh          # Automated installer
```

---

## Resilience & Production Hardening

| Concern | Implementation |
|---|---|
| **Rate Limits** | Exponential backoff with `Retry-After` header support (Minimax + Discord) |
| **API Credits** | Pre-flight Shodan credit check before each scan cycle |
| **Deduplication** | Thread-safe in-memory cache with 24h TTL (daemon mode) |
| **Graceful Shutdown** | `context.Context` propagation + `SIGINT`/`SIGTERM` handling |
| **Error Isolation** | Per-camera failures don't abort the scan; errors logged, scan continues |
| **Alert Sequencing** | Discord alerts dispatched sequentially after parallel analysis completes |
| **Log Hygiene** | ANSI colors/emojis stripped in daemon mode for clean journald output |
| **JSON Safety** | Robust first-`{` / last-`}` JSON extraction from AI responses |
| **UTF-8 Safety** | Rune-aware string truncation prevents multi-byte corruption |

---

## ⚠️ Disclaimer

This tool is designed for **authorized security research and educational purposes only**.

- All analysis is **passive** — no connections are made to discovered devices
- The tool uses only publicly available Shodan data and AI-based inference
- **Do NOT** attempt to access, authenticate against, or exploit any discovered cameras
- Always comply with applicable laws and Shodan's [Terms of Service](https://www.shodan.io/tos)
- The authors are not responsible for any misuse of this tool

---

## License

[MIT](LICENSE)

## Author

**Krishna Kumar** ([@xalgord](https://github.com/xalgord))
