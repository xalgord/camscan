# CamScan

**IP Camera Security Scanner** — Discover IP cameras via [Shodan](https://shodan.io) and analyze their security posture with [Minimax M2.7](https://platform.minimax.io/) AI.

```
   ____                ____
  / ___|__ _ _ __ ___ / ___|  ___ __ _ _ __
 | |   / _` | '_ ` _ \\___ \ / __/ _` | '_ \
 | |__| (_| | | | | | |___) | (_| (_| | | | |
  \____\__,_|_| |_| |_|____/ \___\__,_|_| |_|
```

## Features

- 🔍 **Shodan Discovery** — Find IP cameras by country, state, or city
- 🤖 **AI Security Analysis** — Minimax M2.7 evaluates each camera's security posture
- 🎯 **Camera Type Filters** — Hikvision, Dahua, Axis, RTSP, WebcamXP, and more
- 📊 **Risk Scoring** — Color-coded risk levels (Critical → Low)
- 📦 **Multiple Output Formats** — Pretty table or JSON
- ⚡ **Concurrent Analysis** — Parallel AI processing with rate limiting

## Prerequisites

- Go 1.21+
- [Shodan API Key](https://account.shodan.io/) (paid membership recommended)
- [Minimax API Key](https://platform.minimax.io/) (Token Plan or Pay-As-You-Go)

## Installation

```bash
git clone https://github.com/xalgord/camscan.git
cd camscan
go build -o camscan .
```

## Configuration

Copy the example env file and add your API keys:

```bash
cp .env.example .env
```

Edit `.env`:
```
SHODAN_API_KEY=your_shodan_api_key
MINIMAX_API_KEY=your_minimax_api_key
```

Or export them directly:
```bash
export SHODAN_API_KEY=your_key
export MINIMAX_API_KEY=your_key
```

## Usage

```bash
# Scan cameras in India (default: webcam type, limit 25)
./camscan --country IN

# Scan Hikvision cameras in Mumbai
./camscan --country IN --city Mumbai --type hikvision

# Scan RTSP streams in California
./camscan --country US --state California --type rtsp --limit 10

# JSON output, skip AI analysis
./camscan --country JP --no-ai --output json

# Verbose mode with full banner data
./camscan -c DE --city Berlin -v --limit 5

# Scan all camera types
./camscan --country RU --type all --limit 15
```

### Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--country` | `-c` | 2-letter country code (required) | — |
| `--state` | `-s` | State/region name | — |
| `--city` | | City name | — |
| `--type` | `-t` | Camera type filter | `webcam` |
| `--limit` | `-l` | Max results | `25` |
| `--output` | `-o` | Output format: `table`, `json` | `table` |
| `--verbose` | `-v` | Show detailed results | `false` |
| `--no-ai` | | Skip Minimax AI analysis | `false` |

### Camera Types

| Type | What it searches |
|------|-----------------|
| `webcam` | Generic webcam devices |
| `hikvision` | Hikvision IP cameras |
| `dahua` | Dahua cameras |
| `axis` | AXIS network cameras |
| `rtsp` | RTSP streaming devices |
| `webcamxp` | WebcamXP servers |
| `yawcam` | Yawcam devices |
| `blueiris` | Blue Iris surveillance |
| `all` | All camera types combined |

## Example Output

```
🔍 Searching Shodan: webcam country:IN city:"Mumbai"
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

## ⚠️ Disclaimer

This tool is designed for **authorized security research and educational purposes only**. 

- All analysis is **passive** — no connections are made to discovered devices
- The tool uses only publicly available Shodan data and AI inference
- **Do NOT** attempt to access, authenticate against, or exploit any discovered cameras
- Always comply with applicable laws and Shodan's Terms of Service
- The authors are not responsible for any misuse of this tool

## License

MIT

## Author

**Krishna Kumar** ([@xalgord](https://github.com/xalgord))
