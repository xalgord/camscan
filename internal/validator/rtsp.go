package validator

import (
	"bufio"
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/camscan/internal/shodan"
)

// RTSPProbeResult holds the result of probing an RTSP endpoint.
type RTSPProbeResult struct {
	URL            string
	Path           string
	StatusCode     int
	Server         string
	Authenticated  bool // false = open stream, true = auth required
	Accessible     bool // true if we got a genuine 200 OK with SDP body
	DefaultCreds   bool // true if access was gained via default credentials
	Methods        string
	ContentBase    string
	ContentType    string
	ContentLength  int
	HasWWWAuth     bool   // buggy DVRs return 200 + WWW-Authenticate
	AuthRealm      string // parsed from WWW-Authenticate
	AuthNonce      string // parsed from WWW-Authenticate
	Error          string
}

// Common RTSP paths used by DVRs and IP cameras.
// These are documented across vendor SDKs and widely exploited in the wild.
var rtspPaths = []string{
	"/",
	"/live",
	"/live/ch0",
	"/live/ch00_0",
	"/live/ch01_0",
	"/cam/realmonitor?channel=1&subtype=0",
	"/cam/realmonitor?channel=1&subtype=1",
	"/h264/ch1/main/av_stream",
	"/h264/ch1/sub/av_stream",
	"/Streaming/Channels/1",
	"/Streaming/Channels/101",
	"/Streaming/Channels/102",
	"/1",
	"/11",
	"/12",
	"/MediaInput/h264",
	"/media/video1",
	"/video1",
	"/ch0_0.h264",
	"/0",
	"/stream1",
	"/VideoInput/1/h264/1",
}

// H264DVR-specific paths that embed credentials directly in the URL.
// These DVRs don't use standard Digest auth — the user/password goes in the path.
var h264dvrCredPaths = []string{
	"/user=admin&password=&channel=1&stream=0.sdp",
	"/user=admin&password=&channel=1&stream=1.sdp",
	"/user=admin&password=&channel=2&stream=0.sdp",
	"/user=admin&password=&channel=3&stream=0.sdp",
	"/user=admin&password=&channel=4&stream=0.sdp",
	"/user=admin_password=_channel=1&stream=0.sdp",
	"/user=admin&password=admin&channel=1&stream=0.sdp",
	"/user=admin&password=12345&channel=1&stream=0.sdp",
	"/user=admin&password=123456&channel=1&stream=0.sdp",
}

// Default RTSP credentials to try when digest auth is required.
var rtspDefaultCreds = []struct {
	User string
	Pass string
}{
	{"admin", ""},
	{"admin", "admin"},
	{"admin", "12345"},
	{"admin", "123456"},
	{"admin", "1234"},
	{"root", ""},
	{"root", "root"},
}

// SupportsRTSP returns true if the camera's port is a known RTSP port.
func SupportsRTSP(cam shodan.Camera) bool {
	switch cam.Port {
	case 554, 8554, 5554, 10554:
		return true
	default:
		return false
	}
}

// IsRTSPBanner checks if the banner text indicates an RTSP server.
func IsRTSPBanner(cam shodan.Camera) bool {
	banner := strings.ToLower(cam.Banner)
	return strings.Contains(banner, "rtsp/") ||
		strings.Contains(banner, "h264dvr") ||
		strings.Contains(banner, "realserver") ||
		strings.Contains(banner, "streaming server")
}

// ProbeRTSP performs lightweight RTSP DESCRIBE requests against well-known
// stream paths to determine if the camera allows unauthenticated access.
//
// When a server returns 200 + WWW-Authenticate (buggy H264DVR firmware) or
// 401 Unauthorized, the probe retries with default credentials using Digest auth.
//
// For H264DVR servers, credentials are embedded in the URL path rather than
// sent via Digest auth headers — the probe detects this and tries H264DVR-specific
// paths first.
func ProbeRTSP(ctx context.Context, cam shodan.Camera, timeout time.Duration) []RTSPProbeResult {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	host := net.JoinHostPort(cam.IP, strconv.Itoa(cam.Port))
	var results []RTSPProbeResult

	// 1. Initial probe on "/" to detect server type
	initialResult := probeRTSPPath(ctx, host, cam.IP, cam.Port, "/", timeout)
	results = append(results, initialResult)

	isH264DVR := strings.Contains(strings.ToLower(initialResult.Server), "h264dvr") ||
		strings.Contains(strings.ToLower(cam.Banner), "h264dvr")

	// 2. If H264DVR detected, try credential-in-URL paths FIRST
	//    These DVRs embed user/pass in the path, not via Digest auth headers.
	if isH264DVR {
		log.Printf("          [H264DVR] Detected H264DVR server — trying credential-in-URL paths")
		for _, path := range h264dvrCredPaths {
			select {
			case <-ctx.Done():
				return results
			default:
			}

			credResult := probeRTSPPath(ctx, host, cam.IP, cam.Port, path, timeout)
			if credResult.Accessible {
				credResult.DefaultCreds = true
				results = append(results, credResult)
				log.Printf("          [H264DVR] ✓ Stream accessible via %s", path)
				return results
			}
			// For H264DVR paths, also check: 200 status with any body = accessible
			if credResult.StatusCode == 200 && credResult.ContentLength > 0 && !credResult.HasWWWAuth {
				credResult.Accessible = true
				credResult.DefaultCreds = true
				results = append(results, credResult)
				log.Printf("          [H264DVR] ✓ Stream accessible via %s (200 + body)", path)
				return results
			}
		}
		log.Printf("          [H264DVR] credential-in-URL paths exhausted, trying Digest auth fallback")
	}

	// 3. Try standard paths with Digest auth retry
	for i, path := range rtspPaths {
		if i == 0 {
			continue // Already probed "/" above
		}

		select {
		case <-ctx.Done():
			return results
		default:
		}

		result := probeRTSPPath(ctx, host, cam.IP, cam.Port, path, timeout)

		// If the stream needs auth (200+WWW-Auth or 401), try default creds
		if (result.HasWWWAuth || result.StatusCode == 401) && result.AuthRealm != "" {
			for _, cred := range rtspDefaultCreds {
				select {
				case <-ctx.Done():
					return results
				default:
				}
				authResult := probeRTSPWithDigest(ctx, host, cam.IP, cam.Port, path, timeout,
					cred.User, cred.Pass, result.AuthRealm, result.AuthNonce)
				if authResult.Accessible {
					authResult.DefaultCreds = true
					results = append(results, authResult)
					return results
				}
			}
		}

		results = append(results, result)

		// If we found a genuinely open stream, stop
		if result.Accessible {
			return results
		}

		// If auth required, most paths will behave the same — try a few then stop
		if (result.StatusCode == 401 || result.HasWWWAuth) && len(results) >= 3 {
			return results
		}
	}

	return results
}

func probeRTSPPath(ctx context.Context, host, ip string, port int, path string, timeout time.Duration) RTSPProbeResult {
	rtspURL := fmt.Sprintf("rtsp://%s:%d%s", ip, port, path)
	result := RTSPProbeResult{
		URL:  rtspURL,
		Path: path,
	}

	conn, err := dialRTSP(ctx, host, port, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Send DESCRIBE request
	request := fmt.Sprintf(
		"DESCRIBE %s RTSP/1.0\r\n"+
			"CSeq: 1\r\n"+
			"Accept: application/sdp\r\n"+
			"User-Agent: Mozilla/5.0\r\n"+
			"\r\n",
		rtspURL,
	)

	_, err = conn.Write([]byte(request))
	if err != nil {
		result.Error = fmt.Sprintf("write failed: %v", err)
		return result
	}

	parseRTSPResponse(bufio.NewReader(conn), &result)
	classifyAccess(&result)
	return result
}

// probeRTSPWithDigest retries DESCRIBE with HTTP Digest auth credentials.
func probeRTSPWithDigest(ctx context.Context, host, ip string, port int, path string, timeout time.Duration,
	user, pass, realm, nonce string) RTSPProbeResult {

	rtspURL := fmt.Sprintf("rtsp://%s:%d%s", ip, port, path)
	result := RTSPProbeResult{
		URL:  rtspURL,
		Path: path,
	}

	conn, err := dialRTSP(ctx, host, port, timeout)
	if err != nil {
		result.Error = fmt.Sprintf("connection failed: %v", err)
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Compute Digest auth response (RFC 2617)
	ha1 := md5hex(fmt.Sprintf("%s:%s:%s", user, realm, pass))
	ha2 := md5hex(fmt.Sprintf("DESCRIBE:%s", rtspURL))
	response := md5hex(fmt.Sprintf("%s:%s:%s", ha1, nonce, ha2))

	authHeader := fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		user, realm, nonce, rtspURL, response,
	)

	request := fmt.Sprintf(
		"DESCRIBE %s RTSP/1.0\r\n"+
			"CSeq: 2\r\n"+
			"Accept: application/sdp\r\n"+
			"Authorization: %s\r\n"+
			"User-Agent: Mozilla/5.0\r\n"+
			"\r\n",
		rtspURL, authHeader,
	)

	_, err = conn.Write([]byte(request))
	if err != nil {
		result.Error = fmt.Sprintf("write failed: %v", err)
		return result
	}

	parseRTSPResponse(bufio.NewReader(conn), &result)
	classifyAccess(&result)
	return result
}

func dialRTSP(ctx context.Context, host string, port int, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	if port == 322 || port == 8322 {
		return tls.DialWithDialer(dialer, "tcp", host, &tls.Config{
			InsecureSkipVerify: true,
		})
	}
	return dialer.DialContext(ctx, "tcp", host)
}

func parseRTSPResponse(reader *bufio.Reader, result *RTSPProbeResult) {
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		result.Error = fmt.Sprintf("read failed: %v", err)
		return
	}

	// Parse status code from "RTSP/1.0 200 OK"
	statusLine = strings.TrimSpace(statusLine)
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) >= 2 {
		code, parseErr := strconv.Atoi(parts[1])
		if parseErr == nil {
			result.StatusCode = code
		}
	}

	// Read headers
	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}

		lowerLine := strings.ToLower(line)
		if strings.HasPrefix(lowerLine, "server:") {
			result.Server = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(lowerLine, "content-base:") {
			result.ContentBase = strings.TrimSpace(line[13:])
		} else if strings.HasPrefix(lowerLine, "public:") {
			result.Methods = strings.TrimSpace(line[7:])
		} else if strings.HasPrefix(lowerLine, "content-type:") {
			result.ContentType = strings.TrimSpace(line[13:])
		} else if strings.HasPrefix(lowerLine, "content-length:") {
			cl, clErr := strconv.Atoi(strings.TrimSpace(line[15:]))
			if clErr == nil {
				result.ContentLength = cl
			}
		} else if strings.HasPrefix(lowerLine, "www-authenticate:") {
			result.HasWWWAuth = true
			parseDigestChallenge(line, result)
		}
	}
}

// parseDigestChallenge extracts realm and nonce from WWW-Authenticate header.
func parseDigestChallenge(header string, result *RTSPProbeResult) {
	// WWW-Authenticate: Digest realm="xxx", nonce="yyy"
	lower := strings.ToLower(header)
	if idx := strings.Index(lower, "realm=\""); idx >= 0 {
		start := idx + 7
		if end := strings.Index(header[start:], "\""); end >= 0 {
			result.AuthRealm = header[start : start+end]
		}
	}
	if idx := strings.Index(lower, "nonce=\""); idx >= 0 {
		start := idx + 7
		if end := strings.Index(header[start:], "\""); end >= 0 {
			result.AuthNonce = header[start : start+end]
		}
	}
}

func classifyAccess(result *RTSPProbeResult) {
	// A truly open RTSP stream must satisfy ALL of:
	//   1. Status 200
	//   2. No WWW-Authenticate header (buggy H264DVR sends 200+WWW-Auth)
	//   3. Ideally Content-Type: application/sdp (has actual stream description)
	//
	// If 200 + WWW-Authenticate → auth required (firmware bug)
	// If 401 → auth required (correct behavior)
	switch {
	case result.StatusCode == 200 && result.HasWWWAuth:
		// Buggy firmware: says 200 but actually wants auth
		result.Authenticated = true
		result.Accessible = false
	case result.StatusCode == 200 && strings.Contains(strings.ToLower(result.ContentType), "application/sdp"):
		// Genuine open stream with SDP body
		result.Accessible = true
		result.Authenticated = false
	case result.StatusCode == 200 && result.ContentLength > 0 && !result.HasWWWAuth:
		// 200 with body content and no auth challenge — likely open
		result.Accessible = true
		result.Authenticated = false
	case result.StatusCode == 200:
		// 200 but no SDP, no body, no auth — inconclusive, don't mark as open
		result.Accessible = false
		result.Authenticated = false
	case result.StatusCode == 401:
		result.Authenticated = true
	}
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", h)
}
