package validator

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/xalgord/camscan/internal/shodan"
)

// VendorEndpoint represents a well-known camera endpoint that may expose
// unauthenticated video/image streams or configuration data.
type VendorEndpoint struct {
	Path        string // URL path including query string
	Description string // Human-readable description
	StreamType  string // "mjpeg", "jpeg", "video", "config", "snapshot"
}

// VendorEndpoints maps vendor names to their well-known exposed endpoints.
// These are documented in vendor SDKs, manuals, and security advisories.
var VendorEndpoints = map[string][]VendorEndpoint{
	// Dahua / CP Plus / Amcrest — ISAPI-compatible endpoints
	"dahua": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream channel 1", StreamType: "mjpeg"},
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=0", Description: "MJPEG main-stream channel 1", StreamType: "mjpeg"},
		{Path: "/cgi-bin/snapshot.cgi?channel=1", Description: "JPEG snapshot channel 1", StreamType: "snapshot"},
		{Path: "/cgi-bin/configManager.cgi?action=getConfig&name=Network", Description: "Network config disclosure", StreamType: "config"},
		{Path: "/cgi-bin/magicBox.cgi?action=getDeviceType", Description: "Device type info", StreamType: "config"},
		{Path: "/cgi-bin/magicBox.cgi?action=getSerialNo", Description: "Serial number disclosure", StreamType: "config"},
	},
	"cp plus": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream channel 1", StreamType: "mjpeg"},
		{Path: "/cgi-bin/snapshot.cgi?channel=1", Description: "JPEG snapshot channel 1", StreamType: "snapshot"},
		{Path: "/cgi-bin/configManager.cgi?action=getConfig&name=Network", Description: "Network config disclosure", StreamType: "config"},
	},
	"cpplus": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream channel 1", StreamType: "mjpeg"},
		{Path: "/cgi-bin/snapshot.cgi?channel=1", Description: "JPEG snapshot channel 1", StreamType: "snapshot"},
	},
	"cp-plus": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream channel 1", StreamType: "mjpeg"},
		{Path: "/cgi-bin/snapshot.cgi?channel=1", Description: "JPEG snapshot channel 1", StreamType: "snapshot"},
	},
	"amcrest": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream channel 1", StreamType: "mjpeg"},
		{Path: "/cgi-bin/snapshot.cgi?channel=1", Description: "JPEG snapshot channel 1", StreamType: "snapshot"},
		{Path: "/cgi-bin/configManager.cgi?action=getConfig&name=Network", Description: "Network config disclosure", StreamType: "config"},
	},

	// Hikvision — ISAPI endpoints
	"hikvision": {
		{Path: "/ISAPI/Streaming/channels/101/picture", Description: "ISAPI snapshot channel 1 sub", StreamType: "snapshot"},
		{Path: "/ISAPI/Streaming/channels/1/picture", Description: "ISAPI snapshot channel 1", StreamType: "snapshot"},
		{Path: "/Streaming/channels/1/preview", Description: "Stream preview channel 1", StreamType: "mjpeg"},
		{Path: "/ISAPI/System/deviceInfo", Description: "Device info disclosure", StreamType: "config"},
		{Path: "/System/configurationFile?auth=YWRtaW46MTEK", Description: "Config file (default auth token)", StreamType: "config"},
	},

	// Axis — classic VAPIX API
	"axis": {
		{Path: "/axis-cgi/jpg/image.cgi", Description: "VAPIX JPEG snapshot", StreamType: "snapshot"},
		{Path: "/axis-cgi/mjpg/video.cgi", Description: "VAPIX MJPEG stream", StreamType: "mjpeg"},
		{Path: "/view/viewer_index.shtml", Description: "Viewer page", StreamType: "video"},
		{Path: "/axis-cgi/param.cgi?action=list&group=Brand", Description: "Brand info disclosure", StreamType: "config"},
	},

	// Foscam
	"foscam": {
		{Path: "/cgi-bin/CGIProxy.fcgi?cmd=snapPicture2&usr=admin&pwd=", Description: "Snapshot (blank password)", StreamType: "snapshot"},
		{Path: "/videostream.cgi?user=admin&pwd=", Description: "Video stream (blank password)", StreamType: "mjpeg"},
	},

	// AVTECH
	"avtech": {
		{Path: "/cgi-bin/guest/Video.cgi?media=MJPEG", Description: "Guest MJPEG stream", StreamType: "mjpeg"},
		{Path: "/cgi-bin/nobody/Machine.cgi?action=get_capability", Description: "Capability disclosure", StreamType: "config"},
	},

	// Reolink
	"reolink": {
		{Path: "/cgi-bin/api.cgi?cmd=Snap&channel=0&rs=wuuPhkmUCeI9WG7C&user=admin&password=", Description: "Snapshot (blank password)", StreamType: "snapshot"},
	},

	// Uniview
	"uniview": {
		{Path: "/LAPI/V1.0/Channels/0/Media/Video/Streams/0/LiveStreamSetup", Description: "Live stream setup", StreamType: "config"},
	},

	// Huawei
	"huawei": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream (Dahua-compatible)", StreamType: "mjpeg"},
		{Path: "/snapshot.cgi?channel=1", Description: "Snapshot channel 1", StreamType: "snapshot"},
	},

	// Tiandy
	"tiandy": {
		{Path: "/cgi-bin/mjpg/video.cgi?channel=1&subtype=1", Description: "MJPEG sub-stream", StreamType: "mjpeg"},
		{Path: "/cgi-bin/snapshot.cgi?channel=1", Description: "Snapshot channel 1", StreamType: "snapshot"},
	},

	// GeoVision
	"geovision": {
		{Path: "/PictureCatch.cgi", Description: "JPEG snapshot", StreamType: "snapshot"},
		{Path: "/cam1/mpeg4", Description: "MPEG4 stream cam 1", StreamType: "video"},
	},

	// Vivotek
	"vivotek": {
		{Path: "/cgi-bin/viewer/video.jpg", Description: "JPEG snapshot", StreamType: "snapshot"},
		{Path: "/video.mjpg", Description: "MJPEG stream", StreamType: "mjpeg"},
	},

	// Bosch
	"bosch": {
		{Path: "/snap.jpg", Description: "JPEG snapshot", StreamType: "snapshot"},
		{Path: "/video.mjpg", Description: "MJPEG stream", StreamType: "mjpeg"},
	},

	// Wisenet / Hanwha
	"wisenet": {
		{Path: "/stw-cgi/video.cgi?msubmenu=stream&action=view&Channel=0&Profile=1", Description: "Video stream", StreamType: "mjpeg"},
	},
	"hanwha": {
		{Path: "/stw-cgi/video.cgi?msubmenu=stream&action=view&Channel=0&Profile=1", Description: "Video stream", StreamType: "mjpeg"},
	},

	// Pelco
	"pelco": {
		{Path: "/image.cgi", Description: "JPEG snapshot", StreamType: "snapshot"},
	},

	// Honeywell
	"honeywell": {
		{Path: "/ISAPI/Streaming/channels/1/picture", Description: "ISAPI snapshot (Hik-compatible)", StreamType: "snapshot"},
	},
}

// EndpointProbeResult holds the result of probing a single vendor endpoint.
type EndpointProbeResult struct {
	Path           string
	Description    string
	StreamType     string
	StatusCode     int
	ContentType    string
	ContentLength  int64
	Accessible     bool // true if the endpoint returned media or config data
	IsStream       bool // true if content-type indicates video/image stream
	IsConfig       bool // true if content-type indicates text/config data
	ResponseSample string
}

// ProbeVendorEndpoints performs lightweight HTTP requests against known
// vendor-specific endpoints that may expose unauthenticated content.
// It does NOT use a browser — just plain HTTP GET with content-type checking.
func ProbeVendorEndpoints(ctx context.Context, cam shodan.Camera, banner string, timeout time.Duration) []EndpointProbeResult {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	lower := strings.ToLower(banner)
	var allEndpoints []VendorEndpoint
	var matchedVendor string

	for vendor, endpoints := range VendorEndpoints {
		if strings.Contains(lower, vendor) {
			allEndpoints = append(allEndpoints, endpoints...)
			if matchedVendor == "" {
				matchedVendor = vendor
			}
		}
	}

	if len(allEndpoints) == 0 {
		return nil
	}

	// Deduplicate by path
	seen := make(map[string]bool)
	var unique []VendorEndpoint
	for _, ep := range allEndpoints {
		if !seen[ep.Path] {
			seen[ep.Path] = true
			unique = append(unique, ep)
		}
	}

	scheme := "http"
	if cam.SSL != nil || cam.Port == 443 || cam.Port == 8443 || strings.EqualFold(cam.Transport, "ssl") {
		scheme = "https"
	}
	host := net.JoinHostPort(cam.IP, strconv.Itoa(cam.Port))

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Don't follow redirects to login pages
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	defer client.CloseIdleConnections()

	var results []EndpointProbeResult

	for _, ep := range unique {
		targetURL := scheme + "://" + host + ep.Path

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		result := EndpointProbeResult{
			Path:        ep.Path,
			Description: ep.Description,
			StreamType:  ep.StreamType,
			StatusCode:  resp.StatusCode,
		}

		if resp.Header.Get("Content-Type") != "" {
			result.ContentType = resp.Header.Get("Content-Type")
		}
		result.ContentLength = resp.ContentLength

		ct := strings.ToLower(result.ContentType)

		// Check if the response contains actual media/data
		if resp.StatusCode == 200 {
			switch {
			case strings.Contains(ct, "image/jpeg"),
				strings.Contains(ct, "image/png"),
				strings.Contains(ct, "image/gif"),
				strings.Contains(ct, "multipart/x-mixed-replace"),
				strings.Contains(ct, "video/"),
				strings.Contains(ct, "application/octet-stream") && (ep.StreamType == "mjpeg" || ep.StreamType == "video"):
				result.Accessible = true
				result.IsStream = true

			case ep.StreamType == "config" && (strings.Contains(ct, "text/") || strings.Contains(ct, "application/json") || strings.Contains(ct, "application/xml")):
				// Read a small sample for config endpoints
				body := make([]byte, 512)
				n, _ := io.ReadFull(resp.Body, body)
				if n > 0 {
					sample := string(body[:n])
					// Config is accessible if it contains actual data, not a login redirect
					if !strings.Contains(strings.ToLower(sample), "login") &&
						!strings.Contains(strings.ToLower(sample), "unauthorized") &&
						n > 10 {
						result.Accessible = true
						result.IsConfig = true
						result.ResponseSample = truncate(sample, 200)
					}
				}

			case ep.StreamType == "snapshot" && resp.ContentLength > 1000:
				// Snapshots with > 1KB content are likely real images
				result.Accessible = true
				result.IsStream = true
			}
		}

		resp.Body.Close()
		results = append(results, result)
	}

	_ = matchedVendor
	return results
}

