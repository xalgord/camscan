package shodan

// Location holds geographic information about a discovered camera.
type Location struct {
	City        string  `json:"city"`
	Country     string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region_code"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

// Camera represents a single discovered IP camera from Shodan.
type Camera struct {
	IP        string   `json:"ip_str"`
	Port      int      `json:"port"`
	Product   string   `json:"product"`
	Banner    string   `json:"data"`
	Hostnames []string `json:"hostnames"`
	Org       string   `json:"org"`
	OS        string   `json:"os"`
	Location  Location `json:"location"`
	Transport string   `json:"transport"`
	Timestamp string   `json:"timestamp"`
	Title     string   `json:"title"`
	HTTP      *HTTP    `json:"http,omitempty"`
	SSL      *SSL     `json:"ssl,omitempty"`
}

// HTTP holds HTTP-specific banner data.
type HTTP struct {
	Title  string `json:"title"`
	Server string `json:"server"`
	Status int    `json:"status"`
}

// SSL holds TLS/SSL certificate data.
type SSL struct {
	Version string   `json:"version"`
	Chain   []string `json:"chain"`
}

// SearchResult is the top-level Shodan search response.
type SearchResult struct {
	Total   int      `json:"total"`
	Matches []Camera `json:"matches"`
}
