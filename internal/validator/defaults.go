package validator

// VendorDefaults maps known camera vendor names (lowercase) to their
// well-documented factory-default credentials.  These are published in
// vendor manuals and widely referenced in security advisories.
// Every entry is a pair {username, password} that ships from the factory.
var VendorDefaults = map[string][]Credentials{
	// Dahua & OEMs (CP Plus, Lorex, Amcrest older firmware)
	"dahua":   {{Username: "admin", Password: "admin"}, {Username: "admin", Password: "admin123"}},
	"cp plus": {{Username: "admin", Password: "admin"}, {Username: "admin", Password: "admin123"}},
	"cp-plus": {{Username: "admin", Password: "admin"}, {Username: "admin", Password: "admin123"}},
	"cpplus":  {{Username: "admin", Password: "admin"}, {Username: "admin", Password: "admin123"}},

	// Hikvision (older firmware, newer requires forced password change)
	"hikvision": {{Username: "admin", Password: "12345"}, {Username: "admin", Password: "admin12345"}},

	// Axis (classic defaults)
	"axis": {{Username: "root", Password: "pass"}, {Username: "root", Password: "root"}},

	// Foscam
	"foscam": {{Username: "admin", Password: ""}, {Username: "admin", Password: "admin"}},

	// AVTECH
	"avtech": {{Username: "admin", Password: "admin"}},

	// Reolink
	"reolink": {{Username: "admin", Password: ""}, {Username: "admin", Password: "admin"}},

	// Amcrest (newer firmware)
	"amcrest": {{Username: "admin", Password: "admin"}},

	// Uniview
	"uniview": {{Username: "admin", Password: "123456"}},

	// Vivotek
	"vivotek": {{Username: "root", Password: "root"}},

	// Bosch
	"bosch": {{Username: "admin", Password: "admin"}, {Username: "service", Password: "service"}},

	// GeoVision
	"geovision": {{Username: "admin", Password: "admin"}},

	// Huawei
	"huawei": {{Username: "admin", Password: "HuaWei123"}, {Username: "admin", Password: "admin"}},

	// Tiandy
	"tiandy": {{Username: "admin", Password: "admin"}, {Username: "admin", Password: "123456"}},

	// Samsung Wisenet / Hanwha
	"wisenet": {{Username: "admin", Password: "4321"}, {Username: "admin", Password: "admin"}},
	"hanwha":  {{Username: "admin", Password: "4321"}, {Username: "admin", Password: "admin"}},

	// Pelco
	"pelco": {{Username: "admin", Password: "admin"}},

	// Honeywell
	"honeywell": {{Username: "admin", Password: "1234"}},
}

// DefaultCredsForBanner searches the banner text for any known vendor name
// and returns the first matching set of default credentials.
func DefaultCredsForBanner(banner string) ([]Credentials, string) {
	lower := toLower(banner)
	for vendor, creds := range VendorDefaults {
		if contains(lower, vendor) {
			return creds, vendor
		}
	}
	return nil, ""
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := range s {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && searchSubstr(s, substr)
}

func searchSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
