package validator

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/launcher/flags"
	"github.com/go-rod/rod/lib/proto"
	"github.com/xalgord/camscan/internal/shodan"
)

const defaultHTTPTimeout = 8 * time.Second

var (
	passwordInputRe = regexp.MustCompile(`(?is)<input[^>]+type\s*=\s*["']?password`)
	titleRe         = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	scriptStyleRe   = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>|<style[^>]*>.*?</style>`)
	tagRe           = regexp.MustCompile(`(?is)<[^>]+>`)
	spaceRe         = regexp.MustCompile(`\s+`)
)

const loginFormScript = `(username, password) => {
	const inputs = Array.from(document.querySelectorAll('input'));
	const visible = (el) => {
		const style = window.getComputedStyle(el);
		const rect = el.getBoundingClientRect();
		return style.display !== 'none' && style.visibility !== 'hidden' && rect.width > 0 && rect.height > 0 && !el.disabled && !el.readOnly;
	};
	const typeOf = (el) => (el.getAttribute('type') || 'text').toLowerCase();
	const passwordInput = inputs.find((el) => typeOf(el) === 'password' && visible(el));
	if (!passwordInput) return { ok: false, reason: 'no-password-input' };
	const scoreUser = (el) => {
		const type = typeOf(el);
		if (el === passwordInput || !visible(el) || ['hidden', 'password', 'submit', 'button', 'checkbox', 'radio', 'file'].includes(type)) return -1;
		const text = [el.name, el.id, el.placeholder, el.autocomplete, el.getAttribute('aria-label')].filter(Boolean).join(' ').toLowerCase();
		let score = 0;
		if (/(user|login|account|admin|email|name)/.test(text)) score += 5;
		if (type === 'text' || type === 'email') score += 2;
		if (el.form && passwordInput.form && el.form === passwordInput.form) score += 2;
		return score;
	};
	const usernameInput = inputs
		.map((el) => ({ el, score: scoreUser(el) }))
		.filter((item) => item.score >= 0)
		.sort((a, b) => b.score - a.score)[0]?.el;
	const setValue = (el, value) => {
		if (!el) return;
		el.focus();
		el.value = value;
		el.dispatchEvent(new Event('input', { bubbles: true }));
		el.dispatchEvent(new Event('change', { bubbles: true }));
	};
	setValue(usernameInput, username);
	setValue(passwordInput, password);
	const buttons = Array.from(document.querySelectorAll('button,input[type="submit"],input[type="button"],a[id*="login"],a.btnStyle'));
	const loginButton = buttons.find((el) => {
		const text = [el.innerText, el.value, el.name, el.id, el.getAttribute('aria-label')].filter(Boolean).join(' ');
		const lower = text.toLowerCase();
		return /(login|log in|sign in|submit|enter)/.test(lower) || /登录|登入|로그인|ログイン/.test(text);
	}) || buttons.find((el) => {
		const id = (el.id || '').toLowerCase();
		return /(b_login|loginbtn|btn_login|btn-login|login_btn)/.test(id);
	}) || buttons.find((el) => typeOf(el) === 'submit');
	if (loginButton) {
		loginButton.click();
		return { ok: true, method: 'button' };
	}
	if (passwordInput.form) {
		passwordInput.form.requestSubmit ? passwordInput.form.requestSubmit() : passwordInput.form.submit();
		return { ok: true, method: 'form' };
	}
	passwordInput.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', bubbles: true }));
	passwordInput.dispatchEvent(new KeyboardEvent('keyup', { key: 'Enter', code: 'Enter', bubbles: true }));
	return { ok: true, method: 'enter' };
}`

// HTTPValidation is the result of an active browser render of a camera web UI.
type HTTPValidation struct {
	Method         string   `json:"method"`
	TargetURL      string   `json:"target_url"`
	FinalURL       string   `json:"final_url,omitempty"`
	Attempted      bool     `json:"attempted"`
	Reachable      bool     `json:"reachable"`
	AuthRequired   bool     `json:"auth_required"`
	LoginDetected  bool     `json:"login_detected"`
	LoginAttempted bool     `json:"login_attempted"`
	LoginSucceeded bool     `json:"login_succeeded"`
	LoginUsername  string   `json:"login_username,omitempty"`
	BlankPage      bool     `json:"blank_page"`
	OpenContent    bool     `json:"open_content"`
	Title          string   `json:"title,omitempty"`
	TextSample     string   `json:"text_sample,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	LoginError     string   `json:"login_error,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// Credentials is one explicit credential pair to test during authorized active
// validation. The password is never copied into validation output.
type Credentials struct {
	Username string
	Password string
}

// Option configures optional validator behavior.
type Option func(*HTTPValidator)

func WithCredentials(credentials Credentials) Option {
	return func(v *HTTPValidator) {
		credentials.Username = strings.TrimSpace(credentials.Username)
		if credentials.Username == "" || credentials.Password == "" {
			return
		}
		v.credentials = &credentials
	}
}

// HTTPValidator renders HTTP/HTTPS camera interfaces with Rod. Credential use is
// opt-in, single-pair only, and limited to proving access after a login wall.
type HTTPValidator struct {
	timeout     time.Duration
	credentials *Credentials

	mu      sync.Mutex
	once    sync.Once
	launch  *launcher.Launcher
	browser *rod.Browser
	err     error
}

func NewHTTPValidator(timeout time.Duration, opts ...Option) *HTTPValidator {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	v := &HTTPValidator{timeout: timeout}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Timeout returns the configured per-request timeout.
func (v *HTTPValidator) Timeout() time.Duration {
	return v.timeout
}

func (v *HTTPValidator) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var err error
	if v.browser != nil {
		err = v.browser.Close()
		v.browser = nil
	}
	if v.launch != nil {
		v.launch.Cleanup()
		v.launch = nil
	}
	return err
}

func SupportsHTTP(cam shodan.Camera) bool {
	if cam.HTTP != nil {
		return true
	}
	switch cam.Port {
	case 80, 81, 82, 83, 88, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 8899, 9000:
		return true
	default:
		return false
	}
}

func TargetURL(cam shodan.Camera) string {
	if !SupportsHTTP(cam) {
		return ""
	}
	scheme := "http"
	if cam.SSL != nil || cam.Port == 443 || cam.Port == 8443 || strings.EqualFold(cam.Transport, "ssl") {
		scheme = "https"
	}
	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(cam.IP, strconv.Itoa(cam.Port)),
		Path:   "/",
	}
	return u.String()
}

func withURLCredentials(rawURL string, credentials Credentials) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = url.UserPassword(credentials.Username, credentials.Password)
	return u.String()
}

func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = nil
	return u.String()
}

func sanitizeCredentialText(text string, credentials *Credentials) string {
	if credentials == nil || credentials.Password == "" {
		return text
	}
	replacements := []string{
		credentials.Password,
		url.QueryEscape(credentials.Password),
	}
	if escaped := url.PathEscape(credentials.Password); escaped != url.QueryEscape(credentials.Password) {
		replacements = append(replacements, escaped)
	}
	for _, replacement := range replacements {
		if replacement != "" {
			text = strings.ReplaceAll(text, replacement, "********")
		}
	}
	return text
}

func (v *HTTPValidator) Validate(ctx context.Context, cam shodan.Camera) HTTPValidation {
	result := HTTPValidation{
		Method:    "rod",
		TargetURL: TargetURL(cam),
		Attempted: true,
	}
	if result.TargetURL == "" {
		result.Error = "not an HTTP/HTTPS service"
		return result
	}

	navigationURL := result.TargetURL
	if cam.HTTP != nil && (cam.HTTP.Status == 401 || cam.HTTP.Status == 403) {
		result.Reachable = true
		result.AuthRequired = true
		result.LoginDetected = true
		result.Title = cam.HTTP.Title
		result.Evidence = append(result.Evidence, fmt.Sprintf("Shodan HTTP status %d indicates authentication/authorization required", cam.HTTP.Status))
		if v.credentials == nil || cam.HTTP.Status != 401 {
			return result
		}
		result.LoginAttempted = true
		result.LoginUsername = v.credentials.Username
		result.Evidence = append(result.Evidence, "Attempting supplied credential against HTTP authentication challenge")
		navigationURL = withURLCredentials(result.TargetURL, *v.credentials)
	}

	launchCtx, launchCancel := context.WithTimeout(ctx, maxDuration(30*time.Second, v.timeout*2))
	browser, err := v.browserFor(launchCtx)
	launchCancel()
	if err != nil {
		result.Error = fmt.Sprintf("Rod browser unavailable: %v", err)
		return result
	}

	ctx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	page, err := browser.Context(ctx).Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		result.Error = fmt.Sprintf("create page: %v", err)
		return result
	}
	defer page.Close()

	page = page.Timeout(v.timeout)
	if err := page.Navigate(navigationURL); err != nil {
		result.Error = "navigate: " + sanitizeCredentialText(err.Error(), v.credentials)
		return result
	}
	_ = page.WaitLoad()
	_ = page.WaitDOMStable(300*time.Millisecond, 0.1)

	if info, err := page.Info(); err == nil {
		result.FinalURL = sanitizeURL(info.URL)
	}

	html, err := page.HTML()
	if err != nil {
		result.Error = "read html: " + sanitizeCredentialText(err.Error(), v.credentials)
		return result
	}

	classifyHTML(&result, html)
	if result.LoginAttempted && result.OpenContent && !result.BlankPage {
		result.LoginSucceeded = true
		result.Evidence = append(result.Evidence, "Rod confirmed camera content after authenticating with the supplied credential")
		return result
	}
	if (result.AuthRequired || result.LoginDetected) && v.credentials != nil && !result.LoginAttempted {
		v.tryFormLogin(page, &result)
	}
	return result
}

func (v *HTTPValidator) browserFor(ctx context.Context) (*rod.Browser, error) {
	v.once.Do(func() {
		l := launcher.New().
			Context(ctx).
			Headless(true).
			NoSandbox(true).
			Set(flags.Flag("ignore-certificate-errors")).
			Set(flags.Flag("disable-gpu")).
			Set(flags.Flag("disable-dev-shm-usage"))

		controlURL, err := l.Launch()
		if err != nil {
			v.err = err
			return
		}

		browser := rod.New().ControlURL(controlURL).Trace(false)
		if err := browser.Connect(); err != nil {
			l.Cleanup()
			v.err = err
			return
		}
		_ = browser.IgnoreCertErrors(true)

		v.launch = l
		v.browser = browser
	})

	v.mu.Lock()
	defer v.mu.Unlock()
	return v.browser, v.err
}

func (v *HTTPValidator) tryFormLogin(page *rod.Page, result *HTTPValidation) {
	if v.credentials == nil {
		return
	}
	result.LoginAttempted = true
	result.LoginUsername = v.credentials.Username
	result.Evidence = append(result.Evidence, "Attempting supplied credential in rendered login form")

	if _, err := page.Eval(loginFormScript, v.credentials.Username, v.credentials.Password); err != nil {
		result.LoginError = "form login automation: " + sanitizeCredentialText(err.Error(), v.credentials)
		result.Evidence = append(result.Evidence, "Rod could not submit the login form")
		return
	}

	_ = page.WaitLoad()
	_ = page.WaitDOMStable(500*time.Millisecond, 0.1)

	if info, err := page.Info(); err == nil {
		result.FinalURL = sanitizeURL(info.URL)
	}

	html, err := page.HTML()
	if err != nil {
		result.LoginError = "read post-login html: " + sanitizeCredentialText(err.Error(), v.credentials)
		result.Evidence = append(result.Evidence, "Rod could not read the page after login submission")
		return
	}

	postLogin := HTTPValidation{
		Method:         result.Method,
		TargetURL:      result.TargetURL,
		FinalURL:       result.FinalURL,
		Attempted:      result.Attempted,
		LoginAttempted: true,
		LoginUsername:  result.LoginUsername,
	}
	classifyPostLoginHTML(&postLogin, html)

	result.Reachable = postLogin.Reachable
	result.AuthRequired = true
	result.LoginDetected = true
	result.BlankPage = postLogin.BlankPage
	result.OpenContent = postLogin.OpenContent
	result.Title = postLogin.Title
	result.TextSample = postLogin.TextSample
	result.Evidence = append(result.Evidence, postLogin.Evidence...)

	if postLogin.OpenContent && !postLogin.BlankPage {
		result.LoginSucceeded = true
		result.Evidence = append(result.Evidence, "Rod confirmed camera content after submitting the supplied credential")
		return
	}

	if postLogin.AuthRequired || postLogin.LoginDetected {
		result.Evidence = append(result.Evidence, "Supplied credential did not clear the authentication page")
		return
	}
	result.Evidence = append(result.Evidence, "Supplied credential did not reveal accessible camera content")
}

func classifyHTML(result *HTTPValidation, html string) {
	result.Reachable = true
	result.Title = extractTitle(html)
	text := visibleText(html)
	result.TextSample = truncate(text, 220)

	lowerHTML := strings.ToLower(html)
	lowerText := strings.ToLower(text)

	hasPasswordInput := passwordInputRe.MatchString(lowerHTML)
	authKeyword := containsAny(lowerText, []string{
		"unauthorized",
		"forbidden",
		"authentication required",
		"authorization required",
		"please login",
		"please log in",
		"sign in",
		"login failed",
		"invalid password",
		"incorrect password",
		"invalid session",
	})
	loginPath := containsAny(lowerHTML, []string{
		"/login",
		"login.asp",
		"login.htm",
		"login.html",
		"login.cgi",
		"doc/page/login",
	})

	if hasPasswordInput || loginPath || authKeyword {
		result.AuthRequired = true
		result.LoginDetected = true
		if hasPasswordInput {
			result.Evidence = append(result.Evidence, "Rod rendered a password input")
		}
		if result.Title != "" {
			result.Evidence = append(result.Evidence, "Rod rendered page title: "+result.Title)
		}
		return
	}

	hasMedia := containsAny(lowerHTML, []string{"<video", "<canvas", "<object", "<embed"}) ||
		(strings.Count(lowerHTML, "<img") >= 2 && !containsAny(lowerText, []string{"login", "sign in"}))
	cameraKeyword := containsAny(lowerText, []string{
		"live view",
		"live video",
		"live stream",
		"snapshot",
		"mjpeg",
		"stream",
		"channel",
		"ptz",
		"playback",
		"surveillance",
		"network camera",
		"ip camera",
		"webcam",
		"dvr",
		"nvr",
		"hikvision",
		"dahua",
		"axis",
	})

	result.BlankPage = len(text) < 40 && !hasMedia
	if result.BlankPage {
		result.Evidence = append(result.Evidence, "Rod rendered a blank or minimal page")
		return
	}

	if cameraKeyword && (hasMedia || len(text) >= 80) {
		result.OpenContent = true
		if result.Title != "" {
			result.Evidence = append(result.Evidence, "Rod rendered page title: "+result.Title)
		}
		if hasMedia {
			result.Evidence = append(result.Evidence, "Rod rendered camera media-related DOM elements")
		}
		result.Evidence = append(result.Evidence, "Rod rendered camera-related page content without a login form")
		return
	}

	result.Evidence = append(result.Evidence, "Rod did not confirm accessible camera content")
}

func classifyPostLoginHTML(result *HTTPValidation, html string) {
	result.Reachable = true
	result.Title = extractTitle(html)
	text := visibleText(html)
	result.TextSample = truncate(text, 220)

	lowerHTML := strings.ToLower(html)
	lowerText := strings.ToLower(text)
	hasMedia, cameraKeyword := cameraContentSignals(lowerHTML, lowerText)

	result.BlankPage = len(text) < 40 && !hasMedia
	if result.BlankPage {
		result.Evidence = append(result.Evidence, "Rod rendered a blank or minimal page after login submission")
		return
	}

	if cameraKeyword && (hasMedia || len(text) >= 80) {
		result.OpenContent = true
		if result.Title != "" {
			result.Evidence = append(result.Evidence, "Rod rendered post-login page title: "+result.Title)
		}
		if hasMedia {
			result.Evidence = append(result.Evidence, "Rod rendered post-login camera media-related DOM elements")
		}
		result.Evidence = append(result.Evidence, "Rod rendered camera-related page content after login submission")
		return
	}

	if passwordInputRe.MatchString(lowerHTML) || containsAny(lowerText, []string{
		"unauthorized",
		"forbidden",
		"authentication required",
		"authorization required",
		"please login",
		"please log in",
		"sign in",
		"login failed",
		"invalid password",
		"incorrect password",
		"invalid session",
	}) {
		result.AuthRequired = true
		result.LoginDetected = true
		result.Evidence = append(result.Evidence, "Rod still rendered an authentication/login page after login submission")
		return
	}

	result.Evidence = append(result.Evidence, "Rod did not confirm accessible camera content after login submission")
}

func cameraContentSignals(lowerHTML, lowerText string) (bool, bool) {
	hasMedia := containsAny(lowerHTML, []string{"<video", "<canvas", "<object", "<embed"}) ||
		(strings.Count(lowerHTML, "<img") >= 2 && !containsAny(lowerText, []string{"login", "sign in"}))
	cameraKeyword := containsAny(lowerText, []string{
		"live view",
		"live video",
		"live stream",
		"snapshot",
		"mjpeg",
		"stream",
		"channel",
		"ptz",
		"playback",
		"surveillance",
		"network camera",
		"ip camera",
		"webcam",
		"dvr",
		"nvr",
		"hikvision",
		"dahua",
		"axis",
	})
	return hasMedia, cameraKeyword
}

func extractTitle(html string) string {
	matches := titleRe.FindStringSubmatch(html)
	if len(matches) < 2 {
		return ""
	}
	return truncate(spaceRe.ReplaceAllString(strings.TrimSpace(matches[1]), " "), 120)
}

func visibleText(html string) string {
	text := scriptStyleRe.ReplaceAllString(html, " ")
	text = tagRe.ReplaceAllString(text, " ")
	text = strings.ReplaceAll(text, "&nbsp;", " ")
	text = strings.ReplaceAll(text, "&amp;", "&")
	text = strings.ReplaceAll(text, "&lt;", "<")
	text = strings.ReplaceAll(text, "&gt;", ">")
	return strings.TrimSpace(spaceRe.ReplaceAllString(text, " "))
}

func containsAny(s string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max]) + "..."
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}
