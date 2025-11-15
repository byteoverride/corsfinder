// corsfinder.go
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------------------------
// Types & Config Structures
// ---------------------------

type Mode string

const (
	ModeSafe      Mode = "safe"
	ModeAggressive     = "aggressive"
)

type ScanConfig struct {
	Mode          Mode
	Concurrency   int           // number of parallel workers
	BaseDelay     time.Duration // base delay between requests per-worker
	Jitter        bool          // random jitter enabled
	JitterMinMs   int           // jitter minimum (ms) added
	JitterMaxMs   int           // jitter maximum (ms) added
	ThrottleCodes []int         // status codes to trigger throttling/backoff
	Timeout       time.Duration // per-request timeout
	Cookie        string        // cookie header (used in aggressive)
	Origin        string        // attacker origin header
	WP            bool          // test additional WP endpoints
	Headers       http.Header   // custom headers to include in requests
	Proxy         string        // proxy URL (e.g., http://127.0.0.1:8080)
	Insecure      bool          // skip TLS verify
	OnlyHttps     bool          // if set, do not fallback to http
	ModeName      string        // for JSON output (human)
	Retries       int           // number of retries on connection error
	CSV           bool
	JSONOut       bool
}

type Job struct {
	Domain string
	Tags   string // raw tag string if present on the same line
}

type Result struct {
	URL                      string            `json:"url"`
	Domain                   string            `json:"domain"`
	Path                     string            `json:"path"`
	Status                   int               `json:"status"`
	ACAO                     string            `json:"access_control_allow_origin,omitempty"`
	ACAC                     string            `json:"access_control_allow_credentials,omitempty"`
	ReflectedBody            bool              `json:"reflected_in_body"`
	ReflectedHeaderValues    map[string]string `json:"reflected_headers,omitempty"`
	Method                   string            `json:"method"` // GET or OPTIONS
	DurationMs               int64             `json:"duration_ms"`
	Mode                     string            `json:"mode"`
	ModeAggressiveCookieUsed bool              `json:"aggressive_cookie_used"`
	Severity                 string            `json:"severity"`
	FP                       bool              `json:"possible_false_positive"`
	Headers                  map[string]string `json:"headers_snapshot,omitempty"`
	BodySnippet              string            `json:"body_snippet,omitempty"`
	Error                    string            `json:"error,omitempty"`
}

// ---------------------------
// Utility / Defaults
// ---------------------------

var (
	defaultSafeConfig = ScanConfig{
		Mode:        ModeSafe,
		Concurrency: 2,
		BaseDelay:   150 * time.Millisecond,
		Jitter:      true,
		JitterMinMs: 30,
		JitterMaxMs: 70,
		ThrottleCodes: []int{
			429, 403,
		},
		Timeout:   12 * time.Second,
		Cookie:    "",
		Origin:    "evil.com",
		WP:        false,
		Headers:   http.Header{},
		Proxy:     "",
		Insecure:  false,
		OnlyHttps: false,
		Retries:   1,
		JSONOut:   false,
		CSV:       false,
	}
	defaultAggressiveConfig = ScanConfig{
		Mode:        ModeAggressive,
		Concurrency: 12,
		BaseDelay:   40 * time.Millisecond,
		Jitter:      true,
		JitterMinMs: 20,
		JitterMaxMs: 80,
		ThrottleCodes: []int{
			429, 403,
		},
		Timeout:   12 * time.Second,
		Cookie:    "",
		Origin:    "evil.com",
		WP:        true,
		Headers:   http.Header{},
		Proxy:     "",
		Insecure:  false,
		OnlyHttps: false,
		Retries:   1,
		JSONOut:   false,
		CSV:       false,
	}
)

// ---------------------------
// Tag parsing (global + per-host)
// Supports full names and abbreviations.
// ---------------------------

var tagRe = regexp.MustCompile(`<([^>]+)>`)

func parseTagsToConfig(tagStr string, base ScanConfig) ScanConfig {
	out := base
	if tagStr == "" {
		return out
	}
	matches := tagRe.FindAllStringSubmatch(tagStr, -1)
	for _, m := range matches {
		content := strings.TrimSpace(m[1])
		parts := strings.SplitN(content, "=", 2)
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := ""
		if len(parts) > 1 {
			val = strings.TrimSpace(parts[1])
		}
		switch key {
		case "mode", "m":
			switch val {
			case "safe", "s":
				out.Mode = ModeSafe
			case "aggressive", "aggr", "a":
				out.Mode = ModeAggressive
			}
		case "req_concurrency", "rc", "concurrency", "c":
			if v, err := strconv.Atoi(val); err == nil && v > 0 {
				out.Concurrency = v
			}
		case "delay", "d":
			if d, err := time.ParseDuration(val); err == nil {
				out.BaseDelay = d
			}
		case "throttle_on", "to":
			parts := strings.Split(val, ",")
			out.ThrottleCodes = []int{}
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if v, err := strconv.Atoi(p); err == nil {
					out.ThrottleCodes = append(out.ThrottleCodes, v)
				}
			}
		case "jitter", "j":
			if val == "off" || val == "false" || val == "0" {
				out.Jitter = false
			} else {
				out.Jitter = true
			}
		case "cookie", "ck":
			out.Cookie = val
		case "origin", "o":
			if val != "" {
				out.Origin = val
			}
		case "wp":
			out.WP = true
		case "nowp":
			out.WP = false
		case "proxy", "p":
			out.Proxy = val
		case "insecure":
			out.Insecure = true
		case "onlyhttps", "oh":
			out.OnlyHttps = true
		case "timeout", "t":
			if d, err := time.ParseDuration(val); err == nil {
				out.Timeout = d
			}
		case "retries", "r":
			if v, err := strconv.Atoi(val); err == nil {
				out.Retries = v
			}
		case "json":
			out.JSONOut = true
		case "csv":
			out.CSV = true
		}
	}
	return out
}

// ---------------------------
// Helper: jitter computation
// ---------------------------

func computeDelay(base time.Duration, jitter bool, minMs, maxMs int) time.Duration {
	if !jitter {
		return base
	}
	extra := 0
	if maxMs > 0 && maxMs >= minMs {
		extra = rand.Intn(maxMs-minMs+1) + minMs
	} else {
		extra = rand.Intn(50) + 30
	}
	return base + time.Duration(extra)*time.Millisecond
}

// ---------------------------
// HTTP helpers
// ---------------------------

func makeHttpClient(cfg ScanConfig) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 100,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: cfg.Insecure},
	}
	if cfg.Proxy != "" {
		proxyUrl, err := url.Parse(cfg.Proxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyUrl)
		} else {
			fmt.Fprintf(os.Stderr, "warning: invalid proxy URL '%s': %v\n", cfg.Proxy, err)
		}
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   cfg.Timeout,
	}
	return client
}

// ---------------------------
// Vulnerability detection logic
// ---------------------------

func analyzeResponse(domain, path, method string, duration time.Duration, resp *http.Response, bodySnippet string, origin string, cookieUsed bool) Result {
	r := Result{
		URL:                      resp.Request.URL.String(),
		Domain:                   domain,
		Path:                     path,
		Method:                   method,
		DurationMs:               duration.Milliseconds(),
		Status:                   resp.StatusCode,
		ModeAggressiveCookieUsed: cookieUsed,
		ReflectedHeaderValues:    map[string]string{},
		Headers:                  map[string]string{},
		BodySnippet:              bodySnippet,
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			if len(v[0]) > 200 {
				r.Headers[k] = v[0][:200]
			} else {
				r.Headers[k] = v[0]
			}
		}
	}

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")
	r.ACAO = acao
	r.ACAC = acac

	low := strings.ToLower(acao)
	orig := strings.ToLower(origin)
	vuln := false
	severity := "low"

	if acao != "" {
		if low == "*" {
			severity = "low"
			vuln = true
		}
		if strings.Contains(low, orig) || low == orig {
			vuln = true
			if strings.Contains(low, orig) && strings.Contains(strings.ToLower(acac), "true") {
				severity = "critical"
			} else if low == orig {
				severity = "high"
			} else {
				severity = "medium"
			}
		}
	}

	if bodySnippet != "" {
		if strings.Contains(strings.ToLower(bodySnippet), orig) {
			r.ReflectedBody = true
			vuln = true
			if severity == "low" {
				severity = "medium"
			}
		}
	}
	for hn, hv := range resp.Header {
		for _, v := range hv {
			if strings.Contains(strings.ToLower(v), orig) {
				r.ReflectedHeaderValues[hn] = v
				vuln = true
				if severity == "low" {
					severity = "medium"
				}
			}
		}
	}

	if vuln && strings.Contains(strings.ToLower(acac), "true") && strings.Contains(strings.ToLower(acao), orig) {
		severity = "critical"
	}
	if vuln && strings.Contains(strings.ToLower(acao), "*") && strings.Contains(strings.ToLower(acac), "true") {
		severity = "high"
	}

	r.Severity = severity
	r.FP = false

	if acao == "" && r.ReflectedBody && resp.StatusCode >= 200 && resp.StatusCode < 500 {
		r.FP = true
	}

	return r
}

// ---------------------------
// Worker: performs GET and OPTIONS and returns results
// - TRY HTTPS first, if that "succeeds" use it (do not test HTTP).
// - If HTTPS yields transport error (no response), fall back to HTTP.
// ---------------------------

func performCheckForTarget(client *http.Client, cfg ScanConfig, domain string, baseUrl string, path string, method string, cookieUsed bool) Result {
	full := strings.TrimRight(baseUrl, "/") + path
	start := time.Now()
	req, err := http.NewRequest(method, full, nil)
	if err != nil {
		return Result{URL: full, Domain: domain, Path: path, Error: err.Error()}
	}
	req.Header.Set("Origin", cfg.Origin)
	req.Header.Set("User-Agent", "corsfinder/1.0")
	if cookieUsed && cfg.Cookie != "" {
		req.Header.Set("Cookie", cfg.Cookie)
	}
	if strings.ToUpper(method) == "OPTIONS" {
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "Content-Type, Authorization, X-Requested-With")
	}
	for k, vals := range cfg.Headers {
		for _, v := range vals {
			req.Header.Set(k, v)
		}
	}
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return Result{URL: full, Domain: domain, Path: path, Error: err.Error()}
	}
	defer resp.Body.Close()
	limit := int64(5120) // 5KB
	limited := io.LimitReader(resp.Body, limit)
	tmp, _ := io.ReadAll(limited)
	bodySnippet := string(tmp)
	res := analyzeResponse(domain, path, method, duration, resp, bodySnippet, cfg.Origin, cookieUsed)
	return res
}

// ---------------------------
// Main scanning flow (worker)
// ---------------------------

func worker(id int, cfg ScanConfig, jobs <-chan Job, results chan<- Result, wg *sync.WaitGroup, client *http.Client, globalTags ScanConfig) {
	defer wg.Done()
	for job := range jobs {
		perCfg := parseTagsToConfig(job.Tags, cfg)

		paths := []string{"/wp-json"}
		if perCfg.WP {
			paths = []string{"/wp-json", "/xmlrpc.php", "/wp-admin/admin-ajax.php"}
		}

		// For each path, try https first; if transport error, try http fallback (if allowed)
		for _, p := range paths {
			// per-job delay
			delay := computeDelay(perCfg.BaseDelay, perCfg.Jitter, perCfg.JitterMinMs, perCfg.JitterMaxMs)
			time.Sleep(delay)

			// choose cookie usage
			cookieUsed := false
			if perCfg.Mode == ModeAggressive && perCfg.Cookie != "" {
				cookieUsed = true
			}

			// === START FIX FOR SCHEME HANDLING ===
			candidates := []string{}
			domain := strings.TrimSuffix(job.Domain, "/")
			
			// Check if a scheme is already present in the input domain
			hasScheme := strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://")

			if hasScheme {
				// Scheme is present, use it as is
				candidates = append(candidates, domain)

				// If https was provided and OnlyHttps is false, add http as fallback
				if !perCfg.OnlyHttps && strings.HasPrefix(domain, "https://") {
					httpFallback := strings.Replace(domain, "https://", "http://", 1)
					candidates = append(candidates, httpFallback)
				}
			} else {
				// No scheme is present, prepend both https and http (if not OnlyHttps)
				candidates = append(candidates, "https://"+domain)
				if !perCfg.OnlyHttps {
					candidates = append(candidates, "http://"+domain)
				}
			}
			// === END FIX FOR SCHEME HANDLING ===

			chosenBase := ""
			var getRes Result
			var optsRes Result

			// Try bases sequentially: pick first that returns a response (no transport error).
			for _, base := range candidates {
				// GET
				getRes = performCheckForTarget(client, perCfg, job.Domain, base, p, "GET", cookieUsed)
				// If we got an error that looks like transport (no response), try next candidate.
				transportErr := (getRes.Error != "" && (strings.Contains(strings.ToLower(getRes.Error), "tls") ||
					strings.Contains(strings.ToLower(getRes.Error), "connection refused") ||
					strings.Contains(strings.ToLower(getRes.Error), "no such host") ||
					strings.Contains(strings.ToLower(getRes.Error), "dial tcp")))
				if transportErr && base == "https://"+job.Domain {
					// try next candidate (http) - continue loop
					// record GET error result but don't output it now; we will output only chosenBase results
					// move to next base
					// try next base
					// continue
				} else {
					// we have a usable base (either https worked or http responded)
					chosenBase = base
					// perform OPTIONS on same base
					optsRes = performCheckForTarget(client, perCfg, job.Domain, base, p, "OPTIONS", cookieUsed)
					break
				}
			}

			// If no chosen base (both transport errored), output last GET error (as error)
			if chosenBase == "" {
				// emit the last getRes (likely with error)
				getRes.Mode = string(perCfg.Mode)
				getRes.ModeAggressiveCookieUsed = cookieUsed
				results <- getRes
				continue
			}

			// emit GET then OPTIONS for chosenBase
			getRes.Mode = string(perCfg.Mode)
			getRes.ModeAggressiveCookieUsed = cookieUsed
			results <- getRes

			optsRes.Mode = string(perCfg.Mode)
			optsRes.ModeAggressiveCookieUsed = cookieUsed
			results <- optsRes

			// If either status matches throttle codes - backoff
			shouldThrottle := false
			for _, code := range perCfg.ThrottleCodes {
				if getRes.Status == code || optsRes.Status == code {
					shouldThrottle = true
					break
				}
			}
			if shouldThrottle {
				backoff := time.Duration(150+rand.Intn(250)) * time.Millisecond
				time.Sleep(backoff)
			}
		}
	}
}

// ---------------------------
// Input scanner & tag extraction
// ---------------------------

func extractTagsFromLine(line string) (domain string, tags string) {
	tagMatches := tagRe.FindAllString(line, -1)
	if len(tagMatches) == 0 {
		return strings.TrimSpace(line), ""
	}
	clean := tagRe.ReplaceAllString(line, "")
	clean = strings.TrimSpace(clean)
	tagsJoined := strings.Join(tagMatches, " ")
	return clean, tagsJoined
}

// ---------------------------
// Output helpers (Style A with ANSI colors)
// ---------------------------

const (
	ansiReset = "\033[0m"
	ansiRed   = "\033[31m"
	ansiGreen = "\033[32m"
	ansiYellow= "\033[33m"
	ansiCyan  = "\033[36m"
)

func classifyAndPrint(r Result, origin string, jsonOut bool, csvWriter *csv.Writer, csvMode bool) {
	// Decide label and color
	label := "NO-VULN"
	emoji := "🟥"
	color := ansiRed

	// If error: show as error (yellow)
	if r.Error != "" {
		label = "ERROR"
		emoji = "🔶"
		color = ansiYellow
	} else {
		// determine vulnerability based on severity or headers/reflections
		sev := strings.ToLower(r.Severity)
		acaoLower := strings.ToLower(r.ACAO)
		hasACAO := strings.TrimSpace(r.ACAO) != ""
		hasReflection := r.ReflectedBody || len(r.ReflectedHeaderValues) > 0
		hasACAC := strings.Contains(strings.ToLower(r.ACAC), "true")

		isVuln := false
		if sev == "critical" || sev == "high" || sev == "medium" {
			isVuln = true
		}
		// Additional signal: ACAO contains origin or ACAC true with ACAO set
		if hasACAO && origin != "" && strings.Contains(acaoLower, strings.ToLower(origin)) {
			isVuln = true
		}
		if hasACAO && strings.TrimSpace(r.ACAO) == "*" && hasACAC {
			isVuln = true
		}
		// If vulnerability signalled
		if isVuln {
			label = "VULN"
			emoji = "🟩"
			color = ansiGreen
		} else {
			// mark NO-VULN for common non-vuln statuses
			if !hasACAO && (r.Status == 404 || r.Status == 403 || r.Status == 401 || r.Status == 500) {
				label = "NO-VULN"
				emoji = "🟥"
				color = ansiRed
			} else if hasACAO && hasReflection == false {
				// ACAO present but no reflection and not matching origin => medium/info
				label = "INFO"
				emoji = "🔷"
				color = ansiCyan
			} else if hasReflection && !hasACAO {
				// reflected body but no ACAO header alone -> likely FP
				label = "POSSIBLE"
				emoji = "⚠️"
				color = ansiYellow
			}
		}
	}

	// If JSON or CSV mode requested by flags, printing is handled elsewhere; but keep JSON here if asked
	if jsonOut {
		printResultJSON(r)
		return
	}
	if csvMode && csvWriter != nil {
		printResultCSV(csvWriter, r)
		return
	}

	// STYLE A: single-line header + details line
	// Header:
	fmt.Printf("%s%s %s %s → %s%s\n", color, emoji, "["+label+"]", r.Domain, r.URL, ansiReset)
	// details: status, ACAO, ACAC, reflected, method
	acao := r.ACAO
	if acao == "" {
		acao = "-"
	}
	acac := r.ACAC
	if acac == "" {
		acac = "-"
	}
	fmt.Printf("  status=%d  ACAO=%s  ACAC=%s  reflected=%v  method=%s\n\n",
		r.Status, acao, acac, r.ReflectedBody, r.Method)
}

// Existing print helpers (used by earlier JSON/CSV flows)
func printResultText(r Result) {
	sev := strings.ToUpper(r.Severity)
	if r.Error != "" {
		fmt.Printf("[%s] %s %s %s ERROR: %s\n", "ERR", r.Domain, r.Path, r.URL, r.Error)
		return
	}
	fp := ""
	if r.FP {
		fp = " FP"
	}
	fmt.Printf("[%s] %s %s %s | status=%d | ACAO=%s | ACAC=%s | reflected_body=%v | method=%s%s\n",
		sev, r.Domain, r.Path, r.URL, r.Status, r.ACAO, r.ACAC, r.ReflectedBody, r.Method, fp)
}

func printResultJSON(r Result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

func printResultCSV(w *csv.Writer, r Result) {
	row := []string{
		r.Domain,
		r.Path,
		r.URL,
		strconv.Itoa(r.Status),
		r.ACAO,
		r.ACAC,
		strconv.FormatBool(r.ReflectedBody),
		strings.ToUpper(r.Severity),
		strconv.FormatBool(r.FP),
		r.Method,
	}
	_ = w.Write(row)
	w.Flush()
}

// ---------------------------
// Main
// ---------------------------

func main() {
	rand.Seed(time.Now().UnixNano())

	// CLI flags (global)
	flagMode := flag.String("mode", "safe", "scan mode: safe or aggressive (overridable per-host via tags)")
	flagCookie := flag.String("cookie", "", "cookie string to send in aggressive mode (e.g., 'sess=abc; other=1')")
	flagOrigin := flag.String("origin", "evil.com", "Origin header value to send")
	flagWP := flag.Bool("wp", false, "scan additional Wordpress endpoints (/xmlrpc.php, /wp-admin/admin-ajax.php)")
	flagProxy := flag.String("proxy", "", "proxy URL (e.g., http://127.0.0.1:8080)")
	flagConcurrency := flag.Int("concurrency", 0, "global concurrency (overrides mode default). 0 = use mode default")
	flagDelay := flag.String("delay", "", "base delay between requests (e.g., 150ms). if empty uses mode default")
	flagTimeout := flag.String("timeout", "", "per request timeout (e.g., 12s)")
	flagInsecure := flag.Bool("insecure", false, "skip TLS verification")
	flagJitterOff := flag.Bool("nojitter", false, "disable jitter globally (enabled by default)")
	flagOnlyHttps := flag.Bool("onlyhttps", false, "do not fallback to http if https fails")
	flagJSON := flag.Bool("json", false, "output JSON lines")
	flagCSV := flag.Bool("csv", false, "output CSV")
	flagHeader := flag.String("H", "", "custom header to include (format: 'Name: value'). Repeat flag by providing comma-separated multiple headers")
	flagHeadersMany := flag.String("headers", "", "additional convenience: comma-separated custom headers 'Name: v,Another: v2'")
	flagRetries := flag.Int("retries", -1, "number of retries on transient errors (default from mode)")
	flagTags := flag.String("tags", "", "global tags string (like '<mode=aggr> <rc=6> <d=80ms>') to apply to all jobs (overridable per-host)")
	flagHelp := flag.Bool("help", false, "show help")
	flag.Parse()

	if *flagHelp {
		flag.Usage()
		return
	}

	// build base config
	var cfg ScanConfig
	if strings.ToLower(*flagMode) == "aggressive" || strings.ToLower(*flagMode) == "aggr" || strings.ToLower(*flagMode) == "a" {
		cfg = defaultAggressiveConfig
	} else {
		cfg = defaultSafeConfig
	}

	// override with CLI options
	if *flagConcurrency > 0 {
		cfg.Concurrency = *flagConcurrency
	}
	if *flagDelay != "" {
		if d, err := time.ParseDuration(*flagDelay); err == nil {
			cfg.BaseDelay = d
		} else {
			fmt.Fprintf(os.Stderr, "invalid -delay: %v\n", err)
		}
	}
	if *flagTimeout != "" {
		if d, err := time.ParseDuration(*flagTimeout); err == nil {
			cfg.Timeout = d
		} else {
			fmt.Fprintf(os.Stderr, "invalid -timeout: %v\n", err)
		}
	}
	if *flagCookie != "" {
		cfg.Cookie = *flagCookie
	}
	if *flagOrigin != "" {
		cfg.Origin = *flagOrigin
	}
	if *flagWP {
		cfg.WP = true
	}
	if *flagProxy != "" {
		cfg.Proxy = *flagProxy
	}
	if *flagInsecure {
		cfg.Insecure = true
	}
	if *flagJitterOff {
		cfg.Jitter = false
	}
	if *flagOnlyHttps {
		cfg.OnlyHttps = true
	}
	if *flagJSON {
		cfg.JSONOut = true
	}
	if *flagCSV {
		cfg.CSV = true
	}
	if *flagRetries >= 0 {
		cfg.Retries = *flagRetries
	}

	// parse headers
	if *flagHeader != "" {
		parts := strings.Split(*flagHeader, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			hparts := strings.SplitN(p, ":", 2)
			if len(hparts) != 2 {
				fmt.Fprintf(os.Stderr, "invalid header format: %s\n", p)
				continue
			}
			name := strings.TrimSpace(hparts[0])
			value := strings.TrimSpace(hparts[1])
			cfg.Headers.Set(name, value)
		}
	}
	if *flagHeadersMany != "" {
		parts := strings.Split(*flagHeadersMany, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			hparts := strings.SplitN(p, ":", 2)
			if len(hparts) != 2 {
				fmt.Fprintf(os.Stderr, "invalid header format: %s\n", p)
				continue
			}
			name := strings.TrimSpace(hparts[0])
			value := strings.TrimSpace(hparts[1])
			cfg.Headers.Set(name, value)
		}
	}

	// apply global tags override if present
	if *flagTags != "" {
		cfg = parseTagsToConfig(*flagTags, cfg)
	}

	// ensure some sane bounds
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.BaseDelay < 0 {
		cfg.BaseDelay = 0
	}
	if cfg.Timeout < 1*time.Second {
		cfg.Timeout = 5 * time.Second
	}

	// Prepare HTTP client (shared). We will reuse client for everything.
	client := makeHttpClient(cfg)

	// Prepare worker pool
	jobs := make(chan Job, cfg.Concurrency*2)
	results := make(chan Result, cfg.Concurrency*4)
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cfg.Concurrency; i++ {
		wg.Add(1)
		go worker(i, cfg, jobs, results, &wg, client, cfg)
	}

	// Start a goroutine to read stdin and feed jobs
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			domain, tags := extractTagsFromLine(line)
			if domain == "" {
				continue
			}
			j := Job{Domain: domain, Tags: tags}
			jobs <- j
		}
		close(jobs)
		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "error reading stdin: %v\n", err)
		}
	}()

	// Output handling goroutine
	var csvWriter *csv.Writer
	if cfg.CSV {
		csvWriter = csv.NewWriter(os.Stdout)
		header := []string{"domain", "path", "url", "status", "acao", "acac", "reflected_body", "severity", "possible_fp", "method"}
		_ = csvWriter.Write(header)
		csvWriter.Flush()
	}

	done := make(chan struct{})
	go func() {
		for r := range results {
			// Use new colored, styled output (Style A), unless JSON/CSV requested
			classifyAndPrint(r, cfg.Origin, cfg.JSONOut, csvWriter, cfg.CSV)
		}
		close(done)
	}()

	// Wait for workers to finish
	wg.Wait()
	// all workers done; close results
	close(results)
	// wait for output goroutine to finish
	<-done
}
