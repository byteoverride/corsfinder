
# 🎯 corsfinder: Go-based CORS Misconfiguration Scanner

**`corsfinder`** is a fast, highly configurable, and concurrent command-line tool written in Go for discovering Cross-Origin Resource Sharing (CORS) misconfigurations, including dynamic origin reflection and improper credential handling.

It is designed for professional penetration testers and bug bounty hunters, featuring both **safe** (passive) and **aggressive** (credential-aware) scanning modes.

## ✨ Features

`corsfinder` is built for speed and reliability, incorporating numerous features essential for real-world testing.

  * **Two Scanning Modes:** **Safe** (passive) and **Aggressive** (cookie-aware).
  * **Dual Request Methods:** Automatically performs both **GET** and **OPTIONS** (preflight) requests.
  * **Dynamic Reflection Check:** Detects dangerous misconfigurations where the server dynamically reflects the attacker's origin.
  * **Credential Check (ACAC):** Specifically flags results when `Access-Control-Allow-Credentials: true` is present.
  * **Concurrency:** High-performance, concurrent scanning with configurable worker count (`-concurrency`).
  * **Politeness (Jitter & Delay):** Configurable base delay with **random jitter** enabled by default.
  * **Automatic Throttling:** Backs off upon receiving common rate-limit/block codes (`429`, `403`).
  * **Input Pipeline:** Reads targets directly from `stdin` (e.g., `cat hosts | corsfinder ...`).
  * **HTTPS → HTTP Fallback:** Automatically retries the scan over `http://` if the initial `https://` connection fails.
  * **WordPress Awareness:** Tests the default `/wp-json` endpoint and can be extended to include `/xmlrpc.php` and `/wp-admin/admin-ajax.php` using the `-wp` flag.
  * **Customization:** Supports custom headers (`-H`) and traffic routing via a proxy (`-proxy`).
  * **Flexible Output:** Supports human-readable text (default), **JSON lines (`-json`)**, or **CSV (`-csv`)**.
  * **False Positive Tagging:** Flags results that are likely to be False Positives for manual review.

-----

## 🚀 Installation

The simplest way to install `corsfinder` is using the `go install` command.

### Prerequisites

  * **Go (Golang)** environment installed (version 1.18 or higher recommended).
  * Ensure your **`$GOPATH/bin`** directory is in your system's **`$PATH`** environment variable.

### 1\. Install via `go install`

Run the following command to download, build, and install the executable directly:

```bash
go install github.com/byteoverride/corsfinder@latest
```

The `corsfinder` binary will be placed in your `$GOPATH/bin` directory, making it immediately executable from your terminal.

-----

## 💡 Usage

`corsfinder` is designed to be used with a list of domains piped to its standard input (`stdin`).

### Basic Syntax

```bash
cat hosts.txt | corsfinder [flags]
```

### Example: Safe Scan with Default Settings

This runs a safe scan, uses `evil.com` as the Origin header, and tests only the default `/wp-json` path.

```bash
cat domains.txt | corsfinder -mode safe -origin attacker.site
```

### Example: Aggressive Credential Scan via Burp

This runs an aggressive scan, includes cookies, enables the full WordPress endpoint list, and routes all traffic through Burp Suite on the default port.

```bash
cat domains.txt | corsfinder -mode aggressive \
    -cookie "sessionid=abc12345; token=xyz" \
    -wp \
    -proxy "http://127.0.0.1:8080"
```

### Example: Highly Concurrent Scan with Custom Headers (JSON Output)

This sets a high concurrency, a faster delay, and adds a custom header required by the API.

```bash
cat domains.txt | corsfinder -mode safe \
    -concurrency 50 \
    -delay 40ms \
    -H "Accept: application/json" \
    -json
```

-----

## 🔧 Full Flag Reference

| Flag | Abbr. | Description | Default |
| :--- | :--- | :--- | :--- |
| `-mode` | | Scan mode: `safe` or `aggressive`. | `safe` |
| `-cookie` | | Cookie string to send (only in aggressive mode). | `""` |
| `-origin` | `o` | Origin header value to send (the attacker domain). | `evil.com` |
| `-wp` | | Scan additional WordPress endpoints. | `false` |
| `-H` | | Custom header to include (`Name: value`). Can be repeated. | `""` |
| `-headers` | | Convenience: comma-separated custom headers (`Name: v,Another: v2`). | `""` |
| `-proxy` | `p` | Proxy URL for traffic routing (e.g., `http://127.0.0.1:8080`). | `""` |
| `-concurrency` | `c` | Global concurrency (number of workers). | Mode default |
| `-delay` | `d` | Base delay between requests (e.g., `150ms`). | Mode default |
| `-timeout` | `t` | Per request timeout (e.g., `12s`). | `12s` |
| `-insecure` | | Skip TLS certificate verification. | `false` |
| `-nojitter` | | Disable random jitter (politeness). | `false` |
| `-onlyhttps` | `oh` | Do not fallback to HTTP if HTTPS fails. | `false` |
| `-json` | | Output JSON lines instead of human-readable text. | `false` |
| `-csv` | | Output CSV instead of human-readable text. | `false` |
| `-retries` | `r` | Number of retries on transient errors. | Mode default |
| `-tags` | | Global tags string to override CLI flags (e.g., `<mode=aggr> <rc=6>`). | `""` |

## 🏷️ Per-Host Tags (Advanced)

For advanced control, you can embed configuration overrides directly into your input list using tags. This allows different domains to be scanned with different concurrency or delay settings.

**Input Example:**

```
example.com <mode=aggressive> <rc=20> <d=50ms>
dog.com <mode=safe> <throttle_on=429>
api.example.org
```

| Full Tag | Abbreviation | Description | Example Value |
| :--- | :--- | :--- | :--- |
| `<mode>` | `<m>` | Scan mode: `safe` or `aggressive`. | `aggr` |
| `<req_concurrency>` | `<rc>`/`<c>` | Number of concurrent requests. | `10` |
| `<delay>` | `<d>` | Base delay between requests (Go duration format). | `150ms` |
| `<throttle_on>` | `<to>` | Comma-separated status codes for throttling. | `429,403` |
| `<jitter>` | `<j>` | Disable jitter. | `off` |
| `<cookie>` | `<ck>` | Cookie string for this host. | `"a=b"` |
| `<proxy>` | `<p>` | Proxy URL for this host. | `http://127.0.0.1:8080` |
| `<wp>` | | Enable full WP scan for this host. | |
| `<nowp>` | | Disable WP scan for this host. | |
