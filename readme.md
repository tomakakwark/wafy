# Wafy - Laravel Firewall & Malicious Request Detector

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP](https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg)
![Laravel](https://img.shields.io/badge/laravel-%5E8.0%7C%5E9.0%7C%5E10.0%7C%5E11.0%7C%5E12.0-FF2D20.svg)

**Wafy** is a robust Laravel package developed by **Bdsa** designed to automatically ban IP addresses and detect malicious requests, including SQL Injection, XSS, and more.

## Features

- 🛡️ **IP Banning**: Automatically block IPs engaging in suspicious activity.
- 🕵️ **Malicious Request Detection**: Detects SQLi, XSS, LFI, and RCE attempts.
- ⏱️ **Temporary & Permanent Bans**: Configurable ban durations.
- ⚙️ **Customizable Patterns**: Define your own regex patterns for detection.
- 🖥️ **Artisan Commands**: Easily manage banned IPs via CLI.

---

## Installation

### 1. Require with Composer

Add the package to your project:

```bash
composer require bdsa/wafy
```

### 2. Publish Configuration

Publish the configuration file and migrations:

```bash
php artisan vendor:publish --provider="Bdsa\Wafy\WafyServiceProvider"
```

### 3. Run Migrations

Create the `banned_ips` table:

```bash
php artisan migrate
```

---

## Usage

### Middleware

Wafy provides two key middlewares : BlockBannedIp & DetectMaliciousRequests.

#### Protecting Routes

Apply the middleware to your routes or groups:

```php

use Bdsa\Wafy\Middleware\BlockBannedIp;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;

Route::group(['middleware' => ['block.banned.ip', 'detect.malicious.requests']], function () {
    Route::get('/', function () {
        return view('welcome');
    });
    
    // Your protected routes
});
```

### Artisan Commands

Manage banned IPs directly from the terminal:

- **Ban an IP manually:**
  ```bash
  php artisan wafy:ban {ip_address} [--reason="Your reason"]
  ```

- **Unban an IP:**
  ```bash
  php artisan wafy:unban {ip_address}
  ```

- **List all banned IPs:**
  ```bash
  php artisan wafy:list
  ```

- **Enable/Disable WAF:**
  ```bash
  php artisan wafy:mode {enable|disable}
  ```

- **Set Action Mode (Block or Log-Only):**
  ```bash
  php artisan wafy:action {block|log}
  ```

- **Send a test notification** (verify your mail/Slack/Discord/Teams wiring):
  ```bash
  php artisan wafy:test-notification            # all configured channels
  php artisan wafy:test-notification --channel=discord
  ```
  Reports success/failure per channel and skips channels with no destination configured.

> **ℹ️ Note — `wafy:mode` and `wafy:action` are temporary runtime overrides.**
> These two commands store their state in the **cache**, so they are meant for
> momentary situations (testing, incident response). Any cache flush
> (`php artisan cache:clear`, `config:cache`, a deploy, a Redis restart…) resets
> them, and Wafy falls back to the values in `config/wafy.php`. To change the
> behaviour **permanently**, edit `config/wafy.php` (or the matching `WAFY_*`
> environment variables) — that is the source of truth.

---

## ⚠️ Running behind a reverse proxy / CDN (read this first)

Wafy identifies clients by IP (`$request->ip()`) and can **ban** them. If your
application runs behind a reverse proxy, load balancer or CDN (Nginx, Traefik,
Cloudflare, AWS ALB…), you **must** configure Laravel's `TrustProxies`
middleware so that `$request->ip()` returns the real client IP.

- If you **don't** configure trusted proxies, every request appears to come from
  the proxy. The first malicious request then bans your own proxy, cutting off
  **all** traffic.
- If you trust proxies with a blanket `*`, the `X-Forwarded-For` header becomes
  attacker-controlled: an attacker can spoof a clean IP to bypass bans, or forge
  a victim's IP to get it banned. Only trust the specific proxy ranges you use.

Also add your proxy / CDN ranges and any critical infrastructure to
`wafy.allowed_ips` (CIDR ranges are supported) so they can never be banned.

## Configuration

The configuration file is located at `config/wafy.php`. Besides the detection
patterns, the following options control how bans are applied:

| Key | Default | Description |
| --- | --- | --- |
| `ban_threshold` | `3` | Number of detections from one IP (within `strike_window` minutes) before it is banned. Kept above 1 so a single false positive doesn't lock out a legitimate (shared/NAT/mobile) IP. The offending request is always blocked regardless. |
| `strike_window` | `60` | Minutes over which strikes accumulate. |
| `ban_duration` | `1440` | Automatic ban lifetime in minutes (24h). Set to `null` for permanent bans. Manual `wafy:ban` bans are always permanent. |
| `score_threshold` | `4` | Minimum **accumulated rule score** before a request is **blocked** (403). See *Detection scoring* below. |
| `ban_score_threshold` | = `score_threshold` | Score at/above which a blocked request becomes **eligible for a persistent ban** (the actual escalation is still gated by `ban_threshold` strikes). Raise it to *block but not ban* medium threats; combine low thresholds with `ban_threshold=1` for strict *ban on first match*. |
| `ban_private_ips` | `false` | When `false` (default), Wafy **refuses to ban private/reserved/loopback IPs** — a strong sign that TrustProxies is misconfigured and `$request->ip()` is the proxy, so banning it would take down all traffic. Set to `true` only if your clients legitimately have private IPs (internal network, no proxy). |
| `max_scan_length` | `16384` | Max characters inspected per field — caps regex CPU cost (ReDoS protection). |
| `fail_open` | `true` | If the ban database is unreachable, let requests through (`true`) instead of returning 503 for everyone (`false`). |
| `scan_headers` | `['User-Agent', 'Referer', 'Cookie', 'X-Forwarded-For', 'X-Forwarded-Host', 'Origin', 'X-Api-Version']` | Request headers inspected for patterns. Only header **names** appear in logs, never their values. |
| `sensitive_keys` | passwords, tokens, card fields… | Input keys whose values are redacted before a request is stored or notified (body **and** query-string parameters). |
| `allowed_ips` | `[]` | IPs / CIDR ranges (IPv4 & IPv6) that bypass Wafy entirely. |

Default protection covers:
- **SQL Injection (SQLi)**: `UNION SELECT`, contextual `SELECT … FROM`/DML, **boolean tautologies / auth bypass** (`' OR '1'='1`, `admin'--`), **DDL** (`DROP/ALTER/TRUNCATE TABLE`), **stacked queries**, `INTO OUTFILE`, error-based (`extractvalue`/`updatexml`), time-based (`sleep`/`benchmark`), hex literals *in SQL context*.
- **Local File Inclusion (LFI)**: Directory traversal (`../`), system files (`/etc/passwd`, `/etc/shadow`), PHP wrappers (`php://`, `phar://`).
- **Cross-Site Scripting (XSS)**: Script tags, **all inline `on*` event handlers** (whitespace-tolerant), dangerous tags, `javascript:`, executable data URIs.
- **Remote Code Execution (RCE)**: Shell commands & separators (`;id`, `|whoami`), command substitution (`$(...)`), PHP execution functions.

### Detection scoring

Instead of banning on the **first** matching pattern, Wafy assigns each rule a
**score** and only acts once the **accumulated** score of all rules that match a
request reaches `score_threshold` (default `4`). Each rule counts once, no matter
how many fields it matches. This is the core defence against false positives: a
lone ambiguous signal (e.g. the word `select … from` in a support message) never
blocks legitimate traffic, while a strong rule (score ≥ threshold) or several
corroborating weak signals do.

Indicative scale: `5` = unambiguous attack (blocks alone) · `4` = strong · `3` =
medium (needs one more signal) · `2` = weak · `1` = hint.

Rules live in the `rules` array, each `['id' => …, 'score' => …, 'pattern' => …]`.
Disable a rule by removing it, tune sensitivity via its `score` or the global
`score_threshold`. Ban reasons/logs reference the stable rule **id** and the
total score (e.g. `WAF score 8/4 in RequestBody (rules: xss.script_tag, …)`).

**Blocking vs banning.** `score_threshold` decides when a request is *blocked*
(403); `ban_score_threshold` (default = `score_threshold`) decides when a blocked
request may *escalate to a persistent IP ban* — the escalation itself still needs
`ban_threshold` strikes. This lets you dial the whole spectrum:

| Goal | Settings |
| --- | --- |
| Strict — ban on the first match | `score_threshold=1`, `ban_score_threshold=1`, `ban_threshold=1` |
| Balanced (default) | `score_threshold=4`, `ban_score_threshold=4`, `ban_threshold=3` |
| Block medium threats but only ban strong/repeat ones | `score_threshold=4`, `ban_score_threshold=8` |

> **Backward compatibility:** a config still using the old flat `patterns` array
> (list of regex strings) keeps working — each pattern is scored at the threshold,
> preserving the pre-scoring "block on first match" behaviour until you migrate to
> `rules`.

Example `config/wafy.php`:

```php
return [
    'enabled' => env('WAFY_ENABLED', true),
    'score_threshold' => env('WAFY_SCORE_THRESHOLD', 4),
    'rules' => [
        ['id' => 'sqli.union_select', 'score' => 5, 'pattern' => '/(union(\s+all)?\s+select)/i'],
        ['id' => 'sqli.tautology',    'score' => 4, 'pattern' => '/\b(or|and)\s+([\'"`]?)(\w+)\2\s*(=|<>|!=|<|>|\blike\b)\s*([\'"`]?)\3\b/i'],
        ['id' => 'xss.script_tag',    'score' => 5, 'pattern' => '/(<script.*?>.*?<\/script>)/is'],
        // Add your own rules here…
    ],
    'allowed_ips' => [
        '127.0.0.1', // Localhost
        '192.168.1.1', // Office IP
    ],
    'notifications' => [
        'enabled' => env('WAFY_NOTIFICATIONS_ENABLED', false),
        'channels' => ['mail'], // any of: 'mail', 'slack', 'discord', 'teams'
        'email' => env('WAFY_NOTIFICATION_EMAIL', 'admin@example.com'),
        'slack_webhook' => env('WAFY_SLACK_WEBHOOK', ''),
        'discord_webhook' => env('WAFY_DISCORD_WEBHOOK', ''),
        'teams_webhook' => env('WAFY_TEAMS_WEBHOOK', ''),
    ],
];
```

### Notification channels

Wafy ships four channels, selected via `notifications.channels`:

| Channel | Destination config | Notes |
| --- | --- | --- |
| `mail` | `notifications.email` | Uses your app's mailer. |
| `slack` | `notifications.slack_webhook` | Requires `laravel/slack-notification-channel`. |
| `discord` | `notifications.discord_webhook` | Discord **Incoming Webhook** URL; posts a rich embed. No extra package. |
| `teams` | `notifications.teams_webhook` | Microsoft Teams **Incoming Webhook** URL; posts a MessageCard. No extra package. |

Discord and Teams POST directly to their webhook via Laravel's HTTP client, so no
third-party notification package is needed. Notifications are queued
(`ShouldQueue`) — a slow webhook never blocks the request. Verify your setup with
`php artisan wafy:test-notification`.

---

## Testing

To run the package tests:

```bash
vendor/bin/phpunit
```

---

## License

This project is licensed under the [MIT License](LICENSE).
