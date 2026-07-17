<?php

namespace Bdsa\Wafy\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Bdsa\Wafy\Concerns\HandlesClientIp;
use Bdsa\Wafy\Models\BannedIp;
use Bdsa\Wafy\Notifications\IpBannedNotification;

class DetectMaliciousRequests
{
    use HandlesClientIp;

    public function handle(Request $request, Closure $next)
    {
        $clientIp = $request->ip();

        // Check Allowed IPs (Whitelist) — supports single IPs and CIDR ranges.
        if ($this->isAllowed($clientIp)) {
            return $next($request);
        }

        // Check Cache first (runtime override), then Config (default)
        $isEnabled = cache()->get('wafy.enabled', config('wafy.enabled', true));

        if (!$isEnabled) {
            return $next($request);
        }

        // Canonical ban identity (IPv4 as-is; IPv6 collapsed to its /prefix).
        $identity = $this->banIdentity($clientIp);

        // Check action mode (block vs log)
        $action = cache('wafy.action', config('wafy.action', 'block'));

        // Fast early exit: if the IP is already under an ACTIVE ban, skip the
        // (relatively expensive) pattern matching. A cached "clean" marker lets
        // legitimate repeat traffic skip the DB lookup entirely. Expired bans
        // are ignored here and cleaned up by BlockBannedIp. Never fail the whole
        // app just because the ban store is momentarily unavailable.
        if ($action !== 'log' && !$this->isKnownClean($identity)) {
            try {
                $existing = BannedIp::forIp($identity)->first();
                if ($existing && $existing->isActive()) {
                    return $this->wafyBlock('banned', 'Votre IP est bannie.', 'banned', 403);
                }
                if (!$existing) {
                    $this->rememberClean($identity);
                }
            } catch (\Throwable $e) {
                Log::error("Wafy: ban lookup failed for {$clientIp}: " . $e->getMessage());
                if (!config('wafy.fail_open', true)) {
                    return $this->wafyBlock('unavailable', 'Service temporairement indisponible.', 'unavailable', 503, false);
                }
                // fail-open: continue to pattern detection
            }
        }

        // GeoIP country/ASN policy (opt-in). Evaluated AFTER the active-ban exit
        // so an already-banned IP short-circuits first (no re-ban / offense
        // inflation). A deny either blocks/bans outright or contributes a score.
        $geoScore = 0;
        $geoReason = $this->geoDenyReason($clientIp);
        if ($geoReason !== null) {
            $geoAction = config('wafy.geoip.action', 'block');
            if ($geoAction === 'score') {
                $geoScore = max(0, (int) config('wafy.geoip.score', 2));
            } else {
                return $this->actOnDetection($request, $next, $clientIp, $identity, $action, $geoReason, $geoAction === 'ban', ['rules' => ['geoip'], 'fields' => ['GeoIP']]);
            }
        }

        // Honeypot traps: a hit on an operator-defined trap URL is a near-certain
        // bot. Checked before velocity/scoring so a probe blocks immediately and
        // never runs the regex engine. Routed through actOnDetection so log-mode
        // and the private-IP self-DoS guard still apply.
        $trap = $this->honeypotHit($request);
        if ($trap !== null) {
            return $this->actOnDetection(
                $request,
                $next,
                $clientIp,
                $identity,
                $action,
                $trap,
                (bool) config('wafy.honeypot_ban', true),
                ['rules' => ['honeypot'], 'fields' => ['Path']]
            );
        }

        // Velocity/rate detection catches scanners that walk many URLs without
        // matching any pattern (typically a 404 storm). Skipped for private/
        // reserved IPs we refuse to ban, so we never act on a proxy's aggregate
        // traffic (self-DoS).
        $rateApplies = (bool) config('wafy.rate_limit.enabled', false)
            && !($this->isUnbannable($clientIp) && !config('wafy.ban_private_ips', false));

        if ($rateApplies) {
            $breach = $this->velocityBreach($identity);
            if ($breach !== null) {
                return $this->actOnDetection($request, $next, $clientIp, $identity, $action, $breach, true, ['rules' => ['velocity']]);
            }
        }

        // Weighted scoring: accumulate the score of every rule that matches
        // this request and only act once the total reaches score_threshold.
        // A lone ambiguous signal no longer blocks legitimate traffic; a strong
        // rule (score >= threshold) or several corroborating rules do.
        $threshold = $this->scoreThreshold();
        $result = $this->evaluate($this->buildSubjects($request));

        // Empty/whitespace-only User-Agent: weak corroborating hint (score 1),
        // opt-in. Never blocks alone; merely reinforces another signal.
        if ($this->flagsEmptyUserAgent($request)) {
            $result['score'] += 1;
            $result['rules'][] = 'bot.empty_user_agent';
            $result['fields'][] = 'User-Agent';
        }

        // Fold in a GeoIP score contribution (wafy.geoip.action = 'score').
        if ($geoScore > 0) {
            $result['score'] += $geoScore;
            $result['rules'][] = 'geoip';
            $result['fields'][] = 'GeoIP';
        }

        if ($result['score'] >= $threshold) {
            $summary = sprintf(
                'WAF score %d/%d in %s (rules: %s)%s%s',
                $result['score'],
                $threshold,
                implode(',', $result['fields']),
                implode(', ', $result['rules']),
                isset($result['severity']) && $result['severity'] !== null ? ' | severity: ' . $result['severity'] : '',
                $geoScore > 0 && $geoReason !== null ? ' | ' . $geoReason : ''
            );

            // A blocked request escalates toward a persistent ban only when it is
            // strong enough (score >= ban_score_threshold); weaker-but-blocked
            // requests are refused (403) yet never contribute to a ban.
            return $this->actOnDetection(
                $request,
                $next,
                $clientIp,
                $identity,
                $action,
                $summary,
                $result['score'] >= $this->banScoreThreshold(),
                [
                    'score' => $result['score'],
                    'threshold' => $threshold,
                    'rules' => $result['rules'],
                    'fields' => $result['fields'],
                    'severity' => $result['severity'],
                ]
            );
        }

        // No block: pass through and, for velocity, record the response status
        // (a 404 storm is the signal a scanner leaves behind).
        $response = $next($request);

        if ($rateApplies) {
            $this->recordResponseStatus($identity, $response);
        }

        return $response;
    }

    /**
     * Return a detection summary if the request path matches a configured
     * honeypot trap (exact path or fnmatch glob), or null. Case-insensitive
     * against the leading-slash-normalised path; fnmatch '*' also spans '/'.
     */
    private function honeypotHit(Request $request): ?string
    {
        $traps = array_filter((array) config('wafy.honeypot_paths', []), 'is_string');

        if (empty($traps)) {
            return null;
        }

        $path = '/' . ltrim($request->path(), '/');

        foreach ($traps as $trap) {
            $pattern = '/' . ltrim(trim((string) $trap), '/');

            if ($pattern === '/') {
                continue; // never trap the site root
            }

            if (@fnmatch($pattern, $path, FNM_CASEFOLD)) {
                return sprintf("WAF honeypot: path '%s' matched trap '%s'", $path, $pattern);
            }
        }

        return null;
    }

    /**
     * Whether the request carries no (or whitespace-only) User-Agent and the
     * operator opted in. A weak hint only (score 1): never blocks on its own.
     */
    private function flagsEmptyUserAgent(Request $request): bool
    {
        if (!config('wafy.flag_empty_user_agent', false)) {
            return false;
        }

        $ua = $request->header('User-Agent');

        return $ua === null || trim((string) $ua) === '';
    }

    /**
     * Apply the block/log/ban decision shared by pattern and velocity detection.
     */
    private function actOnDetection(Request $request, Closure $next, string $clientIp, string $identity, string $action, string $summary, bool $banEligible, array $meta = [])
    {
        $ctx = array_merge(
            $this->wafyRequestContext($request, $clientIp, $identity),
            ['action' => $action, 'reason' => $summary],
            $meta
        );
        $ruleIds = isset($meta['rules']) ? (array) $meta['rules'] : [];
        $score = isset($meta['score']) ? (int) $meta['score'] : 0;

        // In Log-Only mode we record the hit but never block or ban.
        if ($action === 'log') {
            $this->wafyLog('info', 'log_only', array_merge($ctx, ['decision' => 'allowed']));
            $this->recordEvent($request, $identity, 'logged', $ruleIds, $score);
            return $next($request);
        }

        if ($banEligible) {
            // Never persist a ban for a private/reserved IP unless explicitly
            // allowed: such an address almost always means TrustProxies is
            // misconfigured and we would ban our own proxy/CDN. Still blocked.
            if ($this->isUnbannable($clientIp) && !config('wafy.ban_private_ips', false)) {
                $this->wafyLog('warning', 'ban_skipped', array_merge($ctx, ['decision' => 'ban_skipped']));
                $this->recordEvent($request, $identity, 'blocked', $ruleIds, $score);

                return $this->wafyBlock('blocked', 'Requête bloquée.', 'blocked', 403);
            }
            if ($this->registerStrike($identity)) {
                // Strike threshold reached -> persistent ban.
                $this->banIp($request, $clientIp, $summary, $ctx);
                $this->recordEvent($request, $identity, 'banned', $ruleIds, $score);

                return $this->wafyBlock('banned', 'Votre IP est bannie.', 'banned', 403);
            }
        }

        $this->wafyLog('warning', 'detection', array_merge($ctx, ['decision' => 'blocked']));
        $this->recordEvent($request, $identity, 'blocked', $ruleIds, $score);

        return $this->wafyBlock('blocked', 'Requête bloquée.', 'blocked', 403);
    }

    /**
     * Increment this IP's request counter and report a velocity breach (request
     * rate or 404 rate over the configured limit), or null if within limits.
     */
    private function velocityBreach(string $identity): ?string
    {
        $window = max(1, (int) config('wafy.rate_limit.window', 60));
        $maxRequests = (int) config('wafy.rate_limit.max_requests', 0);
        $max404 = (int) config('wafy.rate_limit.max_404', 0);

        $requests = $this->hitCounter('wafy:rate:req:' . $identity, $window);

        if ($maxRequests > 0 && $requests > $maxRequests) {
            return "Rate limit: {$requests} requests in {$window}s (max {$maxRequests})";
        }

        if ($max404 > 0) {
            $notFound = (int) cache()->get('wafy:rate:404:' . $identity, 0);
            if ($notFound > $max404) {
                return "Scan detected: {$notFound} 404s in {$window}s (max {$max404})";
            }
        }

        return null;
    }

    /**
     * Record a 404 response against this IP's rolling counter (velocity signal).
     */
    private function recordResponseStatus(string $identity, $response): void
    {
        $status = is_object($response) && method_exists($response, 'getStatusCode')
            ? (int) $response->getStatusCode()
            : 0;

        if ($status === 404) {
            $window = max(1, (int) config('wafy.rate_limit.window', 60));
            $this->hitCounter('wafy:rate:404:' . $identity, $window);
        }
    }

    /**
     * Atomically increment a fixed-window counter and return its new value.
     */
    private function hitCounter(string $key, int $windowSeconds): int
    {
        $store = cache();
        $store->add($key, 0, now()->addSeconds($windowSeconds));

        return (int) $store->increment($key);
    }

    /**
     * Configured blocking threshold (minimum accumulated score to refuse a
     * request).
     */
    private function scoreThreshold(): int
    {
        return max(1, (int) config('wafy.score_threshold', 4));
    }

    /**
     * Score at/above which a blocked request becomes eligible for a persistent
     * ban. Defaults to the blocking threshold when not configured.
     */
    private function banScoreThreshold(): int
    {
        $configured = config('wafy.ban_score_threshold');

        return max(1, (int) ($configured ?? $this->scoreThreshold()));
    }

    /**
     * Normalise the configured detection rules into a uniform list of
     * ['id', 'score', 'pattern'] entries.
     *
     * Backward compatibility: if `wafy.rules` is empty, fall back to the legacy
     * flat `wafy.patterns` list, scoring every pattern at the threshold so a
     * single match still blocks — preserving the pre-scoring behaviour for
     * configs published before this version.
     */
    private function loadRules(): array
    {
        $disabled = $this->disabledRuleIds(); // one cache get (runtime disable set)

        $out = [];
        foreach ($this->collectRules() as $id => $rule) {
            // Drop: score <= 0 (an operator can neutralise a pack rule by
            // re-declaring its id with score 0), static enabled=false, or a
            // runtime-disabled id (wafy:rule disable).
            if ($rule['score'] <= 0 || $rule['enabled'] === false || isset($disabled[$id])) {
                continue;
            }
            $out[] = $rule;
        }

        return $out;
    }

    /**
     * All merged detection rules keyed by id, BEFORE the runtime-disable/score
     * filtering. Merge order (later overrides earlier on id collision): bundled
     * packs < imported-rules file < wafy.rules (operator config always wins).
     */
    private function collectRules(): array
    {
        $byId = [];
        foreach ($this->packRules() as $rule) {
            $byId[$rule['id']] = $rule;
        }
        foreach ($this->importedRules() as $rule) {
            $byId[$rule['id']] = $rule;
        }
        foreach ((array) config('wafy.rules', []) as $i => $rule) {
            $norm = $this->normalizeRule($rule, 'rule_' . $i);
            if ($norm !== null) {
                $byId[$norm['id']] = $norm;
            }
        }

        // Legacy flat patterns fallback (only when nothing above loaded).
        if (empty($byId)) {
            foreach ((array) config('wafy.patterns', []) as $i => $pattern) {
                $id = 'legacy_' . $i;
                $byId[$id] = ['id' => $id, 'score' => $this->scoreThreshold(), 'pattern' => $pattern, 'fields' => null, 'severity' => null, 'enabled' => true];
            }
        }

        return $byId;
    }

    /**
     * Public rule metadata for the wafy:rule console command (id => score,
     * severity, static-disabled state) — derives ids exactly like loadRules().
     */
    public function rulesMetadata(): array
    {
        $meta = [];
        foreach ($this->collectRules() as $id => $rule) {
            $meta[$id] = [
                'score' => $rule['score'],
                'severity' => $rule['severity'],
                'static_disabled' => ($rule['enabled'] === false),
            ];
        }

        return $meta;
    }

    /** Allowed severities, weakest -> strongest (index = rank). */
    private static $severities = ['info', 'low', 'medium', 'high', 'critical'];

    /**
     * Normalise one configured rule (string or array) into the internal shape.
     * Returns null for a malformed entry (ignored, never fatal).
     */
    private function normalizeRule($rule, string $fallbackId): ?array
    {
        if (is_string($rule)) {
            return ['id' => $fallbackId, 'score' => $this->scoreThreshold(), 'pattern' => $rule, 'fields' => null, 'severity' => null, 'enabled' => true];
        }

        if (is_array($rule) && !empty($rule['pattern'])) {
            $severity = isset($rule['severity']) ? strtolower((string) $rule['severity']) : null;
            if ($severity !== null && !in_array($severity, self::$severities, true)) {
                $severity = null; // unknown severity => informational none
            }

            return [
                'id' => (string) ($rule['id'] ?? $fallbackId),
                'score' => (int) ($rule['score'] ?? $this->scoreThreshold()),
                'pattern' => $rule['pattern'],
                'fields' => isset($rule['fields']) ? (array) $rule['fields'] : null,
                'severity' => $severity,
                'enabled' => !(isset($rule['enabled']) && $rule['enabled'] === false),
            ];
        }

        return null;
    }

    /** Runtime-disabled rule ids as an O(1) lookup map (id => true). */
    private function disabledRuleIds(): array
    {
        $ids = cache()->get(\Bdsa\Wafy\Console\ManageRules::CACHE_KEY, []);

        if (!is_array($ids) || empty($ids)) {
            return [];
        }

        return array_flip(array_map('strval', array_values($ids)));
    }

    /** Numeric rank of a severity string (0 = unset/unknown). */
    private function severityRank(?string $severity): int
    {
        if ($severity === null) {
            return 0;
        }
        $i = array_search($severity, self::$severities, true);

        return $i === false ? 0 : $i + 1;
    }

    /** Rules from the enabled bundled packs (wafy.rule_packs). */
    private function packRules(): array
    {
        $out = [];
        foreach (array_filter((array) config('wafy.rule_packs', []), 'is_string') as $pack) {
            $path = $this->resolvePackPath($pack);
            foreach ($this->readRuleFile($path) as $i => $rule) {
                $norm = $this->normalizeRule($rule, $pack . '_' . $i);
                if ($norm !== null) {
                    $out[] = $norm;
                }
            }
        }

        return $out;
    }

    private function resolvePackPath(string $pack): ?string
    {
        if (substr($pack, -4) === '.php' && is_file($pack)) {
            return $pack; // absolute file path
        }
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $pack)) {
            return null; // no path traversal
        }
        $path = __DIR__ . '/../../resources/rules/' . $pack . '.php';

        return is_file($path) ? $path : null;
    }

    /** Rules from the wafy:rules:import output file, if any. */
    private function importedRules(): array
    {
        $path = $this->importedRulesPath();
        if ($path === null || !is_file($path)) {
            return [];
        }

        $out = [];
        foreach ($this->readRuleFile($path) as $i => $rule) {
            $norm = $this->normalizeRule($rule, 'imported_' . $i);
            if ($norm !== null) {
                $out[] = $norm;
            }
        }

        return $out;
    }

    private function importedRulesPath(): ?string
    {
        $configured = config('wafy.imported_rules_path');
        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        return function_exists('storage_path') ? storage_path('app/wafy/imported-rules.php') : null;
    }

    private function readRuleFile(?string $path): array
    {
        if ($path === null) {
            return [];
        }

        try {
            $data = require $path; // file just returns an array
        } catch (\Throwable $e) {
            Log::warning('Wafy: rule file load failed ' . $path . ': ' . $e->getMessage());
            return [];
        }

        return is_array($data) ? $data : [];
    }

    /**
     * Run every rule against every subject and accumulate a score.
     *
     * Each rule counts at most once regardless of how many subjects it matches
     * (so the same payload appearing in both RequestBody and RawBody is not
     * double-counted). Returns the total score, the matched rule ids and the
     * fields in which matches were found.
     */
    private function evaluate(array $subjects): array
    {
        $rules = $this->loadRules();
        $score = 0;
        $matchedRules = [];
        $matchedFields = [];
        $topSeverity = null;

        foreach ($subjects as $fieldName => $value) {
            $variants = $this->recursiveUrldecode($value);

            foreach ($rules as $rule) {
                if (isset($matchedRules[$rule['id']])) {
                    continue; // already counted this rule
                }

                // Field-scoped rules only apply to their declared subjects.
                if (!empty($rule['fields']) && !in_array($fieldName, $rule['fields'], true)) {
                    continue;
                }

                foreach ($variants as $variant) {
                    if (@preg_match($rule['pattern'], $variant) === 1) {
                        $matchedRules[$rule['id']] = true;
                        $matchedFields[$fieldName] = true;
                        $score += $rule['score'];

                        $sev = isset($rule['severity']) ? $rule['severity'] : null;
                        if ($this->severityRank($sev) > $this->severityRank($topSeverity)) {
                            $topSeverity = $sev;
                        }

                        break; // count each rule at most once per field
                    }
                }
            }
        }

        return [
            'score' => $score,
            'rules' => array_keys($matchedRules),
            'fields' => array_keys($matchedFields),
            'severity' => $topSeverity,
        ];
    }

    /**
     * Build the (truncated) list of request fields to inspect.
     *
     * Truncation caps the CPU cost of the regex engine on large payloads
     * (ReDoS protection).
     */
    private function buildSubjects(Request $request): array
    {
        $maxLen = max(1, (int) config('wafy.max_scan_length', 16384));

        try {
            $rawBody = (string) $request->getContent();
        } catch (\Throwable $e) {
            $rawBody = '';
        }

        $subjects = [
            'QueryString' => $request->getQueryString() ?? '',
            'RequestBody' => json_encode($request->all(), JSON_UNESCAPED_SLASHES) ?: '',
            'Path' => '/' . ltrim($request->path(), '/'),
            'RawBody' => $rawBody,
        ];

        foreach ((array) config('wafy.scan_headers', ['User-Agent', 'Referer']) as $header) {
            $subjects[$header] = $request->header($header) ?? '';
        }

        // Multipart uploads: getContent() is empty (body consumed into $_FILES),
        // so RawBody misses them. Scan attacker-controlled filenames and a
        // bounded, text-only slice of small uploads. Form fields are already in
        // RequestBody.
        if (config('wafy.multipart.scan_files', true)) {
            foreach ($this->multipartSubjects($request, $maxLen) as $name => $value) {
                $subjects[$name] = $value;
            }
        }

        foreach ($subjects as $name => $value) {
            if (strlen($value) > $maxLen) {
                // Scan the HEAD and the TAIL so a payload padded past the cut is
                // still inspected (defeats junk-prefix truncation bypass). A
                // newline join prevents a match spanning the two slices.
                $subjects[$name] = substr($value, 0, $maxLen) . "\n" . substr($value, -$maxLen);
            }
        }

                return $subjects;
    }

    /**
     * Extra subjects derived from multipart uploads: each file's client-provided
     * name (always) plus a bounded text-only slice of small uploads.
     *
     * @return array<string,string>
     */
    private function multipartSubjects(Request $request, int $maxLen): array
    {
        try {
            $files = $this->flattenFiles($request->allFiles());
        } catch (\Throwable $e) {
            return [];
        }

        if (empty($files)) {
            return [];
        }

        $maxFiles = max(0, (int) config('wafy.multipart.max_files', 20));
        $maxSize = max(0, (int) config('wafy.multipart.max_file_size', 1048576));
        $perFileCap = min($maxLen, max(0, (int) config('wafy.multipart.max_file_bytes', 8192)));
        $scanContents = (bool) config('wafy.multipart.scan_file_contents', false);

        $subjects = [];
        $i = 0;

        foreach ($files as $file) {
            if ($i >= $maxFiles) {
                break;
            }
            if (!is_object($file) || !method_exists($file, 'getClientOriginalName')) {
                continue;
            }

            // Filename is attacker-controlled ("<script>.svg", "../../etc/passwd").
            $name = (string) $file->getClientOriginalName();
            if ($name !== '') {
                $subjects['File#' . $i . '.name'] = $name;
            }

            // Content scanning is opt-in (higher FP risk on legit code/SQL uploads).
            if ($scanContents) {
                $content = $this->readUploadSlice($file, $perFileCap, $maxSize);
                if ($content !== null && $content !== '') {
                    $subjects['File#' . $i . '.content'] = $content;
                }
            }

            $i++;
        }

        return $subjects;
    }

    /**
     * Read at most $cap bytes of an upload's content, or null when it must be
     * skipped (invalid, too large, unreadable, or binary).
     */
    private function readUploadSlice($file, int $cap, int $maxSize): ?string
    {
        if ($cap <= 0) {
            return null;
        }

        try {
            if (method_exists($file, 'isValid') && !$file->isValid()) {
                return null;
            }
            // Skip large uploads WITHOUT reading them (images/video/PDF).
            $size = method_exists($file, 'getSize') ? (int) $file->getSize() : 0;
            if ($maxSize > 0 && $size > $maxSize) {
                return null;
            }
            $path = method_exists($file, 'getRealPath') ? $file->getRealPath() : false;
            if ($path === false || $path === '' || !is_readable($path)) {
                return null;
            }
            $slice = @file_get_contents($path, false, null, 0, $cap);
            if ($slice === false || $slice === '') {
                return null;
            }
            // Binary heuristic: a NUL byte in the head => not text; skip content.
            if (strpos($slice, "\0") !== false) {
                return null;
            }

            return $slice;
        } catch (\Throwable $e) {
            return null;
        }
    }

    /**
     * Flatten allFiles() (which may nest arrays like photos[]) into a flat list
     * of UploadedFile objects.
     *
     * @return array<int,object>
     */
    private function flattenFiles(array $files): array
    {
        $flat = [];

        foreach ($files as $item) {
            if (is_array($item)) {
                foreach ($this->flattenFiles($item) as $nested) {
                    $flat[] = $nested;
                }
            } elseif (is_object($item)) {
                $flat[] = $item;
            }
        }

        return $flat;
    }

    /**
     * Register a strike for the IP and report whether the ban threshold has
     * been reached. A threshold of 1 (default) bans on the first detection.
     */
    private function registerStrike(string $identity): bool
    {
        $threshold = max(1, (int) config('wafy.ban_threshold', 1));

        if ($threshold <= 1) {
            return true;
        }

        if ($this->cacheIsEphemeral()) {
            Log::warning('Wafy: cache driver "' . config('cache.default') . '" is ephemeral — strike counting (ban_threshold > 1) will not persist across requests. Use a shared cache (redis/database/file).');
        }

        $key = 'wafy:strikes:' . $identity;
        $window = max(1, (int) config('wafy.strike_window', 60));

        // Atomic increment (avoids the lost-update race of get()+put() under a
        // concurrent flood). add() seeds the key with its window TTL only if it
        // does not already exist.
        $store = cache();
        $store->add($key, 0, now()->addMinutes($window));
        $strikes = (int) $store->increment($key);

        if ($strikes >= $threshold) {
            $store->forget($key);
            return true;
        }

        return false;
    }

    /**
     * Persist the ban and fire notifications, redacting sensitive input.
     */
    private function banIp(Request $request, string $ip, string $reason, array $ctx = []): void
    {
        $identity = $this->banIdentity($ip);

        // Read prior offense history. The row lingers after a ban expires (see
        // BlockBannedIp / wafy:prune) precisely so a returning attacker escalates
        // instead of resetting to the base duration.
        try {
            $existing = BannedIp::forIp($identity)->first();
        } catch (\Throwable $e) {
            Log::error("Wafy: offense lookup failed for {$identity}: " . $e->getMessage());
            $existing = null;
        }

        $offenseCount = ($existing ? (int) $existing->offense_count : 0) + 1;
        $bannedUntil = $this->computeBannedUntil($offenseCount);

        try {
            $bannedIpModel = BannedIp::updateOrCreate(
                ['ip_address' => $identity],
                [
                    'banned_until' => $bannedUntil,
                    'offense_count' => $offenseCount,
                    'reason' => $reason . ' (offense #' . $offenseCount . ')',
                    'request_data' => [
                        'method' => $request->method(),
                        'url' => $this->redactUrl($request),
                        'input' => $this->boundStoredInput($this->redact($request->all())),
                    ],
                ]
            );
        } catch (\Throwable $e) {
            Log::error("Wafy: failed to persist ban for {$identity}: " . $e->getMessage());
            return;
        }

        // The identity now has an active ban -> drop any cached "clean" marker.
        $this->forgetClean($identity);

        $this->wafyLog('warning', 'ban_created', array_merge($ctx, [
            'decision' => 'banned',
            'offense_count' => $offenseCount,
            'banned_until' => $bannedUntil ? $bannedUntil->toIso8601String() : null,
        ]));

        if (config('wafy.notifications.enabled')) {
            try {
                $bannedIpModel->notify(new IpBannedNotification($bannedIpModel));
            } catch (\Exception $e) {
                Log::error("Wafy: Failed to send ban notification: " . $e->getMessage());
            }
        }
    }

    /**
     * Compute banned_until for the Nth offense.
     *
     * duration(min) = backoff_base * backoff_multiplier^(offense-1), capped at
     * backoff_max. Returns null (permanent) when backoff is off and ban_duration
     * is null, or once offense_count reaches escalate_to_permanent_after. When
     * backoff is disabled it preserves the historical fixed ban_duration.
     *
     * @return \Illuminate\Support\Carbon|null
     */
    private function computeBannedUntil(int $offenseCount)
    {
        // Backoff off -> historical fixed-duration behaviour (null = permanent).
        if (!config('wafy.backoff_enabled', true)) {
            $duration = config('wafy.ban_duration', 1440);
            return is_null($duration) ? null : now()->addMinutes((int) $duration);
        }

        // Escalate to a permanent ban after N offenses (null/''/0 = never).
        $escalate = (int) config('wafy.escalate_to_permanent_after');
        if ($escalate > 0 && $offenseCount >= $escalate) {
            return null;
        }

        // Base falls back to ban_duration; a null ban_duration meant "permanent".
        $baseCfg = config('wafy.backoff_base', config('wafy.ban_duration', 1440));
        if ($baseCfg === null || (int) $baseCfg < 1) {
            return is_null(config('wafy.ban_duration', 1440)) ? null : now()->addMinutes(1);
        }
        $base = (int) $baseCfg;

        $multiplier = (float) config('wafy.backoff_multiplier', 2);
        if ($multiplier < 1) {
            $multiplier = 1.0; // never shrink a ban
        }

        $minutes = $base * pow($multiplier, max(0, $offenseCount - 1));

        $max = config('wafy.backoff_max');
        if ($max !== null && $max !== '' && (int) $max > 0) {
            $minutes = min($minutes, (float) (int) $max);
        }

        // Overflow guard: cap at ~68 years of minutes, always >= 1.
        $minutes = (int) max(1, min($minutes, 36000000));

        return now()->addMinutes($minutes);
    }

    /**
     * Redact sensitive values (passwords, tokens, PII) before persisting or
     * notifying, so they are never stored in clear text.
     */
    private function redact(array $input): array
    {
        $sensitive = array_map('strtolower', (array) config('wafy.sensitive_keys', []));

        if (empty($sensitive)) {
            return $input;
        }

        array_walk_recursive($input, function (&$value, $key) use ($sensitive) {
            if ($this->keyIsSensitive($key, $sensitive)) {
                $value = '[REDACTED]';
            }
        });

        return $input;
    }

    /**
     * Bound the size of the input stored in a ban record: truncate long leaf
     * values and, as a hard backstop, replace the whole payload if it would
     * still overflow a TEXT column (~64KB).
     */
    private function boundStoredInput(array $input): array
    {
        $maxValue = max(64, (int) config('wafy.max_stored_value_length', 2048));

        array_walk_recursive($input, function (&$value) use ($maxValue) {
            if (is_string($value) && strlen($value) > $maxValue) {
                $value = substr($value, 0, $maxValue) . '…[truncated]';
            }
        });

        if (strlen((string) json_encode($input)) > 60000) {
            return ['_truncated' => true, '_note' => 'input too large to store'];
        }

        return $input;
    }

    /**
     * Whether a key should be redacted. Matches a sensitive term anywhere in the
     * key name (e.g. "user_password", "billingCardNumber") — erring toward
     * over-redaction rather than leaking a secret.
     */
    private function keyIsSensitive($key, array $sensitive): bool
    {
        if (!is_string($key) && !is_int($key)) {
            return false;
        }

        $key = strtolower((string) $key);

        foreach ($sensitive as $term) {
            if ($term !== '' && strpos($key, $term) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Build the request URL for storage/notification with sensitive query
     * parameters masked (e.g. ?token=..., ?api_key=...). Without this, secrets
     * carried in the query string would be persisted and emailed in clear text —
     * redact() only covers the request body, never the URL.
     */
    private function redactUrl(Request $request): string
    {
        $sensitive = array_map('strtolower', (array) config('wafy.sensitive_keys', []));
        $query = $request->query();

        if (!empty($sensitive) && is_array($query) && !empty($query)) {
            array_walk_recursive($query, function (&$value, $key) use ($sensitive) {
                if ($this->keyIsSensitive($key, $sensitive)) {
                    $value = '[REDACTED]';
                }
            });
        }

        return empty($query)
            ? $request->url()
            : $request->url() . '?' . http_build_query($query);
    }

    /**
     * Recursively decode a string to expose multi-encoded payloads, returning
     * the DISTINCT decoded variants to scan:
     *   - urldecode()    : standard form-encoding, also rewrites '+' -> space.
     *   - rawurldecode() : RFC 3986, keeps '+' literal, so a payload relying on
     *     a literal '+' is not corrupted/lost.
     * Each decoder loops up to depth 5 (nested-encoding / DoS guard). Duplicates
     * are collapsed; evaluate() counts each rule once, so scanning both variants
     * never double-flags.
     *
     * @return string[]
     */
    private function recursiveUrldecode($string): array
    {
        $string = (string) $string;
        $variants = [];

        foreach (['urldecode', 'rawurldecode'] as $decoder) {
            $prev = '';
            $curr = $string;
            $maxDepth = 5;

            while ($curr !== $prev && $maxDepth > 0) {
                $prev = $curr;
                $curr = $decoder($curr);
                $maxDepth--;
            }

            if (!in_array($curr, $variants, true)) {
                $variants[] = $curr;
            }
        }

        return $variants;
    }
}
