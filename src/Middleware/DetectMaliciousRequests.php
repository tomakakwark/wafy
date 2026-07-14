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

        // Check action mode (block vs log)
        $action = cache('wafy.action', config('wafy.action', 'block'));

        // Fast early exit: if the IP is already under an ACTIVE ban, skip the
        // (relatively expensive) pattern matching. Expired bans are ignored
        // here and cleaned up by BlockBannedIp. Never fail the whole app just
        // because the ban store is momentarily unavailable.
        if ($action !== 'log') {
            try {
                $existing = BannedIp::forIp($clientIp)->first();
                if ($existing && $existing->isActive()) {
                    return response()->json(['message' => 'Votre IP est bannie.'], 403);
                }
            } catch (\Throwable $e) {
                Log::error("Wafy: ban lookup failed for {$clientIp}: " . $e->getMessage());
                if (!config('wafy.fail_open', true)) {
                    return response()->json(['message' => 'Service temporairement indisponible.'], 503);
                }
                // fail-open: continue to pattern detection
            }
        }

        // Weighted scoring: accumulate the score of every rule that matches
        // this request and only act once the total reaches score_threshold.
        // A lone ambiguous signal no longer blocks legitimate traffic; a strong
        // rule (score >= threshold) or several corroborating rules do.
        $threshold = $this->scoreThreshold();
        $result = $this->evaluate($this->buildSubjects($request));

        if ($result['score'] < $threshold) {
            return $next($request);
        }

        $summary = sprintf(
            'WAF score %d/%d in %s (rules: %s)',
            $result['score'],
            $threshold,
            implode(',', $result['fields']),
            implode(', ', $result['rules'])
        );

        Log::warning("Wafy: {$summary} from {$clientIp}");

        // In Log-Only mode we record the hit but never block or ban.
        if ($action === 'log') {
            Log::info("Wafy (Log-Only): request allowed for {$clientIp} despite: {$summary}");
            return $next($request);
        }

        // Never persist a ban for a private/reserved IP unless explicitly
        // allowed: such an address almost always means TrustProxies is
        // misconfigured and we would ban our own proxy/CDN, taking down all
        // traffic. The offending request is still blocked.
        if ($this->isUnbannable($clientIp) && !config('wafy.ban_private_ips', false)) {
            Log::warning("Wafy: {$summary} from private/reserved IP {$clientIp} — ban skipped (check TrustProxies).");

            return response()->json(['message' => 'Requête bloquée.'], 403);
        }

        // Only escalate to a persistent IP ban once the strike threshold is
        // reached. The offending request is blocked either way.
        if ($this->registerStrike($clientIp)) {
            $this->banIp($request, $clientIp, $summary);

            return response()->json(['message' => 'Votre IP est bannie.'], 403);
        }

        return response()->json(['message' => 'Requête bloquée.'], 403);
    }

    /**
     * Configured blocking threshold (minimum accumulated score to act on).
     */
    private function scoreThreshold(): int
    {
        return max(1, (int) config('wafy.score_threshold', 4));
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
        $normalized = [];

        foreach ((array) config('wafy.rules', []) as $i => $rule) {
            if (is_string($rule)) {
                $normalized[] = ['id' => 'rule_' . $i, 'score' => $this->scoreThreshold(), 'pattern' => $rule];
            } elseif (is_array($rule) && !empty($rule['pattern'])) {
                $normalized[] = [
                    'id' => (string) ($rule['id'] ?? 'rule_' . $i),
                    'score' => (int) ($rule['score'] ?? $this->scoreThreshold()),
                    'pattern' => $rule['pattern'],
                ];
            }
        }

        if (!empty($normalized)) {
            return $normalized;
        }

        foreach ((array) config('wafy.patterns', []) as $i => $pattern) {
            $normalized[] = ['id' => 'legacy_' . $i, 'score' => $this->scoreThreshold(), 'pattern' => $pattern];
        }

        return $normalized;
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

        foreach ($subjects as $fieldName => $value) {
            $decodedValue = $this->recursiveUrldecode($value);

            foreach ($rules as $rule) {
                if (isset($matchedRules[$rule['id']])) {
                    continue; // already counted this rule
                }

                if (@preg_match($rule['pattern'], $decodedValue) === 1) {
                    $matchedRules[$rule['id']] = true;
                    $matchedFields[$fieldName] = true;
                    $score += $rule['score'];
                }
            }
        }

        return [
            'score' => $score,
            'rules' => array_keys($matchedRules),
            'fields' => array_keys($matchedFields),
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

        foreach ($subjects as $name => $value) {
            if (strlen($value) > $maxLen) {
                $subjects[$name] = substr($value, 0, $maxLen);
            }
        }

        return $subjects;
    }

    /**
     * Register a strike for the IP and report whether the ban threshold has
     * been reached. A threshold of 1 (default) bans on the first detection.
     */
    private function registerStrike(string $ip): bool
    {
        $threshold = max(1, (int) config('wafy.ban_threshold', 1));

        if ($threshold <= 1) {
            return true;
        }

        $key = 'wafy:strikes:' . $ip;
        $window = max(1, (int) config('wafy.strike_window', 60));
        $strikes = (int) cache()->get($key, 0) + 1;

        if ($strikes >= $threshold) {
            cache()->forget($key);
            return true;
        }

        cache()->put($key, $strikes, now()->addMinutes($window));

        return false;
    }

    /**
     * Persist the ban and fire notifications, redacting sensitive input.
     */
    private function banIp(Request $request, string $ip, string $reason): void
    {
        $duration = config('wafy.ban_duration', 1440);
        $bannedUntil = is_null($duration) ? null : now()->addMinutes((int) $duration);

        try {
            $bannedIpModel = BannedIp::updateOrCreate(
                ['ip_address' => $ip],
                [
                    'banned_until' => $bannedUntil,
                    'reason' => $reason,
                    'request_data' => [
                        'method' => $request->method(),
                        'url' => $this->redactUrl($request),
                        'input' => $this->redact($request->all()),
                    ],
                ]
            );
        } catch (\Throwable $e) {
            Log::error("Wafy: failed to persist ban for {$ip}: " . $e->getMessage());
            return;
        }

        if (config('wafy.notifications.enabled')) {
            try {
                $bannedIpModel->notify(new IpBannedNotification($bannedIpModel));
            } catch (\Exception $e) {
                Log::error("Wafy: Failed to send ban notification: " . $e->getMessage());
            }
        }
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
            if (is_string($key) && in_array(strtolower($key), $sensitive, true)) {
                $value = '[REDACTED]';
            }
        });

        return $input;
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
                if (is_string($key) && in_array(strtolower($key), $sensitive, true)) {
                    $value = '[REDACTED]';
                }
            });
        }

        return empty($query)
            ? $request->url()
            : $request->url() . '?' . http_build_query($query);
    }

    /**
     * Recursively urldecode a string to handle multi-encoded payloads.
     */
    private function recursiveUrldecode($string)
    {
        $prev = '';
        $curr = $string;

        // Limite à 5 décodages pour éviter les boucles infinies ou les attaques DoS
        $maxDepth = 5;
        while ($curr !== $prev && $maxDepth > 0) {
            $prev = $curr;
            $curr = urldecode($curr);
            $maxDepth--;
        }

        return $curr;
    }
}
