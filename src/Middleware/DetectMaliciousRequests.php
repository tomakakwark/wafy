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

        // Détection des patterns malveillants
        $patterns = config('wafy.patterns', []);
        $subjects = $this->buildSubjects($request);

        foreach ($subjects as $fieldName => $value) {
            $decodedValue = $this->recursiveUrldecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decodedValue)) {
                    Log::warning("Wafy: Malicious pattern detected from {$clientIp} in {$fieldName}. Pattern: {$pattern}");

                    // If in Log-Only mode, ensure we log but DO NOT BLOCK
                    if ($action === 'log') {
                        Log::info("Wafy (Log-Only): Request allowed for {$clientIp}");
                        continue 2; // Move to next field
                    }

                    $reason = "Malicious pattern detected in {$fieldName}: {$pattern}";

                    // Only escalate to a persistent IP ban once the strike
                    // threshold is reached. The offending request is blocked
                    // either way.
                    if ($this->registerStrike($clientIp)) {
                        $this->banIp($request, $clientIp, $reason);

                        return response()->json(['message' => 'Votre IP est bannie.'], 403);
                    }

                    return response()->json(['message' => 'Requête bloquée.'], 403);
                }
            }
        }

        return $next($request);
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
                        'url' => $request->fullUrl(),
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
