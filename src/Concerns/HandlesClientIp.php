<?php

namespace Bdsa\Wafy\Concerns;

use Symfony\Component\HttpFoundation\IpUtils;
use Illuminate\Support\Facades\Lang;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;
use Bdsa\Wafy\Support\BanKey;
use Bdsa\Wafy\Models\WafyEvent;

trait HandlesClientIp
{
    /**
     * Emit a STRUCTURED Wafy log line on the configured channel. The stable,
     * SIEM-parsable schema is attached as CONTEXT; NEVER pass attacker values
     * here — only rule ids, field names and the path.
     */
    protected function wafyLog(string $level, string $event, array $context = []): void
    {
        if (!config('wafy.logging.enabled', true)) {
            return;
        }

        $payload = array_merge(['wafy' => true, 'schema' => 1, 'event' => $event], $context);
        $reason = isset($context['reason']) && $context['reason'] !== '' ? $context['reason'] : $event;
        $message = 'Wafy: ' . $reason;

        try {
            $channel = config('wafy.logging.channel');
            if ($channel !== null && $channel !== '') {
                Log::channel($channel)->log($level, $message, $payload);
            } else {
                Log::log($level, $message, $payload);
            }
        } catch (\Throwable $e) {
            // A mis-configured channel must never break the request or hide the
            // security event: fall back to the default channel.
            try {
                Log::log($level, $message, $payload);
            } catch (\Throwable $e2) {
                // give up silently
            }
        }
    }

    /** Base structured context from the request. Path ONLY — never the query/values. */
    protected function wafyRequestContext(Request $request, ?string $ip = null, ?string $identity = null): array
    {
        $ip = $ip ?? $request->ip();

        return [
            'ip' => $ip,
            'identity' => $identity ?? $this->banIdentity($ip),
            'path' => '/' . ltrim($request->path(), '/'),
            'method' => $request->method(),
        ];
    }

    /**
     * Append a telemetry event for wafy:stats. Opt-in (wafy.stats.enabled) and
     * fully failure-isolated: a stats write must NEVER break the request.
     */
    protected function recordEvent(Request $request, string $identity, string $event, array $ruleIds, int $score): void
    {
        if (!config('wafy.stats.enabled', false)) {
            return; // one read, then out — no DB touched when off
        }

        // Coalesce writes: at most one row per identity+event per dedup window, so
        // a flood cannot amplify into unbounded INSERTs. add() is atomic.
        $window = max(0, (int) config('wafy.stats.dedup_seconds', 10));
        if ($window > 0 && !cache()->add('wafy:evt:' . $event . ':' . $identity, 1, $window)) {
            return;
        }

        try {
            $path = '/' . ltrim($request->path(), '/');
            if (strlen($path) > 512) {
                $path = substr($path, 0, 512);
            }

            WafyEvent::create([
                'ip_identity' => $identity,
                'event' => $event,
                'rule_ids' => array_values(array_slice(array_map('strval', $ruleIds), 0, 30)),
                'score' => max(0, min(65535, $score)),
                'path' => $path,
                'country' => $this->statsCountry($request->ip()),
                'created_at' => now(),
            ]);
        } catch (\Throwable $e) {
            Log::error('Wafy: stats event write failed: ' . $e->getMessage());
        }
    }

    private function statsCountry(?string $ip): ?string
    {
        if (empty($ip) || !config('wafy.stats.geo', true)) {
            return null;
        }

        return $this->resolveCountryOnce($ip);
    }

    /** @var array<string,?string> per-request country memo (shared geo policy + stats). */
    private $wafyCountryMemo = [];

    /**
     * Resolve (and memoize for this request) the client's ISO country, so the
     * geo policy and the stats event don't each hit the resolver.
     */
    protected function resolveCountryOnce(?string $ip): ?string
    {
        if (empty($ip)) {
            return null;
        }
        if (array_key_exists($ip, $this->wafyCountryMemo)) {
            return $this->wafyCountryMemo[$ip];
        }

        try {
            $c = $this->geoIpResolver()->country($ip);
            $c = $c !== null ? strtoupper(substr((string) $c, 0, 2)) : null;
        } catch (\Throwable $e) {
            $c = null;
        }

        return $this->wafyCountryMemo[$ip] = $c;
    }
    /**
     * Resolve a configurable Wafy response message. The configured value may be
     * a literal string (the historical default) OR a translation key: only when
     * a matching lang line exists is it passed through trans(). $default is a
     * hard fallback for configs published before this feature existed.
     */
    protected function wafyMessage(string $key, string $default): string
    {
        $value = (string) config('wafy.messages.' . $key, $default);

        if ($value !== '' && Lang::has($value)) {
            return (string) trans($value);
        }

        return $value;
    }

    /**
     * Configurable HTTP status for a response site, falling back to the
     * historical code when unset or implausible.
     */
    protected function wafyStatus(string $key, int $default): int
    {
        $status = (int) config('wafy.status_codes.' . $key, $default);

        return ($status >= 100 && $status <= 599) ? $status : $default;
    }

    /**
     * Build a refusal response from a configurable message + status, honouring
     * wafy.response.mode (json | view | auto) and an optional bounded tarpit.
     * Shared by both middlewares. $tarpitEligible MUST be false for the
     * fail-open 503 so we never pin a PHP-FPM worker while the store is degraded.
     */
    protected function wafyBlock(string $messageKey, string $defaultMessage, string $statusKey, int $defaultStatus, bool $tarpitEligible = true)
    {
        $message = $this->wafyMessage($messageKey, $defaultMessage);
        $status = $this->wafyStatus($statusKey, $defaultStatus);

        if ($tarpitEligible) {
            $this->wafyTarpit();
        }

        return $this->wafyResponse($message, $status);
    }

    /**
     * Bounded delay to slow scanners. Default 0 (disabled, BC). Clamped to
     * [0, tarpit_max]. WARNING: sleep() pins a PHP-FPM worker for its duration.
     */
    protected function wafyTarpit(): void
    {
        $max = max(0, (int) config('wafy.response.tarpit_max', 5));
        $seconds = max(0, min((int) config('wafy.response.tarpit_seconds', 0), $max));

        if ($seconds > 0) {
            sleep($seconds);
        }
    }

    /**
     * Render the refusal body per wafy.response.mode. Falls back to JSON when
     * the view is missing so a block can never 500.
     */
    protected function wafyResponse(string $message, int $status)
    {
        $mode = (string) config('wafy.response.mode', 'json');

        if ($mode === 'view' || $mode === 'auto') {
            $wantsJson = false;
            if ($mode === 'auto') {
                $request = request();
                $wantsJson = $request !== null && ($request->expectsJson() || $request->wantsJson());
            }

            if (!$wantsJson) {
                $view = (string) config('wafy.response.view', 'wafy::blocked');
                if (\Illuminate\Support\Facades\View::exists($view)) {
                    return response()->view($view, ['message' => $message, 'status' => $status], $status);
                }
                // View missing: degrade to JSON rather than 500.
            }
        }

        return response()->json(['message' => $message], $status);
    }

    /**
     * Canonical identity used to store / look up bans and strikes for an IP
     * (IPv4 unchanged; IPv6 collapsed to its configured network prefix).
     */
    protected function banIdentity(?string $ip): string
    {
        return BanKey::for($ip);
    }

    /**
     * Whether the default cache store is ephemeral (array/null) and therefore
     * cannot persist strikes or runtime toggles across requests.
     */
    protected function cacheIsEphemeral(): bool
    {
        return in_array(config('cache.default'), ['array', 'null'], true);
    }

    /**
     * Configured TTL (seconds) for caching negative ban lookups. 0 = disabled.
     */
    protected function banLookupTtl(): int
    {
        return max(0, (int) config('wafy.ban_lookup_cache_ttl', 0));
    }

    /**
     * Whether this identity is known (cached) to have no ban, letting both
     * middlewares skip the database lookup for legitimate repeat traffic.
     */
    protected function isKnownClean(string $identity): bool
    {
        return $this->banLookupTtl() > 0
            && (bool) cache()->get('wafy:clean:' . $identity, false);
    }

    /**
     * Remember that this identity currently has no ban (short TTL).
     */
    protected function rememberClean(string $identity): void
    {
        $ttl = $this->banLookupTtl();

        if ($ttl > 0) {
            cache()->put('wafy:clean:' . $identity, true, $ttl);
        }
    }

    /**
     * Invalidate the "clean" marker for an identity (called when a ban is
     * created so the next request re-checks the database).
     */
    protected function forgetClean(string $identity): void
    {
        cache()->forget('wafy:clean:' . $identity);
    }

    /**
     * Determine whether the given client IP is whitelisted.
     *
     * Supports single IPv4/IPv6 addresses as well as CIDR ranges
     * (e.g. '10.0.0.0/8', '2001:db8::/32').
     */
    protected function isAllowed(?string $ip): bool
    {
        if (empty($ip)) {
            return false;
        }

        $allowed = array_filter((array) config('wafy.allowed_ips', []));

        if (empty($allowed)) {
            return false;
        }

        return IpUtils::checkIp($ip, array_values($allowed));
    }

    /**
     * The bound GeoIP resolver (or the null resolver if unbound).
     */
    protected function geoIpResolver()
    {
        return app(\Bdsa\Wafy\Contracts\GeoIpResolver::class);
    }

    /**
     * Return a deny reason if the client IP is blocked by GeoIP country/ASN
     * policy, or null. Skipped for private/reserved IPs (same anti self-DoS
     * invariant as velocity) and when GeoIP is disabled.
     */
    protected function geoDenyReason(?string $ip): ?string
    {
        if (!config('wafy.geoip.enabled', false)) {
            return null;
        }

        if (empty($ip) || $this->isUnbannable($ip)) {
            return null;
        }

        // A broken/mis-bound resolver must never take the app down: fault-isolate
        // the whole lookup and skip geo on any error (fail-open, like the ban store).
        try {
            $resolver = $this->geoIpResolver();

            // ASN deny list (cheap, checked first).
            $denyAsns = array_map('intval', (array) config('wafy.geoip.deny_asns', []));
            if (!empty($denyAsns)) {
                $asn = $resolver->asn($ip);
                if ($asn !== null && in_array((int) $asn, $denyAsns, true)) {
                    return "GeoIP: ASN {$asn} denied (hosting/VPN)";
                }
            }

            // Country allow/deny list.
            $countries = array_map('strtoupper', array_map('strval', (array) config('wafy.geoip.countries', [])));
            if (!empty($countries)) {
                $country = $this->resolveCountryOnce($ip); // memoized (also reused by stats)
                $mode = config('wafy.geoip.mode', 'deny');

                if ($mode === 'allow') {
                    // Block only a KNOWN country not in the allow-list (unknown passes).
                    if ($country !== null && !in_array($country, $countries, true)) {
                        return "GeoIP: country {$country} not in allow-list";
                    }
                } else {
                    if ($country !== null && in_array($country, $countries, true)) {
                        return "GeoIP: country {$country} denied";
                    }
                }
            }
        } catch (\Throwable $e) {
            \Illuminate\Support\Facades\Log::error('Wafy: GeoIP lookup failed for ' . $ip . ': ' . $e->getMessage());
            return null;
        }

        return null;
    }

    /**
     * Whether the given IP must never be persisted as a ban.
     *
     * A private / reserved / loopback address is almost always the sign that
     * TrustProxies is misconfigured and $request->ip() is returning the
     * proxy/CDN egress address — banning it would take down all traffic
     * (self-DoS). Callers may override this via the `wafy.ban_private_ips` flag.
     */
    protected function isUnbannable(?string $ip): bool
    {
        if (empty($ip)) {
            return true;
        }

        // filter_var returns the address only when it is a valid PUBLIC IP;
        // private/reserved/loopback ranges (and malformed input) yield false.
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }
}
