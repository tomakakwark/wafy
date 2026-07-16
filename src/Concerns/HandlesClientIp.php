<?php

namespace Bdsa\Wafy\Concerns;

use Symfony\Component\HttpFoundation\IpUtils;
use Illuminate\Support\Facades\Lang;
use Bdsa\Wafy\Support\BanKey;

trait HandlesClientIp
{
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
     * Build a JSON refusal response from a configurable message + status.
     * Shared by both middlewares.
     */
    protected function wafyBlock(string $messageKey, string $defaultMessage, string $statusKey, int $defaultStatus)
    {
        return response()->json(
            ['message' => $this->wafyMessage($messageKey, $defaultMessage)],
            $this->wafyStatus($statusKey, $defaultStatus)
        );
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
                $country = $resolver->country($ip); // null => unknown
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
