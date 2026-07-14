<?php

namespace Bdsa\Wafy\Concerns;

use Symfony\Component\HttpFoundation\IpUtils;
use Bdsa\Wafy\Support\BanKey;

trait HandlesClientIp
{
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
