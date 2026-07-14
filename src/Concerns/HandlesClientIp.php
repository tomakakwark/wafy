<?php

namespace Bdsa\Wafy\Concerns;

use Symfony\Component\HttpFoundation\IpUtils;

trait HandlesClientIp
{
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
