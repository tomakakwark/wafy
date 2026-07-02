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
}
