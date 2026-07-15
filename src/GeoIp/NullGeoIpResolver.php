<?php

namespace Bdsa\Wafy\GeoIp;

use Bdsa\Wafy\Contracts\GeoIpResolver;

/**
 * A resolver that knows nothing — used when GeoIP is disabled or as a safe base.
 */
class NullGeoIpResolver implements GeoIpResolver
{
    public function country(?string $ip): ?string
    {
        return null;
    }

    public function asn(?string $ip): ?int
    {
        return null;
    }
}
