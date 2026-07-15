<?php

namespace Bdsa\Wafy\Contracts;

interface GeoIpResolver
{
    /**
     * ISO 3166-1 alpha-2 country code (UPPERCASE) for the IP, or null if unknown.
     */
    public function country(?string $ip): ?string;

    /**
     * Autonomous System Number for the IP, or null if unknown.
     */
    public function asn(?string $ip): ?int;
}
