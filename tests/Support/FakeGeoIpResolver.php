<?php

namespace Bdsa\Wafy\Tests\Support;

use Bdsa\Wafy\Contracts\GeoIpResolver;

/**
 * Deterministic resolver for tests: map ip => ['country' => 'RU', 'asn' => 14061].
 */
class FakeGeoIpResolver implements GeoIpResolver
{
    private $map;

    public function __construct(array $map = [])
    {
        $this->map = $map;
    }

    public function country(?string $ip): ?string
    {
        return isset($this->map[$ip]['country']) ? strtoupper((string) $this->map[$ip]['country']) : null;
    }

    public function asn(?string $ip): ?int
    {
        return isset($this->map[$ip]['asn']) ? (int) $this->map[$ip]['asn'] : null;
    }
}
