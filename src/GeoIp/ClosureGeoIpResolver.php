<?php

namespace Bdsa\Wafy\GeoIp;

use Closure;
use Bdsa\Wafy\Contracts\GeoIpResolver;

/**
 * Wraps a user-provided closure `fn(?string $ip): array` that returns
 * ['country' => 'FR'|null, 'asn' => int|null] for an IP.
 */
class ClosureGeoIpResolver implements GeoIpResolver
{
    private $callback;

    public function __construct(Closure $callback)
    {
        $this->callback = $callback;
    }

    public function country(?string $ip): ?string
    {
        $data = $this->resolve($ip);
        $country = $data['country'] ?? null;

        return $country !== null && $country !== '' ? strtoupper((string) $country) : null;
    }

    public function asn(?string $ip): ?int
    {
        $data = $this->resolve($ip);

        return isset($data['asn']) && $data['asn'] !== null ? (int) $data['asn'] : null;
    }

    private function resolve(?string $ip): array
    {
        try {
            $result = ($this->callback)($ip);

            return is_array($result) ? $result : [];
        } catch (\Throwable $e) {
            return [];
        }
    }
}
