<?php

namespace Bdsa\Wafy\GeoIp;

use Bdsa\Wafy\Contracts\GeoIpResolver;
use Illuminate\Support\Facades\Log;

/**
 * Best-effort resolver that uses whatever GeoIP backend is available WITHOUT
 * hard-requiring any dependency:
 *   - a MaxMind GeoIp2 reader (geoip2/geoip2) if a database path is configured;
 *   - the torann/geoip helper geoip() if installed;
 *   - the legacy geoip_* PHP extension functions.
 * When nothing is available it degrades gracefully to null (logged once).
 */
class DefaultGeoIpResolver implements GeoIpResolver
{
    private static $warned = false;

    private $reader;
    private $asnReader;
    private $triedReader = false;
    private $triedAsnReader = false;

    public function country(?string $ip): ?string
    {
        if (empty($ip)) {
            return null;
        }

        try {
            $reader = $this->maxmind();
            if ($reader) {
                $code = $reader->country($ip)->country->isoCode;
                return $code ? strtoupper((string) $code) : null;
            }

            if (function_exists('geoip')) {
                $loc = geoip($ip);
                if (is_object($loc) && !empty($loc->iso_code)) {
                    return strtoupper((string) $loc->iso_code);
                }
            }

            if (function_exists('geoip_country_code_by_name')) {
                $code = @geoip_country_code_by_name($ip);
                return $code ? strtoupper((string) $code) : null;
            }
        } catch (\Throwable $e) {
            // fall through to the warning
        }

        $this->warnOnce();

        return null;
    }

    public function asn(?string $ip): ?int
    {
        if (empty($ip)) {
            return null;
        }

        try {
            $reader = $this->maxmindAsn();
            if ($reader) {
                $number = $reader->asn($ip)->autonomousSystemNumber;
                return $number !== null ? (int) $number : null;
            }

            if (function_exists('geoip_asnum_by_name')) {
                $raw = @geoip_asnum_by_name($ip); // e.g. "AS12345 Some Org"
                if ($raw && preg_match('/AS(\d+)/i', $raw, $m)) {
                    return (int) $m[1];
                }
            }
        } catch (\Throwable $e) {
            // fall through
        }

        $this->warnOnce();

        return null;
    }

    private function maxmind()
    {
        if ($this->triedReader) {
            return $this->reader;
        }
        $this->triedReader = true;

        $db = (string) config('wafy.geoip.database', '');
        if ($db !== '' && class_exists('\\GeoIp2\\Database\\Reader') && is_file($db)) {
            $this->reader = new \GeoIp2\Database\Reader($db);
        }

        return $this->reader;
    }

    private function maxmindAsn()
    {
        if ($this->triedAsnReader) {
            return $this->asnReader;
        }
        $this->triedAsnReader = true;

        $db = (string) config('wafy.geoip.asn_database', '');
        if ($db !== '' && class_exists('\\GeoIp2\\Database\\Reader') && is_file($db)) {
            $this->asnReader = new \GeoIp2\Database\Reader($db);
        }

        return $this->asnReader;
    }

    private function warnOnce(): void
    {
        if (!self::$warned) {
            self::$warned = true;
            Log::warning('Wafy: GeoIP enabled but no backend/database available — geo checks skipped. Install geoip2/geoip2 (+ a database) or configure a resolver.');
        }
    }
}
