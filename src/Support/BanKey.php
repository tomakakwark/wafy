<?php

namespace Bdsa\Wafy\Support;

class BanKey
{
    /**
     * Canonical ban identity for an IP address.
     *
     * IPv4 addresses are returned unchanged. IPv6 addresses are collapsed to
     * their network prefix (default /64, via wafy.ipv6_ban_prefix) so an
     * attacker cannot dodge a ban simply by rotating through the billions of
     * addresses in their allocation. The prefix is appended (e.g.
     * "2001:db8:1:2::/64") so a network ban is visible and never collides with
     * a single-address ban.
     */
    public static function for(?string $ip): string
    {
        $ip = (string) $ip;

        // IPv4 or empty -> use as-is.
        if ($ip === '' || strpos($ip, ':') === false) {
            return $ip;
        }

        $prefix = (int) config('wafy.ipv6_ban_prefix', 64);

        // 128 (or an out-of-range value) means "ban the exact address".
        if ($prefix < 1 || $prefix > 127) {
            return $ip;
        }

        $packed = @inet_pton($ip);
        if ($packed === false || strlen($packed) !== 16) {
            return $ip; // not a parseable IPv6 address
        }

        $fullBytes = intdiv($prefix, 8);
        $remainingBits = $prefix % 8;

        $network = substr($packed, 0, $fullBytes);

        if ($remainingBits > 0) {
            $mask = chr((0xff << (8 - $remainingBits)) & 0xff);
            $network .= ($packed[$fullBytes] & $mask);
        }

        $network = str_pad($network, 16, "\0");
        $address = @inet_ntop($network);

        if ($address === false) {
            return $ip;
        }

        return $address . '/' . $prefix;
    }
}
