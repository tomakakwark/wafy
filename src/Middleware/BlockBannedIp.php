<?php

namespace Bdsa\Wafy\Middleware;

use Closure;
use Illuminate\Http\Request;
use Bdsa\Wafy\Models\BannedIp;

class BlockBannedIp
{
    public function handle(Request $request, Closure $next)
    {
        $clientIp = $request->ip();

        // Check Allowed IPs (Whitelist)
        $allowedIps = config('wafy.allowed_ips', []);
        if (in_array($clientIp, $allowedIps)) {
            return $next($request);
        }

        // Check Cache first (runtime override), then Config (default)
        $isEnabled = cache()->get('wafy.enabled', config('wafy.enabled', true));

        if (!$isEnabled) {
            return $next($request);
        }

        $bannedIp = BannedIp::where('ip_address', $clientIp)->first();

        if ($bannedIp) {
            // Si banned_until est null, c'est un ban permanent via DetectMaliciousRequests ou commande
            if (is_null($bannedIp->banned_until)) {
                return response()->json(['message' => 'Votre IP est bannie définitivement.'], 403);
            }

            // Si le bannissement est temporaire et encore valide
            if (now()->lessThan($bannedIp->banned_until)) {
                return response()->json(['message' => 'Votre IP est temporairement bannie.'], 403);
            }

            // Si on arrive ici, c'est que le ban temporaire est expiré, on le nettoie
            $bannedIp->delete();
        }

        return $next($request);
    }
}