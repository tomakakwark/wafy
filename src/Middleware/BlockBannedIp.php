<?php

namespace Bdsa\Wafy\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Bdsa\Wafy\Concerns\HandlesClientIp;
use Bdsa\Wafy\Models\BannedIp;

class BlockBannedIp
{
    use HandlesClientIp;

    public function handle(Request $request, Closure $next)
    {
        $clientIp = $request->ip();

        // Check Allowed IPs (Whitelist) — supports single IPs and CIDR ranges.
        if ($this->isAllowed($clientIp)) {
            return $next($request);
        }

        // Check Cache first (runtime override), then Config (default)
        $isEnabled = cache()->get('wafy.enabled', config('wafy.enabled', true));

        if (!$isEnabled) {
            return $next($request);
        }

        try {
            $bannedIp = BannedIp::forIp($clientIp)->first();
        } catch (\Throwable $e) {
            Log::error("Wafy: ban lookup failed for {$clientIp}: " . $e->getMessage());
            if (!config('wafy.fail_open', true)) {
                return response()->json(['message' => 'Service temporairement indisponible.'], 503);
            }
            return $next($request);
        }

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
