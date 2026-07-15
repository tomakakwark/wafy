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

        $identity = $this->banIdentity($clientIp);

        // A cached "clean" marker lets legitimate repeat traffic skip the DB.
        if ($this->isKnownClean($identity)) {
            return $next($request);
        }

        try {
            $bannedIp = BannedIp::forIp($identity)->first();
        } catch (\Throwable $e) {
            Log::error("Wafy: ban lookup failed for {$clientIp}: " . $e->getMessage());
            if (!config('wafy.fail_open', true)) {
                return response()->json(['message' => 'Service temporairement indisponible.'], 503);
            }
            return $next($request);
        }

        if ($bannedIp) {
            // Ban permanent (banned_until null) ou temporaire encore valide.
            $isActive = is_null($bannedIp->banned_until) || now()->lessThan($bannedIp->banned_until);

            if ($isActive) {
                // En mode "log", on n'interdit rien : on trace et on laisse passer,
                // conformément à la sémantique documentée du mode log-only.
                $action = cache('wafy.action', config('wafy.action', 'block'));
                if ($action === 'log') {
                    Log::info("Wafy (Log-Only): request from banned IP {$clientIp} allowed (would be blocked in block mode).");
                    return $next($request);
                }

                $message = is_null($bannedIp->banned_until)
                    ? 'Votre IP est bannie définitivement.'
                    : 'Votre IP est temporairement bannie.';

                return response()->json(['message' => $message], 403);
            }

            // Ban temporaire expiré -> on le nettoie.
            $bannedIp->delete();
        }

        // No active ban -> remember the identity as clean for a short while.
        $this->rememberClean($identity);

        return $next($request);
    }
}
