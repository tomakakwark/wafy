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
                return $this->wafyBlock('unavailable', 'Service temporairement indisponible.', 'unavailable', 503, false);
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

                return is_null($bannedIp->banned_until)
                    ? $this->wafyBlock('banned_permanent', 'Votre IP est bannie définitivement.', 'banned', 403)
                    : $this->wafyBlock('banned_temporary', 'Votre IP est temporairement bannie.', 'banned', 403);
            }

            // Ban temporaire expiré. En mode backoff, on GARDE la ligne pour que
            // le compteur d'offenses survive (escalade) — mais seulement pendant
            // la fenêtre de grâce backoff_reset_after ; passé ce délai on la
            // supprime à l'accès (filet de nettoyage sans dépendre de wafy:prune).
            // Hors backoff, suppression immédiate (comportement historique).
            $resetAfter = (int) config('wafy.backoff_reset_after', 30);
            $stale = $resetAfter > 0
                && $bannedIp->updated_at !== null
                && $bannedIp->updated_at->lessThan(now()->subDays($resetAfter));

            if (!config('wafy.backoff_enabled', true) || $stale) {
                $bannedIp->delete();
            }
        }

        // No active ban -> remember the identity as clean for a short while.
        $this->rememberClean($identity);

        return $next($request);
    }
}
