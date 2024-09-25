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

        $bannedIp = BannedIp::where('ip_address', $clientIp)->first();

        if ($bannedIp) {
            // Vérifier si le bannissement est encore en cours
            if ($bannedIp->banned_until && now()->lessThan($bannedIp->banned_until)) {
                return response()->json(['message' => 'Votre IP est temporairement bannie.'], 403);
            }
            // Si le bannissement est expiré, on le supprime de la base de données
            $bannedIp->delete();
        }

        return $next($request);
    }
}
