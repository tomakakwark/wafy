<?php

namespace Bdsa\Wafy\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Bdsa\Wafy\Models\BannedIp;

class DetectMaliciousRequests
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

        // Détection des patterns malveillants
        $patterns = config('wafy.patterns');

        $queryString = $request->getQueryString() ?? '';
        $requestBody = json_encode($request->all(), JSON_UNESCAPED_SLASHES);

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $queryString) || preg_match($pattern, $requestBody)) {
                Log::warning('Tentative d\'injection SQL détectée de ' . $clientIp);

                if (!BannedIp::where('ip_address', $clientIp)->exists()) {
                    BannedIp::create(['ip_address' => $clientIp]);
                }

                return response()->json(['message' => 'Votre IP est bannie.'], 403);
            }
        }

        return $next($request);
    }
}