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

        // Détection des patterns malveillants
        $patterns = config('wafy.patterns');

        $queryString = $request->getQueryString();
        $requestBody = json_encode($request->all());

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
