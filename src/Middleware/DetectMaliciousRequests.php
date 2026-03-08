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

        // Check action mode (block vs log)
        $action = cache('wafy.action', config('wafy.action', 'block'));

        // Fast early exit: Check if already banned and skip patterns
        if (BannedIp::where('ip_address', $clientIp)->exists() && $action !== 'log') {
            return response()->json(['message' => 'Votre IP est bannie.'], 403);
        }

        // Détection des patterns malveillants
        $patterns = config('wafy.patterns');

        $queryString = $request->getQueryString() ?? '';
        $requestBody = json_encode($request->all(), JSON_UNESCAPED_SLASHES);
        $userAgent = $request->header('User-Agent') ?? '';
        $referer = $request->header('Referer') ?? '';

        $subjectToTest = $queryString . ' | ' . $requestBody . ' | ' . $userAgent . ' | ' . $referer;

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $subjectToTest)) {
                Log::warning("Wafy: Malicious pattern detected form {$clientIp}. Pattern: {$pattern}");

                // If in Log-Only mode, ensure we log but DO NOT BLOCK
                if ($action === 'log') {
                    Log::info("Wafy (Log-Only): Request allowed for {$clientIp}");
                    continue; // Skip onto the next pattern or just finish loop effectively
                }

                $banData = [
                    'ip_address' => $clientIp,
                    'reason' => "Malicious pattern detected: {$pattern}",
                    'request_data' => [
                        'method' => $request->method(),
                        'url' => $request->fullUrl(),
                        'input' => $request->all(),
                    ],
                ];

                $bannedIpModel = BannedIp::create($banData);

                // Send Notifications
                if (config('wafy.notifications.enabled')) {
                    try {
                        $bannedIpModel->notify(new \Bdsa\Wafy\Notifications\IpBannedNotification($bannedIpModel));
                    }
                    catch (\Exception $e) {
                        Log::error("Wafy: Failed to send ban notification: " . $e->getMessage());
                    }
                }

                return response()->json(['message' => 'Votre IP est bannie.'], 403);
            }
        }

        return $next($request);
    }
}