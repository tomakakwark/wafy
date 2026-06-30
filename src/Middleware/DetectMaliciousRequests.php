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

        $subjects = [
            'QueryString' => $request->getQueryString() ?? '',
            'RequestBody' => json_encode($request->all(), JSON_UNESCAPED_SLASHES),
            'UserAgent' => $request->header('User-Agent') ?? '',
            'Referer' => $request->header('Referer') ?? '',
            'Path' => '/' . ltrim($request->path(), '/'),
        ];

        foreach ($subjects as $fieldName => $value) {
            $decodedValue = $this->recursiveUrldecode($value);

            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $decodedValue)) {
                    Log::warning("Wafy: Malicious pattern detected form {$clientIp} in {$fieldName}. Pattern: {$pattern}");

                    // If in Log-Only mode, ensure we log but DO NOT BLOCK
                    if ($action === 'log') {
                        Log::info("Wafy (Log-Only): Request allowed for {$clientIp}");
                        continue 2; // Move to next field
                    }

                    $banData = [
                        'ip_address' => $clientIp,
                        'reason' => "Malicious pattern detected in {$fieldName}: {$pattern}",
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
                        } catch (\Exception $e) {
                            Log::error("Wafy: Failed to send ban notification: " . $e->getMessage());
                        }
                    }

                    return response()->json(['message' => 'Votre IP est bannie.'], 403);
                }
            }
        }

        return $next($request);
    }

    /**
     * Recursively urldecode a string to handle multi-encoded payloads.
     */
    private function recursiveUrldecode($string)
    {
        $prev = '';
        $curr = $string;

        // Limite à 5 décodages pour éviter les boucles infinies ou les attaques DoS
        $maxDepth = 5;
        while ($curr !== $prev && $maxDepth > 0) {
            $prev = $curr;
            $curr = urldecode($curr);
            $maxDepth--;
        }

        return $curr;
    }
}