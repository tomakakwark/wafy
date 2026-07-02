<?php

return [
    'action' => env('WAFY_ACTION', 'block'), // 'block' or 'log'
    'enabled' => env('WAFY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Allowed IPs (whitelist)
    |--------------------------------------------------------------------------
    | IP addresses OR CIDR ranges (IPv4 & IPv6) that bypass Wafy entirely.
    | Examples: '127.0.0.1', '10.0.0.0/8', '2001:db8::/32'.
    |
    | IMPORTANT: if your app runs behind a reverse proxy / load balancer / CDN
    | (Nginx, Cloudflare, etc.), configure Laravel's TrustProxies middleware so
    | that $request->ip() resolves the REAL client IP. Otherwise Wafy sees the
    | proxy IP and a single malicious request can ban your own proxy — cutting
    | off all traffic. Never trust proxies with a blanket '*' unless the app is
    | only reachable through that proxy.
    */
    'allowed_ips' => [],

    /*
    |--------------------------------------------------------------------------
    | Ban policy
    |--------------------------------------------------------------------------
    | ban_threshold : number of malicious detections from a single IP (within
    |   `strike_window` minutes) required before that IP is banned. The
    |   offending request is ALWAYS blocked in "block" mode; the threshold only
    |   governs when a persistent IP ban is created. Raise it above 1 so that a
    |   single false positive does not permanently lock out a legitimate (and
    |   possibly shared / NAT / mobile) IP.
    | ban_duration : lifetime of an automatic ban, in minutes. Use null for a
    |   permanent ban. Temporary bans limit collateral damage from false
    |   positives and shared IPs. Manual bans (wafy:ban) stay permanent.
    */
    'ban_threshold' => (int) env('WAFY_BAN_THRESHOLD', 1),
    'strike_window' => (int) env('WAFY_STRIKE_WINDOW', 60), // minutes
    'ban_duration' => env('WAFY_BAN_DURATION', 1440), // minutes (24h); null = permanent

    /*
    |--------------------------------------------------------------------------
    | Hardening
    |--------------------------------------------------------------------------
    | max_scan_length : maximum number of characters inspected per field. Caps
    |   the CPU cost of the regex engine (ReDoS protection) on large bodies.
    | fail_open : if the ban database is unreachable, let requests through
    |   (true) instead of returning an error for every request (false).
    | scan_headers : request headers inspected for malicious patterns.
    | sensitive_keys : input keys whose values are redacted before a request is
    |   persisted or sent in a notification (avoids storing passwords/PII).
    */
    'max_scan_length' => (int) env('WAFY_MAX_SCAN_LENGTH', 16384),
    'fail_open' => (bool) env('WAFY_FAIL_OPEN', true),
    'scan_headers' => ['User-Agent', 'Referer'],
    'sensitive_keys' => [
        'password', 'password_confirmation', 'current_password',
        'token', '_token', 'api_token', 'api_key', 'apikey', 'secret',
        'authorization', 'access_token', 'refresh_token', 'private_key',
        'credit_card', 'card_number', 'cvv', 'cvc',
    ],

    'notifications' => [
        'enabled' => env('WAFY_NOTIFICATIONS_ENABLED', false),
        'channels' => ['mail'], // Can be ['mail', 'slack']
        'email' => env('WAFY_NOTIFICATION_EMAIL', 'admin@example.com'),
        'slack_webhook' => env('WAFY_SLACK_WEBHOOK', ''),
    ],

    'patterns' => [
        // --- SQL Injection (SQLi) ---
        '/(union(\s+all)?\s+select)/i', // UNION SELECT
        '/(select\s+.*\s+from|delete\s+from|update\s+.*\s+set|insert\s+into)/i', // Basic SQL commands
        '/(select[\s\S]*?from|union[\s\S]*?select|insert[\s\S]*?into|update[\s\S]*?set|delete[\s\S]*?from)/i', // Packed/obfuscated SQL commands
        '/(?:select\s*\(.*?\)\s*from|union\s*\(.*?\)\s*select)/i', // Contre l'obfuscation par parenthèses `(select(id)from...)`
        '/(information_schema\.|table_schema|table_name)/i', // Schema probing
        '/\b(0x[0-9a-f]{2,})\b/i', // Hex encoded data
        '/(unhex\s*\(.*?\))/i', // Unhex function (common in SQLi)
        '/(\/\*.*\*\/|--\s|#\s*sqli)/', // SQL Comments (added #sqli seen in logs)
        '/(waitfor\s+delay|benchmark\(|sleep\(\s*\d+\s*\))/i', // Time-based blind SQLi

        // --- Local File Inclusion (LFI) & Path Traversal ---
        '/(\.\.\/|\.\.\\\\|\.\.%2f|\.\.%5c|\.\.%252f)/i', // Traversal including double encoding & windows
        '/(\/etc\/passwd|C:\\\\Windows\\\\win\.ini|C:\/Windows\/win\.ini|\/boot\.ini)/i', // Common system files
        '/(\/proc\/self\/environ|\/etc\/shadow|\/var\/log)/i', // Sensitive Linux files
        '/(php:\/\/filter|php:\/\/input|file:\/\/)/i', // PHP wrappers
        '/(\.env|auth\.json|launchSettings\.json)/i', // Sensitive config files

        // --- Cross-Site Scripting (XSS) ---
        '/(data:text\/(html|javascript);base64,)/i', // Base64 Data URI XSS
        '/(?:data:[^\/]+\/[^;]+;base64,)/i', // Base64 Data URI XSS élargi
        '/(<script.*?>.*?<\/script>)/is', // Script tags
        '/(?:%3C|%3e|<|>)script/i', // Variante brute pour pallier certains doubles-encodages
        '/(javascript:[^\s]*)/i', // Javascript pseudo-protocol
        '/(on(load|error|click|mouseover|submit|reset|focus|blur)=)/i', // Event handlers
        '/(<iframe.*?>|<iframe>|<object.*?>|<embed.*?>)/i', // Dangerous tags

        // --- Remote Code Execution (RCE) / Command Injection ---
        '/(base64_decode|eval\(|system\(|exec\(|shell_exec\(|passthru\()/i', // PHP execution functions
        '/(\||;|&)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|netcat|nc|rpm|ifconfig)\s+/i', // Common shell commands linked
        '/(%\{lua:os\.execute\(.*?\)\})/i', // Lua RCE seen in logs

        // --- Common Scanner & Exploit Signatures ---
        '/(\/manager\/html|\/wp-admin|\/wp-content\/plugins|\/cgi-bin)/i', // Sensitive areas
        '/(\/XMLPService|\/RPC2|\/igd\/v1\/get-users-data|\/convertCSVtoParquet\.php)/i', // Specific exploit paths
        '/(checkwaf=)/i', // Detect explicit WAF testing if desired
    ],
];
