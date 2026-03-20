<?php

return [
    'action' => env('WAFY_ACTION', 'block'), // 'block' or 'log'
    'enabled' => env('WAFY_ENABLED', true),
    'allowed_ips' => [],
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
        '/(\/\*.*\*\/|--\s)/', // SQL Comments
        '/(waitfor\s+delay|benchmark\()/i', // Time-based blind SQLi
        '/(sleep\(\s*\d+\s*\))/i', // Sleep function

        // --- Local File Inclusion (LFI) & Path Traversal ---
        '/(\.\.\/|\.\.\\\\)/', // Directory traversal
        '/(\/etc\/passwd|\/windows\/win\.ini|\/boot\.ini)/i', // Common system files
        '/(\/proc\/self\/environ|\/etc\/shadow|\/var\/log)/i', // Sensitive Linux files
        '/(php:\/\/filter|php:\/\/input|file:\/\/)/i', // PHP wrappers

        // --- Cross-Site Scripting (XSS) ---
        '/(data:text\/(html|javascript);base64,)/i', // Base64 Data URI XSS
        '/(?:data:[^\/]+\/[^;]+;base64,)/i', // Base64 Data URI XSS élargi
        '/(<script.*?>.*?<\/script>)/is', // Script tags
        '/(?:%3C|%3e|<|>)script/i', // Variante brute pour pallier certains doubles-encodages
        '/(javascript:[^\s]*)/i', // Javascript pseudo-protocol
        '/(on(load|error|click|mouseover|submit|reset|focus|blur)=)/i', // Event handlers
        '/(<iframe.*?>|<iframe>)/i', // iFrames
        '/(<object.*?>|<embed.*?>)/i', // Object/Embed tags

        // --- Remote Code Execution (RCE) / Command Injection ---
        '/(base64_decode|eval\(|system\(|exec\(|shell_exec\(|passthru\()/i', // PHP execution functions
        '/(\||;|&)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|netcat|nc)\s+/i', // Common shell commands linked
    ],
];