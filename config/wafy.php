<?php

return [
    'enabled' => env('WAFY_ENABLED', true),
    'allowed_ips' => [],
    'patterns' => [
        // --- SQL Injection (SQLi) ---
        '/(union(\s+all)?\s+select)/i', // UNION SELECT
        '/(select\s+.*\s+from|delete\s+from|update\s+.*\s+set|insert\s+into)/i', // Basic SQL commands
        '/(information_schema\.|table_schema|table_name)/i', // Schema probing
        '/(0x[0-9a-f]{2,})/i', // Hex encoded data
        '/(\/\*.*\*\/|--\s)/', // SQL Comments
        '/(waitfor\s+delay|benchmark\()/i', // Time-based blind SQLi
        '/(sleep\(\s*\d+\s*\))/i', // Sleep function

        // --- Local File Inclusion (LFI) & Path Traversal ---
        '/(\.\.\/|\.\.\\\\)/', // Directory traversal
        '/(\/etc\/passwd|\/windows\/win\.ini|\/boot\.ini)/i', // Common system files
        '/(php:\/\/filter|php:\/\/input|file:\/\/)/i', // PHP wrappers

        // --- Cross-Site Scripting (XSS) ---
        '/(<script.*?>.*?<\/script>)/is', // Script tags
        '/(javascript:[^\s]*)/i', // Javascript pseudo-protocol
        '/(on(load|error|click|mouseover|submit|reset|focus|blur)=)/i', // Event handlers
        '/(<iframe.*?>|<iframe>)/i', // iFrames
        '/(<object.*?>|<embed.*?>)/i', // Object/Embed tags

        // --- Remote Code Execution (RCE) / Command Injection ---
        '/(base64_decode|eval\(|system\(|exec\(|shell_exec\(|passthru\()/i', // PHP execution functions
        '/(\||;|&)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|netcat|nc)\s+/i', // Common shell commands linked
    ],
];