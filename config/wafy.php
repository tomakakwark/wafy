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
    'ban_threshold' => (int) env('WAFY_BAN_THRESHOLD', 3),
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

    /*
    | ban_private_ips : par défaut Wafy REFUSE de bannir une IP privée / réservée
    |   / loopback. Une telle IP est presque toujours le signe que TrustProxies
    |   n'est pas configuré et que $request->ip() renvoie l'adresse du proxy/CDN :
    |   la bannir couperait TOUT le trafic (self-DoS). Ne passez à true que si vos
    |   clients ont légitimement des IP privées (réseau interne, sans proxy).
    */
    'ban_private_ips' => (bool) env('WAFY_BAN_PRIVATE_IPS', false),

    // Seuls les NOMS d'en-têtes apparaissent dans les logs (jamais leurs valeurs),
    // donc scanner Cookie / X-Forwarded-For ne persiste pas leur contenu.
    'scan_headers' => ['User-Agent', 'Referer', 'Cookie', 'X-Forwarded-For', 'X-Forwarded-Host', 'Origin', 'X-Api-Version'],
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
        '/(?:select\s*\(.*?\)\s*from|union\s*\(.*?\)\s*select)/i', // Obfuscation par parenthèses `(select(id)from...)`
        // SELECT ... FROM uniquement avec un contexte d'injection réel (union / where /
        // commentaire / etc.) — évite de bannir la prose « select an item from the menu ».
        '/\bselect\b[\s\S]{0,150}?\bfrom\b[\s\S]{0,150}?(\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\blimit\b|\bunion\b|\binto\b|\bhaving\b|\bprocedure\b|--|#|;|information_schema)/i',
        // DML destructif / lecture avec contexte SQL (pas la prose « delete from your cart »).
        '/\b(delete\s+from|insert\s+into|update\b[\s\S]{0,60}?\bset)\b[\s\S]{0,150}?(\bwhere\b|--|#|;|\bvalues\s*\(|\bselect\b|information_schema)/i',
        '/(information_schema\.|table_schema)/i', // Schema probing (table_name retiré : trop générique)
        '/(unhex\s*\(.*?\))/i', // Unhex function (common in SQLi)
        // Littéral hexadécimal 0x uniquement accolé à un mot-clé SQL — les adresses crypto
        // (0x71C7…) et les IDs hexa isolés sont légitimes et ne doivent plus bannir.
        '/\b0x[0-9a-f]{2,}\b[\s\S]{0,40}\b(from|where|union|select|order\s+by|limit)\b|\b(select|union|unhex|concat|values)\b[\s\S]{0,40}\b0x[0-9a-f]{2,}\b/i',
        // Commentaires SQL contextualisés : plus de faux positif sur les signatures e-mail
        // « -- » (RFC 3676) ni sur le CSS/JS « /* … */ » collé dans un éditeur riche.
        '/(\/\*!|[\'"`)\d]--|[\'"`)]\s*#|--\s*$|#\s*sqli)/i',
        '/(waitfor\s+delay|benchmark\s*\(|sleep\s*\(\s*\d|pg_sleep\s*\()/i', // Time-based blind SQLi

        // --- Local File Inclusion (LFI) & Path Traversal ---
        '/(\.\.\/|\.\.\\\\|\.\.%2f|\.\.%5c|\.\.%252f)/i', // Traversal including double encoding & windows
        '/(\/etc\/passwd|C:\\\\Windows\\\\win\.ini|C:\/Windows\/win\.ini|\/boot\.ini)/i', // Common system files
        '/(\/proc\/self\/environ|\/etc\/shadow|\/var\/log)/i', // Sensitive Linux files
        '/(php:\/\/filter|php:\/\/input|file:\/\/|phar:\/\/|expect:\/\/|zip:\/\/)/i', // PHP wrappers
        '/(\.env(?![a-z0-9])|auth\.json|launchSettings\.json)/i', // Sensitive config files (.env ancré : plus de FP sur « 3.Environment »)

        // --- Cross-Site Scripting (XSS) ---
        // Data URI exécutable uniquement — image/*, application/pdf, font/* exclus
        // (uploads de signature, avatars, images collées légitimes).
        '/(data:(text\/(html|javascript)|image\/svg\+xml|application\/(xhtml\+xml|xml))\s*;base64,)/i',
        '/(<script.*?>.*?<\/script>)/is', // Script tags
        '/(?:%3C|%3e|<|>)script/i', // Variante brute pour pallier certains doubles-encodages
        '/(javascript:[^\s])/i', // Pseudo-protocole javascript: suivi d'une charge (pas la prose « JavaScript: … »)
        // Handler d'événement inline DANS une balise : couvre tous les on* (whitespace-tolérant),
        // sans le faux positif de « onboarding= » hors contexte HTML.
        '/<[a-z!][^>]{0,200}?[\s\/]on[a-z]{3,}\s*=/i',
        '/(<iframe.*?>|<iframe>|<object.*?>|<embed.*?>|<base\b)/i', // Dangerous tags

        // --- Remote Code Execution (RCE) / Command Injection ---
        '/(base64_decode|eval\(|system\(|exec\(|shell_exec\(|passthru\()/i', // PHP execution functions
        // Séparateur shell (hors « & » seul, trop courant en prose) + binaire, sans exiger
        // d'espace final : couvre « ;id », « |whoami », « ;bash -i »…
        '/([;|]|\|\||&&)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|netcat|nc|bash|sh|zsh|python[23]?|perl|ruby|ping|nslookup|dig|rm|chmod|chown|xxd|nohup|nmap)\b/i',
        // Substitution de commande $(commande) — exclut jQuery $(document) et la prose.
        '/\$\(\s*(ls|cat|id|whoami|uname|curl|wget|nc|bash|sh|python|perl|echo|env|base64|printf|head|tail|awk|sed)\b/i',
        '/(%\{lua:os\.execute\(.*?\)\})/i', // Lua RCE seen in logs

        // --- Common Scanner & Exploit Signatures ---
        '/(\/manager\/html|\/wp-admin|\/wp-content\/plugins|\/cgi-bin)/i', // Sensitive areas
        '/(\/XMLPService|\/RPC2|\/igd\/v1\/get-users-data|\/convertCSVtoParquet\.php)/i', // Specific exploit paths
        '/(checkwaf=)/i', // Detect explicit WAF testing if desired
    ],
];
