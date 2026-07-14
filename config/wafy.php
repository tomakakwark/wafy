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

    /*
    |--------------------------------------------------------------------------
    | Moteur de détection : scoring pondéré
    |--------------------------------------------------------------------------
    | Chaque règle possède un `id`, un `score` et un `pattern`. Pour chaque
    | requête, Wafy additionne le score de TOUTES les règles qui matchent (une
    | règle ne compte qu'une fois, quel que soit le nombre de champs touchés) et
    | ne bloque/bannit que si le total atteint `score_threshold`.
    |
    | L'intérêt : un signal ambigu isolé (score faible) ne bloque plus une
    | requête légitime — il faut soit un signal fort (score >= seuil), soit
    | plusieurs signaux corroborants. C'est le remède de fond aux faux positifs.
    |
    | Barème indicatif : 5 = attaque non ambiguë (bloque seule) · 4 = signal fort
    | (bloque seul) · 3 = moyen (a besoin d'un signal de plus) · 2 = faible ·
    | 1 = simple indice. Ajustez librement, désactivez une règle en la retirant.
    |
    | Rétro-compat : si `rules` est vide mais que l'ancienne clé `patterns` (liste
    | plate de regex) existe, chaque pattern est traité comme une règle au score
    | du seuil — le comportement historique (blocage au premier match) est
    | conservé pour les configs déjà publiées.
    */
    'score_threshold' => (int) env('WAFY_SCORE_THRESHOLD', 4),

    /*
    | ban_score_threshold : score à partir duquel une requête (déjà bloquée)
    |   devient ÉLIGIBLE à un bannissement persistant — l'escalade réelle restant
    |   gouvernée par `ban_threshold` (nombre de strikes). Par défaut égal à
    |   `score_threshold` : tout ce qui est bloqué peut mener à un ban (comportement
    |   habituel). Réglages possibles :
    |     • Bloquer SANS bannir les menaces moyennes : score_threshold=4,
    |       ban_score_threshold=8 (bloque dès 4, ne bannit qu'à partir de 8).
    |     • Bannissement STRICT au premier match : score_threshold=1,
    |       ban_score_threshold=1, ban_threshold=1 (toute règle qui matche bannit).
    */
    'ban_score_threshold' => (int) env('WAFY_BAN_SCORE_THRESHOLD', (int) env('WAFY_SCORE_THRESHOLD', 4)),

    'rules' => [
        // === SQL Injection (SQLi) ===
        ['id' => 'sqli.union_select',    'score' => 5, 'pattern' => '/(union(\s+all)?\s+select)/i'],
        ['id' => 'sqli.paren_obfusc',    'score' => 5, 'pattern' => '/(?:select\s*\(.*?\)\s*from|union\s*\(.*?\)\s*select)/i'],
        // SELECT … FROM uniquement avec un contexte d'injection réel (évite la prose « select an item from »).
        ['id' => 'sqli.select_from',     'score' => 3, 'pattern' => '/\bselect\b[\s\S]{0,150}?\bfrom\b[\s\S]{0,150}?(\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\blimit\b|\bunion\b|\binto\b|\bhaving\b|\bprocedure\b|--|#|;|information_schema)/i'],
        // DML avec contexte SQL (pas la prose « delete from your cart »).
        ['id' => 'sqli.dml',             'score' => 3, 'pattern' => '/\b(delete\s+from|insert\s+into|update\b[\s\S]{0,60}?\bset)\b[\s\S]{0,150}?(\bwhere\b|--|#|;|\bvalues\s*\(|\bselect\b|information_schema)/i'],
        // DDL destructif : DROP/ALTER/TRUNCATE/CREATE/RENAME/GRANT.
        ['id' => 'sqli.ddl',             'score' => 4, 'pattern' => '/\b(drop|alter|truncate|rename)\s+(table|database|schema|index|view)\b|\bcreate\s+(table|database)\b|\bgrant\s+all\b/i'],
        // Requêtes empilées : « ; SELECT … », « ; DROP … ».
        ['id' => 'sqli.stacked',         'score' => 3, 'pattern' => '/;\s*(select|insert|update|delete|drop|create|alter|truncate)\b/i'],
        // Tautologie (auth-bypass) : « OR 1=1 », « ' OR '1'='1 » — opérandes identiques (backref).
        ['id' => 'sqli.tautology',       'score' => 4, 'pattern' => '/\b(or|and)\s+([\'"`]?)(\w+)\2\s*(=|<>|!=|<|>|\blike\b)\s*([\'"`]?)\3\b/i'],
        // Comparaison numérique booléenne « OR 5>1 » (indice faible, sujet aux maths).
        ['id' => 'sqli.bool_numeric',    'score' => 2, 'pattern' => '/\b(or|and)\s+\d+\s*(=|<>|!=|<|>)\s*\d+(\s|$|--|#|;|\))/i'],
        ['id' => 'sqli.schema_probe',    'score' => 3, 'pattern' => '/(information_schema\.|\btable_schema\b)/i'],
        // Littéral 0x uniquement en contexte SQL (adresses crypto / IDs hexa isolés = légitimes).
        ['id' => 'sqli.hex_ctx',         'score' => 4, 'pattern' => '/\b0x[0-9a-f]{2,}\b[\s\S]{0,40}\b(from|where|union|select|order\s+by|limit)\b|\b(select|union|unhex|concat|values)\b[\s\S]{0,40}\b0x[0-9a-f]{2,}\b/i'],
        ['id' => 'sqli.unhex_char',      'score' => 3, 'pattern' => '/(unhex\s*\(.*?\)|\bchar\s*\(\s*\d+\s*(,\s*\d+\s*)*\))/i'],
        // Breakout de quote/parenthèse suivi d'un commentaire (« admin'-- », « 1')# ») : signal fort.
        ['id' => 'sqli.quote_comment',   'score' => 4, 'pattern' => '/[\'"`)](--|#)/'],
        // Formes de commentaire ambiguës (score faible) : « /*! » (aussi présent dans le CSS
        // minifié), plage numérique « 5--10 », « -- » en fin de champ. Ne bloque pas seul.
        ['id' => 'sqli.comment',         'score' => 2, 'pattern' => '/(\/\*!|\b\d+\s*--|--\s*$|#\s*sqli)/i'],
        ['id' => 'sqli.time_based',      'score' => 4, 'pattern' => '/(waitfor\s+delay|benchmark\s*\(|sleep\s*\(\s*\d|pg_sleep\s*\(|dbms_pipe\.receive_message)/i'],
        // Écriture de fichier (webshell) et extraction error-based.
        ['id' => 'sqli.into_outfile',    'score' => 5, 'pattern' => '/\binto\s+(out|dump)file\b/i'],
        ['id' => 'sqli.error_based',     'score' => 4, 'pattern' => '/\b(extractvalue|updatexml|load_file)\s*\(/i'],

        // === Local File Inclusion (LFI) & Path Traversal ===
        ['id' => 'lfi.traversal',        'score' => 5, 'pattern' => '/(\.\.\/|\.\.\\\\|\.\.%2f|\.\.%5c|\.\.%252f)/i'],
        ['id' => 'lfi.system_files',     'score' => 5, 'pattern' => '/(\/etc\/passwd|C:\\\\Windows\\\\win\.ini|C:\/Windows\/win\.ini|\/boot\.ini)/i'],
        ['id' => 'lfi.etc_shadow',       'score' => 5, 'pattern' => '/(\/proc\/self\/environ|\/etc\/shadow)/i'],
        ['id' => 'lfi.var_log',          'score' => 2, 'pattern' => '/\/var\/log\b/i'],
        ['id' => 'lfi.php_wrappers',     'score' => 4, 'pattern' => '/(php:\/\/filter|php:\/\/input|file:\/\/|phar:\/\/|expect:\/\/|zip:\/\/)/i'],
        ['id' => 'lfi.config_files',     'score' => 3, 'pattern' => '/(\.env(?![a-z0-9])|auth\.json|launchSettings\.json)/i'],

        // === Cross-Site Scripting (XSS) ===
        // Data URI exécutable uniquement (image/*, application/pdf exclus : uploads légitimes).
        ['id' => 'xss.data_uri',         'score' => 4, 'pattern' => '/(data:(text\/(html|javascript)|image\/svg\+xml|application\/(xhtml\+xml|xml))\s*;base64,)/i'],
        ['id' => 'xss.script_tag',       'score' => 5, 'pattern' => '/(<script.*?>.*?<\/script>)/is'],
        ['id' => 'xss.script_brute',     'score' => 3, 'pattern' => '/(?:%3C|%3e|<|>)script/i'],
        ['id' => 'xss.js_protocol',      'score' => 3, 'pattern' => '/(javascript:[^\s])/i'],
        // Handler d'événement inline dans une balise (tous les on*, tolérant à l'espace).
        ['id' => 'xss.event_handler',    'score' => 4, 'pattern' => '/<[a-z!][^>]{0,200}?[\s\/]on[a-z]{3,}\s*=/i'],
        ['id' => 'xss.dangerous_tags',   'score' => 4, 'pattern' => '/(<iframe.*?>|<iframe>|<object.*?>|<embed.*?>|<base\b)/i'],

        // === Remote Code Execution (RCE) / Command Injection ===
        ['id' => 'rce.php_functions',    'score' => 5, 'pattern' => '/(base64_decode|eval\(|system\(|exec\(|shell_exec\(|passthru\()/i'],
        // Séparateur shell (hors « & » seul, trop courant) + binaire, sans espace final requis.
        ['id' => 'rce.command_inject',   'score' => 4, 'pattern' => '/([;|]|\|\||&&)\s*(ls|cat|pwd|whoami|id|uname|wget|curl|netcat|nc|bash|sh|zsh|python[23]?|perl|ruby|ping|nslookup|dig|rm|chmod|chown|xxd|nohup|nmap)\b/i'],
        // Substitution de commande $(commande) — exclut jQuery $(document).
        ['id' => 'rce.command_subst',    'score' => 4, 'pattern' => '/\$\(\s*(ls|cat|id|whoami|uname|curl|wget|nc|bash|sh|python|perl|echo|env|base64|printf|head|tail|awk|sed)\b/i'],
        ['id' => 'rce.lua',              'score' => 5, 'pattern' => '/(%\{lua:os\.execute\(.*?\)\})/i'],

        // === Scanner & Exploit Signatures ===
        ['id' => 'scanner.sensitive',    'score' => 2, 'pattern' => '/(\/manager\/html|\/wp-admin|\/wp-content\/plugins|\/cgi-bin)/i'],
        ['id' => 'scanner.exploit_path', 'score' => 3, 'pattern' => '/(\/XMLPService|\/RPC2|\/igd\/v1\/get-users-data|\/convertCSVtoParquet\.php)/i'],
        ['id' => 'scanner.checkwaf',     'score' => 2, 'pattern' => '/(checkwaf=)/i'],
    ],
];
