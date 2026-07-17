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
    | ipv6_ban_prefix : longueur de préfixe utilisée pour bannir/compter les
    |   strikes d'une adresse IPv6. Par défaut 64 : les bans portent sur le
    |   réseau /64 (ce qu'un FAI/hébergeur alloue en général à UN client), ce qui
    |   empêche l'attaquant de contourner un ban en changeant d'adresse parmi les
    |   milliards de son allocation. Mettez 128 pour bannir l'adresse exacte.
    |   Sans effet sur l'IPv4 (toujours bannie par adresse exacte).
    */
    'ipv6_ban_prefix' => (int) env('WAFY_IPV6_BAN_PREFIX', 64),

    /*
    | retention_days : durée de conservation maximale d'un enregistrement de ban
    |   (RGPD : l'IP + les données de requête ne sont pas gardées indéfiniment).
    |   null = pas de limite. La commande `wafy:prune` supprime les bans
    |   temporaires expirés et, si défini, les bans plus vieux que ce nombre de
    |   jours. Planifiez-la (ex. $schedule->command('wafy:prune')->daily()).
    */
    'retention_days' => env('WAFY_RETENTION_DAYS', null),

    /*
    |--------------------------------------------------------------------------
    | Backoff exponentiel des bans
    |--------------------------------------------------------------------------
    | Un récidiviste écope de bans de plus en plus longs : durée (minutes) =
    | backoff_base * backoff_multiplier^(offense-1), plafonnée à backoff_max. Le
    | compteur d'offenses survit à l'expiration du ban (la ligne n'est plus
    | supprimée à l'expiration ni par wafy:prune avant backoff_reset_after jours),
    | pour qu'un attaquant ne réinitialise pas sa peine en attendant. Désactivez
    | pour retrouver la durée fixe historique (ban_duration).
    */
    'backoff_enabled' => (bool) env('WAFY_BACKOFF_ENABLED', true),
    'backoff_base' => (int) env('WAFY_BACKOFF_BASE', (int) env('WAFY_BAN_DURATION', 1440)),
    'backoff_multiplier' => (float) env('WAFY_BACKOFF_MULTIPLIER', 2),
    'backoff_max' => (int) env('WAFY_BACKOFF_MAX', 43200), // 30 jours
    'escalate_to_permanent_after' => env('WAFY_ESCALATE_TO_PERMANENT_AFTER', null), // null = jamais
    'backoff_reset_after' => (int) env('WAFY_BACKOFF_RESET_AFTER', 30), // jours de calme avant oubli

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
    |   persisted or sent in a notification (avoids storing passwords/PII). Matched
    |   as a SUBSTRING of the key name, so "password" also covers "user_password",
    |   "billingCardNumber" is covered by "card", etc.
    | max_stored_value_length : long input values are truncated to this many chars
    |   before being stored in a ban record (avoids bloating / overflowing the DB).
    */
    'max_scan_length' => (int) env('WAFY_MAX_SCAN_LENGTH', 16384),
    'fail_open' => (bool) env('WAFY_FAIL_OPEN', true),

    /*
    | ban_lookup_cache_ttl : durée (en secondes) de mise en cache du résultat
    |   « cette IP n'a PAS de ban » afin d'éviter une requête SQL par middleware
    |   et par requête HTTP pour le trafic légitime (99 % des cas). 0 = désactivé
    |   (comportement historique). Seuls les résultats « propre » sont cachés ;
    |   les bans sont invalidés à leur création. Une petite valeur (10-30 s) est
    |   un bon compromis ; nécessite un cache partagé (redis/database/file) pour
    |   être efficace en multi-serveur.
    */
    'ban_lookup_cache_ttl' => (int) env('WAFY_BAN_LOOKUP_CACHE_TTL', 0),

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
        'password', 'passwd', 'passphrase', 'passcode',
        'token', 'secret', 'authorization', 'bearer', 'apikey', 'api_key',
        'private_key', 'credential',
        'card', 'cvv', 'cvc', 'iban', 'ssn', 'session_id',
    ],
    'max_stored_value_length' => (int) env('WAFY_MAX_STORED_VALUE_LENGTH', 2048),

    /*
    | Uploads multipart : le corps brut (getContent) est vide en multipart, donc
    | les fichiers échappent au scan. scan_files inspecte le NOM des fichiers
    | (faible risque de FP, activé). scan_file_contents lit en plus une tranche
    | texte bornée du contenu — DÉSACTIVÉ par défaut car il peut faux-positiver
    | sur des uploads légitimes de code/SQL/HTML ; activez-le en connaissance.
    */
    'multipart' => [
        'scan_files' => (bool) env('WAFY_MULTIPART_SCAN_FILES', true),
        'scan_file_contents' => (bool) env('WAFY_MULTIPART_SCAN_CONTENTS', false),
        'max_files' => (int) env('WAFY_MULTIPART_MAX_FILES', 20),
        'max_file_size' => (int) env('WAFY_MULTIPART_MAX_FILE_SIZE', 1048576), // octets ; au-dessus = non lu
        'max_file_bytes' => (int) env('WAFY_MULTIPART_MAX_FILE_BYTES', 8192),  // octets scannés / fichier
    ],

    /*
    |--------------------------------------------------------------------------
    | Honeypot / chemins pièges
    |--------------------------------------------------------------------------
    | URLs qu'aucun client légitime ne demande (sondes WordPress, git, phpMyAdmin…).
    | Tout hit est un bot quasi certain : bloqué et, si honeypot_ban=true, escaladé
    | vers un ban comme n'importe quelle détection. Comparé à $request->path()
    | (sans query), insensible à la casse, après normalisation du slash initial.
    | Exact ('/wp-login.php') ou glob fnmatch ('/wp-admin/*' — le '*' traverse '/').
    | ⚠ Un glob comme '/admin/*' piégera un '/admin/dashboard' légitime : n'ajoutez
    | que des chemins que votre app ne sert JAMAIS, préférez l'exact en cas de doute.
    */
    'honeypot_paths' => [
        '/wp-login.php',
        '/xmlrpc.php',
        '/wp-config.php',
        '/.git/config',
        '/.git/HEAD',
        '/phpmyadmin',
        '/phpmyadmin/*',
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    ],
    'honeypot_ban' => (bool) env('WAFY_HONEYPOT_BAN', true),

    /*
    |--------------------------------------------------------------------------
    | Détection par vélocité (rate limiting)
    |--------------------------------------------------------------------------
    | Attrape les scanners qui balaient beaucoup d'URLs SANS matcher de motif
    | (souvent une rafale de 404 : /.git/config, /backup.zip, /admin.php …).
    | Compté par IP (identité de ban, donc /64 en IPv6) sur une fenêtre glissante.
    |
    | Désactivé par défaut : réglez les seuils selon VOTRE trafic avant d'activer
    | (un SPA ou une IP partagée/NAT peut être volumineux). Une infraction est
    | traitée comme une détection (strike puis ban selon la politique habituelle).
    | Ignoré pour les IP privées/réservées non bannissables, afin de ne jamais
    | compter le trafic agrégé d'un proxy (anti self-DoS). Nécessite un cache
    | partagé et persistant (redis/database/file).
    |
    |   max_requests / max_404 : mettre 0 pour désactiver ce compteur.
    */
    'rate_limit' => [
        'enabled' => (bool) env('WAFY_RATE_LIMIT_ENABLED', false),
        'window' => (int) env('WAFY_RATE_WINDOW', 60),               // secondes
        'max_requests' => (int) env('WAFY_RATE_MAX_REQUESTS', 300),  // requêtes / fenêtre
        'max_404' => (int) env('WAFY_RATE_MAX_404', 40),             // 404 / fenêtre
    ],

    /*
    |--------------------------------------------------------------------------
    | Messages & codes de réponse (personnalisables / localisables)
    |--------------------------------------------------------------------------
    | Chaque valeur peut être une chaîne littérale (défaut) OU une clé de
    | traduction : si une ligne de langue existe (Lang::has), elle est passée à
    | trans() selon la locale ; sinon la chaîne est renvoyée telle quelle. Les
    | défauts ci-dessous reproduisent exactement le comportement historique.
    */
    'messages' => [
        'banned' => env('WAFY_MSG_BANNED', 'Votre IP est bannie.'),
        'blocked' => env('WAFY_MSG_BLOCKED', 'Requête bloquée.'),
        'unavailable' => env('WAFY_MSG_UNAVAILABLE', 'Service temporairement indisponible.'),
        'banned_permanent' => env('WAFY_MSG_BANNED_PERMANENT', 'Votre IP est bannie définitivement.'),
        'banned_temporary' => env('WAFY_MSG_BANNED_TEMPORARY', 'Votre IP est temporairement bannie.'),
    ],
    'status_codes' => [
        'blocked' => (int) env('WAFY_STATUS_BLOCKED', 403),
        'banned' => (int) env('WAFY_STATUS_BANNED', 403),
        'unavailable' => (int) env('WAFY_STATUS_UNAVAILABLE', 503),
    ],

    /*
    | Forme de la réponse de blocage :
    |   'json' (défaut, rétro-compatible) | 'view' (page HTML) | 'auto' (JSON pour
    |   les clients API expectsJson/wantsJson, sinon la vue HTML pour un navigateur).
    | Tarpit : délai borné (secondes) avant la réponse de blocage pour ralentir les
    | scanners. 0 = désactivé (défaut). ⚠ un sleep() bloque un worker PHP-FPM toute
    | sa durée — gardez-le petit ; jamais appliqué au 503 fail-open. Plafonné par
    | tarpit_max.
    */
    'response' => [
        'mode' => env('WAFY_RESPONSE_MODE', 'json'),
        'view' => env('WAFY_RESPONSE_VIEW', 'wafy::blocked'),
        'tarpit_seconds' => (int) env('WAFY_TARPIT_SECONDS', 0),
        'tarpit_max' => (int) env('WAFY_TARPIT_MAX', 5),
    ],

    /*
    |--------------------------------------------------------------------------
    | GeoIP — filtrage par pays / ASN
    |--------------------------------------------------------------------------
    | Opt-in. Ne REQUIERT aucune dépendance : fournit un résolveur par défaut
    | best-effort (MaxMind geoip2/geoip2 si une base est configurée, sinon
    | torann/geoip, sinon l'extension geoip_*) qui DÉGRADE proprement (aucune
    | base -> aucun blocage, un warning). Vous pouvez brancher votre propre
    | résolveur via 'resolver' (une Closure fn(?string $ip): ['country'=>, 'asn'=>]
    | ou le nom d'une classe implémentant Bdsa\Wafy\Contracts\GeoIpResolver).
    |   mode   : 'deny' (bloque les pays listés) ou 'allow' (n'autorise QUE les
    |            pays listés ; un pays inconnu passe, pour ne pas casser le trafic).
    |   action : 'block' (403), 'ban' (403 + ban), ou 'score' (+geoip.score au
    |            moteur de scoring, corrobore d'autres signaux).
    | Ignoré pour les IP privées/réservées (anti self-DoS).
    */
    'geoip' => [
        'enabled' => (bool) env('WAFY_GEOIP_ENABLED', false),
        'mode' => env('WAFY_GEOIP_MODE', 'deny'), // 'deny' | 'allow'
        'countries' => [], // ex. ['RU', 'CN', 'KP'] (deny) ou ['FR', 'BE'] (allow)
        'deny_asns' => [], // ex. [14061, 16509] (hébergeurs/VPN)
        'action' => env('WAFY_GEOIP_ACTION', 'block'), // 'block' | 'ban' | 'score'
        'score' => (int) env('WAFY_GEOIP_SCORE', 2), // < score_threshold => needs corroboration
        'resolver' => null, // Closure|string|null
        'database' => env('WAFY_GEOIP_DB', ''),     // chemin base MaxMind pays
        'asn_database' => env('WAFY_GEOIP_ASN_DB', ''), // chemin base MaxMind ASN
    ],

    /*
    | Logging structuré (SIEM). Chaque détection émet une ligne dont le CONTEXTE
    | est un schéma stable et parsable (event, ip, path, method, score, rules[],
    | action, decision) — sans jamais inclure la charge de l'attaquant. channel
    | null = canal de log par défaut de l'app.
    */
    'logging' => [
        'enabled' => (bool) env('WAFY_LOGGING_ENABLED', true),
        'channel' => env('WAFY_LOGGING_CHANNEL', null),
    ],

    /*
    | Statistiques : table append-only wafy_events écrite à chaque détection
    | (OPT-IN, défaut false -> zéro surcoût quand désactivé). Alimente wafy:stats.
    | stats.geo : résoudre le pays via GeoIP (si dispo). retention_days : purge
    | par wafy:prune.
    */
    'stats' => [
        'enabled' => (bool) env('WAFY_STATS_ENABLED', false),
        'geo' => (bool) env('WAFY_STATS_GEO', true),
        'retention_days' => (int) env('WAFY_STATS_RETENTION_DAYS', 90),
        // Coalesce : au plus 1 événement par identité+type par fenêtre (borne les
        // écritures sous flood). 0 = pas de dédup (une écriture par détection).
        'dedup_seconds' => (int) env('WAFY_STATS_DEDUP_SECONDS', 10),
    ],

    'notifications' => [
        'enabled' => env('WAFY_NOTIFICATIONS_ENABLED', false),
        'channels' => ['mail'], // any of: 'mail', 'slack', 'discord', 'teams'
        'email' => env('WAFY_NOTIFICATION_EMAIL', 'admin@example.com'),
        'slack_webhook' => env('WAFY_SLACK_WEBHOOK', ''),
        'discord_webhook' => env('WAFY_DISCORD_WEBHOOK', ''),
        'teams_webhook' => env('WAFY_TEAMS_WEBHOOK', ''),
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
    | Packs de règles fournis (dans resources/rules/*.php), fusionnés au ruleset
    | actif. Ex. ['owasp-crs'] pour le pack inspiré de l'OWASP CRS (scores
    | conservateurs). En cas de collision d'id, wafy.rules l'emporte.
    | imported_rules_path : fichier généré par `wafy:rules:import` (défaut :
    | storage/app/wafy/imported-rules.php), chargé automatiquement s'il existe.
    */
    'rule_packs' => array_filter(array_map('trim', explode(',', (string) env('WAFY_RULE_PACKS', '')))),
    'imported_rules_path' => env('WAFY_IMPORTED_RULES_PATH', null),

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

    // Ajoute un indice faible (score 1) quand la requête n'a AUCUN User-Agent.
    // Beaucoup de clients serveur-à-serveur légitimes n'en envoient pas : off par
    // défaut, et à 1 il ne bloque jamais seul (corrobore un autre signal).
    'flag_empty_user_agent' => (bool) env('WAFY_FLAG_EMPTY_USER_AGENT', false),

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

        // === Server-Side Template Injection (SSTI) ===
        // Sonde/gadget dans une expression {{ … }} (Twig/Jinja/Blade). Score moyen :
        // « {{7*7}} » collé dans un tuto ne bannit pas seul.
        // [^{}] (au lieu de [^}]) borne le scan à un seul niveau d'accolades :
        // évite un backtracking quadratique sur une entrée « {{{{… » (anti-ReDoS).
        ['id' => 'ssti.probe',           'score' => 3, 'pattern' => '/\{\{[^{}]{0,80}(7\s*\*\s*7|_self\b|__class__|__globals__|__mro__|__subclasses__|self\.env|\bcycler\b|\blipsum\b|request\.application|config\.items|getRuntime|\bsystem\s*\(|\bexec\s*\(|\bpopen\s*\(|subprocess)/i'],
        // Expression language / Freemarker RCE : ${T(java.lang.Runtime)…}, #{…}.
        ['id' => 'ssti.expr_lang',       'score' => 4, 'pattern' => '/(\$\{|#\{)[^}]{0,150}(T\s*\(|getRuntime|java\.lang|Runtime\.|ProcessBuilder|freemarker\.|\.execute\s*\(|new\s+Process|javax\.script)/i'],

        // === Log4Shell / JNDI ===
        ['id' => 'injection.jndi',       'score' => 5, 'pattern' => '/\$\{jndi:/i'],
        ['id' => 'injection.log4j',      'score' => 4, 'pattern' => '/\$\{(\$\{)?(::-|lower:|upper:)/i'],

        // === SSRF / cloud metadata ===
        ['id' => 'ssrf.metadata',        'score' => 4, 'pattern' => '/(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|\/latest\/meta-data\/|\/computeMetadata\/|fd00:ec2::254)/i'],
        ['id' => 'ssrf.scheme',          'score' => 3, 'pattern' => '/\b(gopher|dict|tftp):\/\//i'],

        // === NoSQL injection (opérateur en clé JSON ou en clé de tableau) ===
        ['id' => 'nosql.operator',       'score' => 4, 'pattern' => '/(\[\s*\$(ne|gt|lt|gte|lte|in|nin|or|and|where|regex|exists|elemMatch)\s*\]|["\']\$(ne|gt|lt|gte|lte|nin|where|regex|elemMatch|expr|function)["\']\s*:)/i'],

        // === XML External Entity (XXE) — entité externe / DTD SYSTEM ===
        ['id' => 'xxe.external',         'score' => 4, 'pattern' => '/(<!ENTITY\s+\S+\s+SYSTEM|<!ENTITY\s+%|<!DOCTYPE[^>]{0,200}SYSTEM)/i'],

        // === Désérialisation ===
        // Objet PHP sérialisé O:<n>:"Classe":<n>:{ — tolérant à l'échappement JSON des quotes.
        ['id' => 'deser.php',            'score' => 4, 'pattern' => '/O:\d+:[^:{}]{2,90}:\d+:\{/'],
        ['id' => 'deser.java',           'score' => 5, 'pattern' => '/rO0AB[A-Za-z0-9+\/]{6}/'],
        ['id' => 'deser.python',         'score' => 4, 'pattern' => '/(c__builtin__\s|cos\s+system|c__main__\s|cposix\s)/i'],

        // === LDAP injection (métacaractères de filtre) ===
        ['id' => 'ldap.injection',       'score' => 3, 'pattern' => '/(\)\s*\(\s*[|&!]|\*\s*\)\s*\(|\)\(uid=|\)\(cn=|\)\(objectclass=)/i'],

        // === Prototype pollution ===
        ['id' => 'proto.pollution',      'score' => 3, 'pattern' => '/(__proto__|constructor\]\s*\[|constructor\.prototype|\[["\']__proto__["\']\])/i'],

        // === CRLF / HTTP response splitting (signal faible) ===
        ['id' => 'crlf.header',          'score' => 2, 'pattern' => '/(\r\n|\n)\s*(set-cookie|location|refresh|link)\s*:/i'],

        // === Scanner & Exploit Signatures ===
        ['id' => 'scanner.sensitive',    'score' => 2, 'pattern' => '/(\/manager\/html|\/wp-admin|\/wp-content\/plugins|\/cgi-bin)/i'],
        ['id' => 'scanner.exploit_path', 'score' => 3, 'pattern' => '/(\/XMLPService|\/RPC2|\/igd\/v1\/get-users-data|\/convertCSVtoParquet\.php)/i'],
        ['id' => 'scanner.checkwaf',     'score' => 2, 'pattern' => '/(checkwaf=)/i'],

        // === Bot / Scanner User-Agents (User-Agent est déjà dans scan_headers) ===
        // Outils offensifs non ambigus : tokens distinctifs bornés par \b (pas des
        // mots anglais). « nuclei » ancré sur « nuclei/ » ou « projectdiscovery »
        // (nuclei = pluriel de nucleus) ; nmap sur « nmap scripting engine » ;
        // curl/python-requests/httpx/hydra VOLONTAIREMENT absents (double usage /
        // mots courants — couverts par la vélocité et les règles de charge).
        ['id' => 'bot.scanner_ua', 'score' => 5, 'fields' => ['User-Agent'], 'pattern' => '/(\bsqlmap\b|\bnikto\b|\bacunetix\b|\bnetsparker\b|\binvicti\b|\bnessus\b|\bopenvas\b|\barachni\b|\bw3af\b|\bskipfish\b|\bwpscan\b|\bjoomscan\b|\bdroopescan\b|\bwhatweb\b|\bwfuzz\b|\bffuf\b|\bdirbuster\b|\bgobuster\b|\bferoxbuster\b|\bdirsearch\b|\bmasscan\b|\bzgrab\b|\bfimap\b|\bhavij\b|\bjbrofuzz\b|nuclei\/|projectdiscovery|nmap scripting engine)/i'],
        // OPTIONNEL — clients HTTP génériques (double usage). Score 1 (indice seul,
        // ne bloque jamais). Décommentez et validez contre VOTRE trafic.
        // ['id' => 'bot.generic_http_client', 'score' => 1, 'pattern' => '/(\bpython-requests\/|\blibwww-perl\/|\bGo-http-client\/|\bWget\/|\bcurl\/)/i'],
    ],
];
