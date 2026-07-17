<?php

/*
 | Pack de règles inspiré de l'OWASP Core Rule Set (curé, exprimé au format
 | scoré de Wafy). Tous les scores sont conservateurs (2-3) : AUCUN n'atteint le
 | seuil par défaut (4) seul, donc chaque règle ne bloque qu'en CORROBORANT un
 | autre signal. Activez le pack via wafy.rule_packs => ['owasp-crs'].
 */

return [
    // LFI / fichiers système au-delà de passwd/shadow du cœur.
    ['id' => 'crs.930.os_files', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/(\/etc\/(hosts|group|issue|hostname|my\.cnf)|\/proc\/(version|cmdline|self\/(cmdline|environ)))\b/i'],

    // Évasion par $IFS (word-splitting shell). Ex. cat$IFS/etc/passwd.
    ['id' => 'crs.932.shell_ifs', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/\$\{?IFS\}?[\s\S]{0,40}?(cat|ls|id|sh|bash|wget|curl|nc)\b/i'],

    // Callables PHP à haut risque hors cœur. Ex. assert($_GET[c]).
    ['id' => 'crs.933.php_high_risk_fn', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/\b(assert|create_function|call_user_func(_array)?|proc_open|popen|phpinfo|pcntl_exec)\s*\(/i'],

    // Accès à une superglobale PHP injectée. Ex. ${$_REQUEST[a]}.
    ['id' => 'crs.933.php_superglobal', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/\$_(GET|POST|REQUEST|SERVER|COOKIE|SESSION|ENV|FILES)\s*\[/'],

    // Handlers d'événements XSS non énumérés par le cœur. Ex. <details ontoggle=…>.
    ['id' => 'crs.941.html_event_ext', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/<[a-z][^>]{0,200}?\s(ontoggle|onstart|onfocus|onpointer[a-z]+|onanimation[a-z]+|onbeforeinput)\s*=/i'],

    // Découpage de mot-clé SQL par commentaire inline. Ex. un/**/ion sel/**/ect.
    ['id' => 'crs.942.sql_inline_comment', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/\w\/\*(?!!)[^*]{0,40}\*\/\w/'],

    // UAs de scanners supplémentaires — limité au sujet User-Agent.
    ['id' => 'crs.913.scanner_ua_ext', 'score' => 3, 'severity' => 'medium', 'fields' => ['User-Agent'],
     'pattern' => '/\b(hakrawler|gospider|katana|httrack|zmeu|xmlrpc-scan|nuclei-templates)\b/i'],

    // CRLF / response-splitting via un paramètre de redirection (faible).
    ['id' => 'crs.921.http_splitting', 'score' => 2, 'severity' => 'low',
     'pattern' => '/(%0d%0a|%0a|%0d|\r\n)\s*(location|refresh|set-cookie|content-type)\s*:/i'],
];
