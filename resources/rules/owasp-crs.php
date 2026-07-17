<?php

/*
 | Pack de règles inspiré de l'OWASP Core Rule Set (curé, format scoré de Wafy).
 | Scores TRÈS conservateurs (1-2) : ces règles corroborent d'autres signaux et
 | ne bloquent jamais seules, ni même à deux, sur du contenu de corps légitime
 | (extraits de code, prose, tutoriels). Activez via wafy.rule_packs=>['owasp-crs'].
 */

return [
    // LFI / fichiers système au-delà de passwd/shadow. Score 2 (prose « /etc/hosts »
    // reste sous le seuil et ne peut pas se combiner à un autre indice de prose).
    ['id' => 'crs.930.os_files', 'score' => 2, 'severity' => 'low',
     'pattern' => '/(\/etc\/(hosts|group|issue|hostname|my\.cnf)|\/proc\/(version|cmdline|self\/(cmdline|environ)))\b/i'],

    // Évasion par $IFS : commande ADJACENTE à $IFS (pas de prose entre les deux),
    // ex. cat$IFS/etc/passwd, $IFS$9wget. Ne matche pas « reset $IFS then run ls ».
    ['id' => 'crs.932.shell_ifs', 'score' => 2, 'severity' => 'low',
     'pattern' => '/\$\{?IFS\}?[${}0-9@*+-]{0,6}(cat|ls|id|sh|bash|zsh|wget|curl|nc|whoami|uname)\b/i'],

    // Callables PHP à haut risque hors cœur. Score 2 (un extrait de code contenant
    // assert( ne bloque pas seul ; combiné à une superglobale = 3, sous le seuil).
    ['id' => 'crs.933.php_high_risk_fn', 'score' => 2, 'severity' => 'low',
     'pattern' => '/\b(assert|create_function|call_user_func(_array)?|proc_open|popen|phpinfo|pcntl_exec)\s*\(/i'],

    // Accès à une superglobale PHP. Score 1 (indice faible : présent dans tout
    // extrait de code PHP légitime uploadé/collé).
    ['id' => 'crs.933.php_superglobal', 'score' => 1, 'severity' => 'info',
     'pattern' => '/\$_(GET|POST|REQUEST|SERVER|COOKIE|SESSION|ENV|FILES)\s*\[/'],

    // Handlers d'événements XSS non énumérés par le cœur — DANS une balise (faible FP).
    ['id' => 'crs.941.html_event_ext', 'score' => 3, 'severity' => 'medium',
     'pattern' => '/<[a-z][^>]{0,200}?\s(ontoggle|onstart|onfocus|onpointer[a-z]+|onanimation[a-z]+|onbeforeinput)\s*=/i'],

    // Découpage de mot-clé SQL par commentaire inline. Score 2 (un commentaire
    // inline de code « 1/*x*/y » ne bloque pas seul).
    ['id' => 'crs.942.sql_inline_comment', 'score' => 2, 'severity' => 'low',
     'pattern' => '/\w\/\*(?!!)[^*]{0,40}\*\/\w/'],

    // UAs de scanners supplémentaires — limité au sujet User-Agent (pas le corps).
    ['id' => 'crs.913.scanner_ua_ext', 'score' => 3, 'severity' => 'medium', 'fields' => ['User-Agent'],
     'pattern' => '/\b(hakrawler|gospider|katana|httrack|zmeu|xmlrpc-scan|nuclei-templates)\b/i'],

    // (crs.921 http-splitting retiré : redondant avec la règle cœur crlf.header.)
];
