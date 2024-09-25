<?php

return [
    'patterns' => [
        '/(select\s.*from|union\s.*select|information_schema|concat|0x)/i',
        '/(\*.*from|where.*=.*\d)/i',
    ],
];
