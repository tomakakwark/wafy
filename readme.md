# Wafy - Gestion des IP Bannies et Détection des Requêtes Malveillantes

**Wafy** est un package Laravel développé par **bdsa** pour bannir automatiquement les adresses IP et détecter les requêtes malveillantes telles que les tentatives d'injection SQL.

### Résumé

Ce fichier **README.md** explique les étapes pour installer, configurer et utiliser le package **wafy** dans un projet Laravel. Il inclut des instructions pour :

- Ajouter le package via Composer.
- Publier la configuration et la migration.
- Appliquer la migration.
- Utiliser les middlewares et les commandes artisan.
- Configurer les patterns de détection des requêtes malveillantes.

## Installation

### 1. Ajouter le package à votre projet

Dans le fichier `composer.json` de votre projet Laravel, ajoutez ce package comme un dépôt local :

```json
"repositories": [
    {
        "type": "vcs",
        "url": "https://github.com/tomakakwark/wafy"
    }
],
```

```json
"require": {
    "bdsa/wafy": "dev-main"
}
```

```bash
composer update
```

```bash
php artisan vendor:publish --provider="Bdsa\Wafy\WafyServiceProvider"
```

```bash
php artisan migrate
```

### Middlewares

Le package fournit deux middlewares principaux :

BlockBannedIp : Bloque l'accès des IP bannies à l'application.
DetectMaliciousRequests : Détecte les requêtes malveillantes (comme les tentatives d'injection SQL) et bannit automatiquement les adresses IP correspondantes.
Pour les utiliser, ajoutez-les dans le fichier app/Http/Kernel.php de votre projet Laravel, dans la section $middleware ou $routeMiddleware :

```php
protected $middleware = [
    \Bdsa\Wafy\Middleware\BlockBannedIp::class,
    \Bdsa\Wafy\Middleware\DetectMaliciousRequests::class,
];
```

### Commands Artisan

Le package fournit également deux commands artisan pour gérer les IP bannies :

```bash
php artisan waf:ban {adresse_ip}
```

```bash
php artisan waf:unban {adresse_ip}
```


### Exemple de configuration :
```php
return [
    'patterns' => [
        '/(select\s.*from|union\s.*select|information_schema|concat|0x)/i',
        '/(\*.*from|where.*=.*\d)/i',
    ],
];
```



### Exemple d'intégration dans les routes
Voici un exemple d'intégration des middlewares dans un groupe de routes :

```php
Route::group(['middleware' => ['block.banned.ip', 'detect.malicious.requests']], function () {
    Route::get('/', function () {
        return view('welcome');
    });

    // Autres routes ici
});
```
