# Wafy - Laravel Firewall & Malicious Request Detector

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![PHP](https://img.shields.io/badge/php-%3E%3D7.4-8892BF.svg)
![Laravel](https://img.shields.io/badge/laravel-%5E8.0%7C%5E9.0%7C%5E10.0%7C%5E11.0%7C%5E12.0-FF2D20.svg)

**Wafy** is a robust Laravel package developed by **Bdsa** designed to automatically ban IP addresses and detect malicious requests, including SQL Injection, XSS, and more.

## Features

- 🛡️ **IP Banning**: Automatically block IPs engaging in suspicious activity.
- 🕵️ **Malicious Request Detection**: Detects SQLi, XSS, LFI, and RCE attempts.
- ⏱️ **Temporary & Permanent Bans**: Configurable ban durations.
- ⚙️ **Customizable Patterns**: Define your own regex patterns for detection.
- 🖥️ **Artisan Commands**: Easily manage banned IPs via CLI.

---

## Installation

### 1. Require with Composer

Add the package to your project:

```bash
composer require bdsa/wafy
```

### 2. Publish Configuration

Publish the configuration file and migrations:

```bash
php artisan vendor:publish --provider="Bdsa\Wafy\WafyServiceProvider"
```

### 3. Run Migrations

Create the `banned_ips` table:

```bash
php artisan migrate
```

---

## Usage

### Middleware

Wafy provides two key middlewares : BlockBannedIp & DetectMaliciousRequests.

#### Protecting Routes

Apply the middleware to your routes or groups:

```php

use Bdsa\Wafy\Middleware\BlockBannedIp;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;

Route::group(['middleware' => ['block.banned.ip', 'detect.malicious.requests']], function () {
    Route::get('/', function () {
        return view('welcome');
    });
    
    // Your protected routes
});
```

### Artisan Commands

Manage banned IPs directly from the terminal:

- **Ban an IP manually:**
  ```bash
  php artisan wafy:ban {ip_address} [--reason="Your reason"]
  ```

- **Unban an IP:**
  ```bash
  php artisan wafy:unban {ip_address}
  ```

- **List all banned IPs:**
  ```bash
  php artisan wafy:list
  ```

- **Enable/Disable WAF:**
  ```bash
  php artisan wafy:mode {enable|disable}
  ```

- **Set Action Mode (Block or Log-Only):**
  ```bash
  php artisan wafy:action {block|log}
  ```

---

## Configuration

The configuration file is located at `config/wafy.php`. You can customize the detection patterns here.

Default protection covers:
- **SQL Injection (SQLi)**: `UNION SELECT`, common SQL verbs, hex encoding.
- **Local File Inclusion (LFI)**: Directory traversal (`../`), system files (`/etc/passwd`).
- **Cross-Site Scripting (XSS)**: Script tags, event handlers (`onload`, `onerror`).
- **Remote Code Execution (RCE)**: Shell commands (`cat`, `wget`), PHP execution functions.

Example `config/wafy.php`:

```php
return [
    'enabled' => env('WAFY_ENABLED', true),
    'patterns' => [
        '/(union(\s+all)?\s+select)/i',
        '/(select\s+.*\s+from|delete\s+from|update\s+.*\s+set)/i',
        '/(<script.*?>.*?<\/script>)/is',
        // Add your custom patterns here
    ],
    'allowed_ips' => [
        '127.0.0.1', // Localhost
        '192.168.1.1', // Office IP
    ],
    'notifications' => [
        'enabled' => env('WAFY_NOTIFICATIONS_ENABLED', false),
        'channels' => ['mail'], // Choose 'mail', 'slack' or both
        'email' => env('WAFY_NOTIFICATION_EMAIL', 'admin@example.com'),
        'slack_webhook' => env('WAFY_SLACK_WEBHOOK', ''),
    ],
];
```

---

## Testing

To run the package tests:

```bash
vendor/bin/phpunit
```

---

## License

This project is licensed under the [MIT License](LICENSE).
