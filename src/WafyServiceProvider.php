<?php

namespace Bdsa\Wafy;

use Illuminate\Support\ServiceProvider;

class WafyServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     */
    public function boot()
    {
        // Publier la migration et le fichier de configuration
        $this->publishes([
            __DIR__.'/../database/migrations/create_banned_ips_table.php' => database_path('migrations/'.date('Y_m_d_His').'_create_banned_ips_table.php'),
            __DIR__.'/../config/wafy.php' => config_path('wafy.php'),
        ]);

        // Charger les migrations
        //$this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // Charger les middlewares
        $router = $this->app['router'];
        $router->aliasMiddleware('block.banned.ip', \Bdsa\Wafy\Middleware\BlockBannedIp::class);
        $router->aliasMiddleware('detect.malicious.requests', \Bdsa\Wafy\Middleware\DetectMaliciousRequests::class);

        // Charger les commandes artisan
        if ($this->app->runningInConsole()) {
            $this->commands([
                \Bdsa\Wafy\Console\BanIp::class,
                \Bdsa\Wafy\Console\UnbanIp::class,
            ]);
        }
    }

    /**
     * Register services.
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/wafy.php', 'wafy');
    }
}
