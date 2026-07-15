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
        // Publier les migrations et le fichier de configuration
        $this->publishes([
            __DIR__ . '/../database/migrations/create_banned_ips_table.php' => database_path('migrations/' . date('Y_m_d_His') . '_create_banned_ips_table.php'),
            __DIR__ . '/../database/migrations/add_offense_count_to_wafy_banned_ips_table.php' => database_path('migrations/' . date('Y_m_d_His', time() + 1) . '_add_offense_count_to_wafy_banned_ips_table.php'),
            __DIR__ . '/../config/wafy.php' => config_path('wafy.php'),
            __DIR__ . '/../lang' => function_exists('lang_path') ? lang_path('vendor/wafy') : resource_path('lang/vendor/wafy'),
        ]);

        // Charger les migrations
        //$this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        // Charger les traductions et les vues
        $this->loadTranslationsFrom(__DIR__ . '/../lang', 'wafy');
        $this->loadViewsFrom(__DIR__ . '/../resources/views', 'wafy');

        // Charger les middlewares
        $router = $this->app['router'];
        $router->aliasMiddleware('block.banned.ip', \Bdsa\Wafy\Middleware\BlockBannedIp::class);
        $router->aliasMiddleware('detect.malicious.requests', \Bdsa\Wafy\Middleware\DetectMaliciousRequests::class);

        // Charger les commandes artisan
        if ($this->app->runningInConsole()) {
            $this->commands([
                \Bdsa\Wafy\Console\BanIp::class ,
                \Bdsa\Wafy\Console\UnbanIp::class ,
                \Bdsa\Wafy\Console\ListBannedIps::class ,
                \Bdsa\Wafy\Console\ToggleWafy::class ,
                \Bdsa\Wafy\Console\SetAction::class ,
                \Bdsa\Wafy\Console\TestNotification::class ,
                \Bdsa\Wafy\Console\PruneBans::class ,
            ]);
        }
    }

    /**
     * Register services.
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/wafy.php', 'wafy');

        // GeoIP resolver: a user closure, a bound class name, or the best-effort
        // default (which degrades gracefully when no backend/DB is present).
        $this->app->singleton(\Bdsa\Wafy\Contracts\GeoIpResolver::class, function () {
            $resolver = config('wafy.geoip.resolver');

            if ($resolver instanceof \Closure) {
                return new \Bdsa\Wafy\GeoIp\ClosureGeoIpResolver($resolver);
            }
            if (is_string($resolver) && $resolver !== '') {
                return app($resolver);
            }

            return new \Bdsa\Wafy\GeoIp\DefaultGeoIpResolver();
        });
    }
}