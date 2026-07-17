<?php

namespace Bdsa\Wafy\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use Bdsa\Wafy\WafyServiceProvider;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app)
    {
        return [
            WafyServiceProvider::class ,
        ];
    }

    public function getEnvironmentSetUp($app)
    {
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        // Le seuil de PRODUCTION est désormais 3 ; la plupart des tests historiques
        // valident la mécanique de ban sur une seule requête, on force donc 1 ici.
        // Les tests s'exécutent depuis 127.0.0.1 (loopback), une IP « unbannable »
        // par défaut — on autorise son ban dans l'environnement de test.
        $app['config']->set('wafy.ban_threshold', 1);
        $app['config']->set('wafy.ban_private_ips', true);

        // Exécuter les migrations du package
        $migration = include __DIR__ . '/../database/migrations/create_banned_ips_table.php';
        $migration->up();

        $events = include __DIR__ . '/../database/migrations/create_wafy_events_table.php';
        $events->up();
    }
}