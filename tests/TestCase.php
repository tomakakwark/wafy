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

        // Exécuter les migrations du package
        $migration = include __DIR__ . '/../database/migrations/create_banned_ips_table.php';
        $migration->up();
    }
}