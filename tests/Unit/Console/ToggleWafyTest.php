<?php

namespace Bdsa\Wafy\Tests\Console;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Cache;

class ToggleWafyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->get('/test-toggle', function () {
            return 'Safe';
        });
    }

    /** @test */
    public function it_can_disable_waf_via_command()
    {
        // Par défaut, le WAF est activé (config default = true)

        // On exécute la commande pour désactiver
        $this->artisan('wafy:mode', ['status' => 'disable'])
            ->expectsOutput('WAF has been disabled.')
            ->assertExitCode(0);

        // On vérifie que le cache a bien été mis à jour
        $this->assertFalse(Cache::get('wafy.enabled'));

        // On vérifie que le middleware laisse passer une requête malveillante
        $response = $this->get('/test-toggle?q=UNION SELECT 1');
        $response->assertStatus(200); // 200 car désactivé
    }

    /** @test */
    public function it_can_enable_waf_via_command()
    {
        // On commence par désactiver
        Cache::put('wafy.enabled', false);

        // On exécute la commande pour activer
        $this->artisan('wafy:mode', ['status' => 'enable'])
            ->expectsOutput('WAF has been enabled.')
            ->assertExitCode(0);

        // On vérifie que le cache est à true
        $this->assertTrue(Cache::get('wafy.enabled'));

        // On vérifie que le middleware bloque une requête malveillante
        $response = $this->get('/test-toggle?q=UNION SELECT 1');
        $response->assertStatus(403);
    }
}