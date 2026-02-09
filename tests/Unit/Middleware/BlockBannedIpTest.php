<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\BlockBannedIp;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

class BlockBannedIpTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(BlockBannedIp::class)->get('/test-route', function () {
            return 'OK';
        });
    }

    /** @test */
    public function it_allows_access_to_non_banned_ips()
    {
        $response = $this->get('/test-route');
        $response->assertStatus(200);
        $response->assertSee('OK');
    }

    /** @test */
    public function it_blocks_permanently_banned_ips()
    {
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => null]);

        $response = $this->get('/test-route');
        $response->assertStatus(403);
        $response->assertJson(['message' => 'Votre IP est bannie définitivement.']);
    }

    /** @test */
    public function it_blocks_temporarily_banned_ips()
    {
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => now()->addMinutes(10)]);

        $response = $this->get('/test-route');
        $response->assertStatus(403);
        $response->assertJson(['message' => 'Votre IP est temporairement bannie.']);
    }

    /** @test */
    public function it_unbans_expired_ips()
    {
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => now()->subMinutes(1)]);

        $response = $this->get('/test-route');

        // La première requête déclenche le nettoyage mais peut encore retourner 403 si le middleware ne laisse pas passer immédiatement (dépend de l'implémentation exact).
        // Dans notre implémentation refactorée : "Si ... expiré... $bannedIp->delete(); return $next($request);"
        // Donc ça devrait passer tout de suite.

        $response->assertStatus(200);
        $response->assertSee('OK');

        $this->assertDatabaseMissing('banned_ips', ['ip_address' => '127.0.0.1']);
    }
}