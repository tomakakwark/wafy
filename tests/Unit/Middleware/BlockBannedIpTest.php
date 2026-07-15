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
    public function it_does_not_block_a_banned_ip_in_log_mode()
    {
        // Mode log : on trace mais on ne bloque pas, même une IP déjà bannie.
        config(['wafy.action' => 'log']);
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => null]);

        $this->get('/test-route')
            ->assertStatus(200)
            ->assertSee('OK');
    }

    /** @test */
    public function an_expired_ban_lets_the_request_through()
    {
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => now()->subMinutes(1)]);

        $this->get('/test-route')->assertStatus(200)->assertSee('OK');
    }

    /** @test */
    public function an_expired_ban_row_is_kept_when_backoff_is_enabled()
    {
        // Défaut backoff -> la ligne survit à l'expiration (pour l'escalade).
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => now()->subMinutes(1), 'offense_count' => 1]);

        $this->get('/test-route')->assertStatus(200);

        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function an_expired_ban_row_is_deleted_when_backoff_is_disabled()
    {
        config(['wafy.backoff_enabled' => false]);
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => now()->subMinutes(1)]);

        $this->get('/test-route')->assertStatus(200);

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }
}