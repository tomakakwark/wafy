<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Illuminate\Support\Facades\Route;

class HoneypotTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('{any}', fn () => 'Safe')->where('any', '.*');
    }

    /** @test */
    public function it_traps_a_configured_honeypot_path()
    {
        $this->get('/wp-login.php')->assertStatus(403);
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_traps_case_insensitively_and_via_glob()
    {
        config(['wafy.honeypot_paths' => ['/wp-login.php', '/phpmyadmin/*']]);

        $this->get('/WP-Login.php')->assertStatus(403);      // case-insensitive
        $this->get('/phpmyadmin/index.php')->assertStatus(403); // glob
    }

    /** @test */
    public function it_does_not_trap_legitimate_paths()
    {
        $this->get('/api/users')->assertStatus(200)->assertSee('Safe');
        $this->get('/login')->assertStatus(200);
        $this->get('/admin/dashboard')->assertStatus(200); // no /admin/* glob by default
        $this->get('/phpmyadmin-tutorial')->assertStatus(200);
    }

    /** @test */
    public function it_can_block_without_banning_when_honeypot_ban_is_false()
    {
        config(['wafy.honeypot_ban' => false]);

        $this->get('/xmlrpc.php')->assertStatus(403);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_respects_log_mode()
    {
        config(['wafy.action' => 'log']);

        $this->get('/wp-login.php')->assertStatus(200)->assertSee('Safe');
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }
}
