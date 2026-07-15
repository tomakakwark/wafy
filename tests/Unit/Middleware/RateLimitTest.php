<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;

class RateLimitTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush(); // fresh velocity counters per test

        Route::middleware(DetectMaliciousRequests::class)->get('/probe', fn () => 'OK');
        Route::middleware(DetectMaliciousRequests::class)->get('/missing', fn () => response('nope', 404));
    }

    /** @test */
    public function it_blocks_and_bans_after_a_404_storm()
    {
        config([
            'wafy.rate_limit.enabled' => true,
            'wafy.rate_limit.max_requests' => 0, // isolate the 404 counter
            'wafy.rate_limit.max_404' => 3,
        ]);

        // 4 probes to a missing path record 404s (max_404 = 3 -> breach once > 3).
        for ($i = 0; $i < 4; $i++) {
            $this->get('/missing')->assertStatus(404);
        }

        // The next request is blocked as a scan.
        $this->get('/missing')->assertStatus(403);

        $ban = \Bdsa\Wafy\Models\BannedIp::first();
        $this->assertNotNull($ban);
        $this->assertStringContainsString('Scan detected', $ban->reason);
    }

    /** @test */
    public function it_blocks_after_the_request_rate_limit()
    {
        config([
            'wafy.rate_limit.enabled' => true,
            'wafy.rate_limit.max_requests' => 3,
            'wafy.rate_limit.max_404' => 0,
        ]);

        // First 3 requests pass, the 4th trips the rate limit.
        $this->get('/probe')->assertStatus(200);
        $this->get('/probe')->assertStatus(200);
        $this->get('/probe')->assertStatus(200);
        $this->get('/probe')->assertStatus(403);
    }

    /** @test */
    public function it_does_not_rate_limit_when_disabled_by_default()
    {
        // rate_limit.enabled defaults to false -> no throttling whatsoever.
        for ($i = 0; $i < 10; $i++) {
            $this->get('/probe')->assertStatus(200);
        }
    }

    /** @test */
    public function it_skips_velocity_for_private_ips_to_avoid_proxy_self_dos()
    {
        // With ban_private_ips=false, the loopback client is "unbannable" and
        // velocity must be skipped (else a misconfigured proxy would self-DoS).
        config([
            'wafy.ban_private_ips' => false,
            'wafy.rate_limit.enabled' => true,
            'wafy.rate_limit.max_requests' => 2,
        ]);

        for ($i = 0; $i < 6; $i++) {
            $this->get('/probe')->assertStatus(200);
        }

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function log_mode_records_the_scan_but_does_not_block()
    {
        config([
            'wafy.action' => 'log',
            'wafy.rate_limit.enabled' => true,
            'wafy.rate_limit.max_requests' => 2,
        ]);

        // Even past the limit, log mode never blocks.
        for ($i = 0; $i < 5; $i++) {
            $this->get('/probe')->assertStatus(200);
        }

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }
}
