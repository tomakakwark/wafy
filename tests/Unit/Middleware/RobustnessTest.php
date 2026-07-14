<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Middleware\BlockBannedIp;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;

class RobustnessTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
        Route::middleware(BlockBannedIp::class)->get('/block', fn () => 'OK');
    }

    /** @test */
    public function it_still_detects_a_payload_padded_past_the_scan_window()
    {
        config(['wafy.max_scan_length' => 2000]);

        // 2100 chars of junk push the real payload beyond the truncation cut;
        // the head+tail scan must still catch it.
        $payload = str_repeat('A', 2100) . ' UNION SELECT 1,2,3';

        $this->get('/waf?q=' . urlencode($payload))->assertStatus(403);
    }

    /** @test */
    public function it_bans_an_ipv6_address_by_its_prefix_and_blocks_the_whole_network()
    {
        config(['wafy.ipv6_ban_prefix' => 64]);

        // Malicious request from one address of a /64.
        $this->call('GET', '/waf?q=' . urlencode('UNION SELECT 1'), [], [], [], ['REMOTE_ADDR' => '2001:db8:1:2::1'])
            ->assertStatus(403);

        // Stored as the /64 network, not the single address.
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '2001:db8:1:2::/64']);

        // A DIFFERENT address in the SAME /64 is now blocked, even when clean.
        $this->call('GET', '/waf', [], [], [], ['REMOTE_ADDR' => '2001:db8:1:2:ffff::abcd'])
            ->assertStatus(403);

        // An address in a DIFFERENT /64 is unaffected.
        $this->call('GET', '/waf?q=hello', [], [], [], ['REMOTE_ADDR' => '2001:db8:1:3::1'])
            ->assertStatus(200);
    }

    /** @test */
    public function it_bans_the_exact_ipv6_address_when_prefix_is_128()
    {
        config(['wafy.ipv6_ban_prefix' => 128]);

        $this->call('GET', '/waf?q=' . urlencode('UNION SELECT 1'), [], [], [], ['REMOTE_ADDR' => '2001:db8:1:2::1'])
            ->assertStatus(403);

        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '2001:db8:1:2::1']);
    }

    /** @test */
    public function it_caches_clean_lookups_when_enabled()
    {
        config(['wafy.ban_lookup_cache_ttl' => 30]);

        $this->get('/waf?q=hello')->assertStatus(200);

        $this->assertTrue((bool) Cache::get('wafy:clean:127.0.0.1'));
    }

    /** @test */
    public function it_does_not_cache_lookups_when_disabled_by_default()
    {
        $this->get('/waf?q=hello')->assertStatus(200);

        $this->assertNull(Cache::get('wafy:clean:127.0.0.1'));
    }

    /** @test */
    public function it_invalidates_the_clean_cache_when_an_ip_is_banned()
    {
        config(['wafy.ban_lookup_cache_ttl' => 30]);

        // Prime the clean cache.
        $this->get('/waf?q=hello')->assertStatus(200);
        $this->assertTrue((bool) Cache::get('wafy:clean:127.0.0.1'));

        // A malicious request bans and must drop the stale "clean" marker.
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);

        $this->assertNull(Cache::get('wafy:clean:127.0.0.1'));
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }
}
