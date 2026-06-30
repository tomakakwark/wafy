<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Support\Facades\Route;

class DetectMaliciousRequestsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/test-waf', function () {
            return 'Safe';
        });
    }

    /** @test */
    public function it_allows_safe_requests()
    {
        $response = $this->get('/test-waf?q=hello');
        $response->assertStatus(200);
    }

    /** @test */
    public function it_detects_sqli_in_query_string()
    {
        $response = $this->get('/test-waf?q=UNION SELECT 1,2,3');
        $response->assertStatus(403);

        $this->assertDatabaseHas('wafy_banned_ips', [
            'ip_address' => '127.0.0.1',
            'reason' => 'Malicious pattern detected in QueryString: /(union(\s+all)?\s+select)/i'
        ]);
    }

    /** @test */
    public function it_detects_xss_in_body()
    {
        $response = $this->postJson('/test-waf', ['comment' => '<script>alert(1)</script>']);
        $response->assertStatus(403);

        $this->assertDatabaseHas('wafy_banned_ips', [
            'ip_address' => '127.0.0.1',
            'reason' => 'Malicious pattern detected in RequestBody: /(<script.*?>.*?<\/script>)/is'
        ]);
    }

    /** @test */
    public function it_detects_lfi_attempts()
    {
        $response = $this->get('/test-waf?file=../../etc/passwd');
        $response->assertStatus(403);
    }

    /** @test */
    public function it_allows_legitimate_payloads_containing_0x()
    {
        // "0x" embedded inside a longer string
        $response = $this->postJson('/test-waf', ['token' => 'a1b2c3d4e5f6g7h80x9i0j1k2l3m4n5']);
        $response->assertStatus(200);
        $response->assertSee('Safe');

        // "0x" used at start of string but without word boundaries
        $response = $this->postJson('/test-waf', ['id' => '0xdeadbeef_legit']);
        $response->assertStatus(200);
        $response->assertSee('Safe');
    }

    /** @test */
    public function it_detects_sqli_hex_payload()
    {
        // Using "0x" exactly like in SQLi (with word boundaries)
        $response = $this->get('/test-waf?q=SELECT 0x2727');
        $response->assertStatus(403);

        $this->assertDatabaseHas('wafy_banned_ips', [
            'ip_address' => '127.0.0.1',
            'reason' => 'Malicious pattern detected in QueryString: /\b(0x[0-9a-f]{2,})\b/i'
        ]);

        // Ensure another typical injection variant works (id=0x... parameter binding)
        $response2 = $this->get('/test-waf?id=0x1a2b3c');
        $response2->assertStatus(403);
    }

    /** @test */
    public function it_does_not_block_requests_in_log_mode()
    {
        // Set mode to 'log'
        \Illuminate\Support\Facades\Cache::put('wafy.action', 'log');

        // Send malicious request
        $response = $this->get('/test-waf?q=UNION SELECT 1,2,3');

        // Should be allowed
        $response->assertStatus(200);
        $response->assertSee('Safe');

        // Should NOT be banned in DB
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_sends_notification_when_ip_is_banned()
    {
        // Enable notifications
        config([
            'wafy.notifications.enabled' => true,
            'wafy.notifications.channels' => ['mail', 'slack'],
            'wafy.notifications.email' => 'admin@test.com',
            'wafy.notifications.slack_webhook' => 'https://hooks.slack.com/test'
        ]);

        \Illuminate\Support\Facades\Notification::fake();

        // Send malicious request (Block mode by default)
        $this->postJson('/test-waf', ['comment' => '<script>alert(1)</script>'])
            ->assertStatus(403);

        // Assert Notification Sent
        \Illuminate\Support\Facades\Notification::assertSentTo(
            BannedIp::first(),
            \Bdsa\Wafy\Notifications\IpBannedNotification::class
        );

        // Assert DB has ban
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }
}