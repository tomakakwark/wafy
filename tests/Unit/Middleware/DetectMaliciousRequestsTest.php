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
            'reason' => 'Malicious pattern detected: /(union(\s+all)?\s+select)/i'
        ]);
    }

    /** @test */
    public function it_detects_xss_in_body()
    {
        $response = $this->postJson('/test-waf', ['comment' => '<script>alert(1)</script>']);
        $response->assertStatus(403);

        $this->assertDatabaseHas('wafy_banned_ips', [
            'ip_address' => '127.0.0.1',
            'reason' => 'Malicious pattern detected: /(<script.*?>.*?<\/script>)/is'
        ]);
    }

    /** @test */
    public function it_detects_lfi_attempts()
    {
        $response = $this->get('/test-waf?file=../../etc/passwd');
        $response->assertStatus(403);
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