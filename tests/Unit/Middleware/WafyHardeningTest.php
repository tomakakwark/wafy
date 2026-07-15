<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Middleware\BlockBannedIp;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Schema;

class WafyHardeningTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/waf-detect', fn () => 'Safe');
        Route::middleware(BlockBannedIp::class)->get('/waf-block', fn () => 'OK');
    }

    /** @test */
    public function automatic_bans_are_temporary_by_default()
    {
        $this->get('/waf-detect?q=UNION SELECT 1,2,3')->assertStatus(403);

        $ban = BannedIp::first();
        $this->assertNotNull($ban);
        $this->assertNotNull($ban->banned_until, 'Automatic bans should be temporary by default.');
    }

    /** @test */
    public function it_requires_multiple_strikes_before_banning_when_threshold_is_raised()
    {
        Config::set('wafy.ban_threshold', 2);

        // First malicious request: blocked but NOT yet banned.
        $this->get('/waf-detect?q=UNION SELECT 1')->assertStatus(403);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);

        // Second malicious request: threshold reached -> banned.
        $this->get('/waf-detect?q=UNION SELECT 1')->assertStatus(403);
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_redacts_sensitive_input_before_storing()
    {
        $this->postJson('/waf-detect', [
            'password' => 'super-secret',
            'comment' => '<script>alert(1)</script>',
        ])->assertStatus(403);

        $ban = BannedIp::first();
        $this->assertSame('[REDACTED]', $ban->request_data['input']['password']);
        $this->assertSame('<script>alert(1)</script>', $ban->request_data['input']['comment']);
    }

    /** @test */
    public function it_redacts_sensitive_keys_by_substring_match()
    {
        $this->postJson('/waf-detect', [
            'user_password' => 'super-secret',
            'billing_card_number' => '4111111111111111',
            'business' => 'ACME Corp',
            'comment' => '<script>alert(1)</script>',
        ])->assertStatus(403);

        $input = BannedIp::first()->request_data['input'];
        $this->assertSame('[REDACTED]', $input['user_password']);
        $this->assertSame('[REDACTED]', $input['billing_card_number']);
        // Not sensitive -> kept (guards against over-broad terms like "sin").
        $this->assertSame('ACME Corp', $input['business']);
    }

    /** @test */
    public function it_truncates_oversized_stored_input()
    {
        Config::set('wafy.max_stored_value_length', 100);

        $this->postJson('/waf-detect', [
            'blob' => str_repeat('x', 5000),
            'comment' => '<script>alert(1)</script>',
        ])->assertStatus(403);

        $blob = BannedIp::first()->request_data['input']['blob'];
        $this->assertLessThan(200, strlen($blob));
        $this->assertStringContainsString('truncated', $blob);
    }

    /** @test */
    public function it_allows_ips_matching_a_cidr_range()
    {
        Config::set('wafy.allowed_ips', ['127.0.0.0/24']);

        $this->get('/waf-detect?q=UNION SELECT 1')->assertStatus(200);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_fails_open_when_the_ban_store_is_unavailable()
    {
        Schema::dropIfExists('wafy_banned_ips');

        // Default fail_open = true -> request is allowed through.
        $this->get('/waf-block')->assertStatus(200);
    }

    /** @test */
    public function it_can_fail_closed_when_configured()
    {
        Config::set('wafy.fail_open', false);
        Schema::dropIfExists('wafy_banned_ips');

        $this->get('/waf-block')->assertStatus(503);
    }
}
