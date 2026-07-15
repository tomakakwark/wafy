<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Middleware\BlockBannedIp;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Support\Facades\Route;

class MessagesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/detect', fn () => 'Safe');
        Route::middleware(BlockBannedIp::class)->get('/block', fn () => 'OK');
    }

    /** @test */
    public function it_uses_the_default_french_messages()
    {
        $this->get('/detect?q=' . urlencode('UNION SELECT 1'))
            ->assertStatus(403)
            ->assertJson(['message' => 'Votre IP est bannie.']);
    }

    /** @test */
    public function it_honours_a_custom_message_and_status_code()
    {
        config([
            'wafy.messages.banned' => 'Access denied.',
            'wafy.status_codes.banned' => 418,
        ]);

        $this->get('/detect?q=' . urlencode('UNION SELECT 1'))
            ->assertStatus(418)
            ->assertJson(['message' => 'Access denied.']);
    }

    /** @test */
    public function it_translates_a_message_key_that_has_a_lang_line()
    {
        config(['wafy.messages.banned' => 'wafy::messages.banned']);
        app()->setLocale('en');

        $this->get('/detect?q=' . urlencode('UNION SELECT 1'))
            ->assertStatus(403)
            ->assertJson(['message' => 'Your IP is banned.']);
    }

    /** @test */
    public function block_banned_ip_uses_the_configured_permanent_message()
    {
        config(['wafy.messages.banned_permanent' => 'Banned for good.']);
        BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => null]);

        $this->get('/block')
            ->assertStatus(403)
            ->assertJson(['message' => 'Banned for good.']);
    }
}
