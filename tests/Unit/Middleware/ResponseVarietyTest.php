<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Illuminate\Support\Facades\Route;

class ResponseVarietyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
    }

    private function attack(array $headers = [])
    {
        return $this->get('/waf?q=' . urlencode('UNION SELECT 1'), $headers);
    }

    /** @test */
    public function json_is_the_default_response()
    {
        $this->attack()
            ->assertStatus(403)
            ->assertHeader('content-type', 'application/json')
            ->assertJson(['message' => 'Votre IP est bannie.']);
    }

    /** @test */
    public function view_mode_renders_the_html_challenge_page()
    {
        config(['wafy.response.mode' => 'view']);

        $response = $this->attack();
        $response->assertStatus(403);
        $this->assertStringContainsString('text/html', (string) $response->headers->get('content-type'));
        $response->assertSee('Protected by Wafy', false);
        $response->assertSee('Votre IP est bannie.', false);
    }

    /** @test */
    public function auto_mode_negotiates_json_for_api_and_html_for_browsers()
    {
        config(['wafy.response.mode' => 'auto']);

        // API client (Accept: application/json) -> JSON.
        $this->getJson('/waf?q=' . urlencode('UNION SELECT 1'))
            ->assertStatus(403)
            ->assertJson(['message' => 'Votre IP est bannie.']);

        // Browser (Accept: text/html) -> HTML view.
        $html = $this->get('/waf?q=' . urlencode('UNION SELECT 1'), ['Accept' => 'text/html']);
        $this->assertStringContainsString('text/html', (string) $html->headers->get('content-type'));
        $html->assertSee('Protected by Wafy', false);
    }

    /** @test */
    public function a_missing_view_degrades_to_json_instead_of_500()
    {
        config(['wafy.response.mode' => 'view', 'wafy.response.view' => 'wafy::does-not-exist']);

        $this->attack()
            ->assertStatus(403)
            ->assertJson(['message' => 'Votre IP est bannie.']);
    }

    /** @test */
    public function the_tarpit_delays_a_block_when_configured()
    {
        config(['wafy.response.tarpit_seconds' => 1, 'wafy.response.tarpit_max' => 5]);

        $start = microtime(true);
        $this->attack()->assertStatus(403);
        $this->assertGreaterThanOrEqual(0.9, microtime(true) - $start);
    }

    /** @test */
    public function the_tarpit_never_applies_to_an_already_banned_ip()
    {
        // A banned IP must get the cheapest 403 (no tarpit) so it can't pin workers.
        config(['wafy.response.tarpit_seconds' => 3]);
        \Bdsa\Wafy\Models\BannedIp::create(['ip_address' => '127.0.0.1', 'banned_until' => now()->addDay()]);

        $start = microtime(true);
        $this->get('/waf?q=hello')->assertStatus(403); // early-ban-exit, no tarpit
        $this->assertLessThan(1.5, microtime(true) - $start);
    }
}
