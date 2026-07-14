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
    public function it_detects_hex_literals_in_sql_context()
    {
        // "0x…" accolé à un mot-clé SQL reste détecté
        $this->get('/test-waf?q=SELECT 0x2727')->assertStatus(403);

        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_allows_isolated_hex_like_crypto_wallets()
    {
        // Adresse Ethereum / ID hexadécimal isolé : plus de faux positif (ex-règle 0x trop large)
        $this->postJson('/test-waf', ['wallet' => '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'])
            ->assertStatus(200)
            ->assertSee('Safe');

        $this->get('/test-waf?id=0x1a2b3c')->assertStatus(200);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
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

    /**
     * Contre-exemples bénins : ces contenus parfaitement légitimes déclenchaient
     * un ban avec l'ancien jeu de règles. Ils verrouillent les correctifs de
     * faux positifs de l'audit.
     *
     * @test
     * @dataProvider benignInputs
     */
    public function it_allows_legitimate_content_that_previously_false_positived(array $payload)
    {
        $this->postJson('/test-waf', $payload)
            ->assertStatus(200)
            ->assertSee('Safe');

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    public static function benignInputs(): array
    {
        return [
            'prose SQL keywords'   => [['comment' => 'Please select an item from our catalog']],
            'delete from prose'    => [['comment' => 'You can delete from your cart at any time']],
            'email signature dash' => [['message' => "Best regards\n-- \nJohn Doe"]],
            'CSS block comment'    => [['content' => '/* header */ .box { color: red }']],
            'javascript book'      => [['title'   => 'JavaScript: The Good Parts']],
            'inline png data uri'  => [['avatar'  => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=']],
            'dot-env in prose'     => [['comment' => 'See section 3.Environment for details']],
            'ampersand prose'      => [['comment' => 'We sell black & cat food and dog food']],
        ];
    }

    /** @test */
    public function it_blocks_but_does_not_ban_private_ips_by_default()
    {
        // Simule TrustProxies mal configuré : $request->ip() = loopback/privée.
        config(['wafy.ban_private_ips' => false]);

        $this->get('/test-waf?q=UNION SELECT 1,2,3')->assertStatus(403);

        // La requête est bloquée mais l'IP (proxy présumé) n'est PAS bannie (anti self-DoS).
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_scans_newly_configured_headers()
    {
        // X-Forwarded-For n'était pas inspecté avant : un payload SQLi qui y est
        // placé passait sans contrôle. Il doit désormais être bloqué.
        $this->get('/test-waf', ['X-Forwarded-For' => "1' UNION SELECT pw FROM users--"])
            ->assertStatus(403);
    }

    /** @test */
    public function it_redacts_sensitive_query_params_in_the_stored_url()
    {
        $this->get('/test-waf?token=SECRET123&q=UNION SELECT 1,2,3')->assertStatus(403);

        $ban = BannedIp::first();
        $this->assertNotNull($ban);
        $this->assertStringNotContainsString('SECRET123', $ban->request_data['url']);
        $this->assertStringContainsString('REDACTED', $ban->request_data['url']);
    }
}