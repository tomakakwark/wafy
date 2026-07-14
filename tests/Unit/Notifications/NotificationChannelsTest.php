<?php

namespace Bdsa\Wafy\Tests\Unit\Notifications;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

class NotificationChannelsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Notifications synchrones pour capturer les webhooks pendant la requête.
        config(['queue.default' => 'sync']);

        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
    }

    /** @test */
    public function it_delivers_discord_and_teams_webhooks_on_ban()
    {
        Http::fake();
        config([
            'wafy.notifications.enabled' => true,
            'wafy.notifications.channels' => ['discord', 'teams'],
            'wafy.notifications.discord_webhook' => 'https://discord.test/hook',
            'wafy.notifications.teams_webhook' => 'https://teams.test/hook',
        ]);

        $this->postJson('/waf', ['c' => '<script>alert(1)</script>'])->assertStatus(403);

        Http::assertSent(function ($request) {
            return $request->url() === 'https://discord.test/hook'
                && isset($request->data()['embeds']);
        });

        Http::assertSent(function ($request) {
            return $request->url() === 'https://teams.test/hook'
                && ($request->data()['@type'] ?? null) === 'MessageCard';
        });
    }

    /** @test */
    public function the_stored_redacted_url_is_forwarded_to_the_webhook()
    {
        Http::fake();
        config([
            'wafy.notifications.enabled' => true,
            'wafy.notifications.channels' => ['discord'],
            'wafy.notifications.discord_webhook' => 'https://discord.test/hook',
        ]);

        // token sensible dans la query -> doit être rédigé avant d'atteindre le webhook.
        $this->get('/waf?token=SECRET123&q=' . urlencode('UNION SELECT 1,2,3'))->assertStatus(403);

        Http::assertSent(function ($request) {
            $body = json_encode($request->data());
            return strpos($body, 'SECRET123') === false && strpos($body, 'REDACTED') !== false;
        });
    }

    /** @test */
    public function test_notification_command_posts_to_the_webhook_and_succeeds()
    {
        Http::fake();
        config([
            'wafy.notifications.enabled' => true,
            'wafy.notifications.channels' => ['discord'],
            'wafy.notifications.discord_webhook' => 'https://discord.test/hook',
        ]);

        $this->artisan('wafy:test-notification')->assertExitCode(0);

        Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/hook');
    }

    /** @test */
    public function test_notification_command_skips_channels_without_destination()
    {
        Http::fake();
        config([
            'wafy.notifications.channels' => ['discord'],
            'wafy.notifications.discord_webhook' => '',
        ]);

        $this->artisan('wafy:test-notification')->assertExitCode(0);

        Http::assertNothingSent();
    }

    /** @test */
    public function test_notification_command_channel_option_targets_a_single_channel()
    {
        Http::fake();
        config([
            'wafy.notifications.channels' => ['mail', 'discord', 'teams'],
            'wafy.notifications.discord_webhook' => 'https://discord.test/hook',
            'wafy.notifications.teams_webhook' => 'https://teams.test/hook',
        ]);

        $this->artisan('wafy:test-notification --channel=discord')->assertExitCode(0);

        Http::assertSent(fn ($request) => $request->url() === 'https://discord.test/hook');
        Http::assertNotSent(fn ($request) => $request->url() === 'https://teams.test/hook');
    }

    /** @test */
    public function test_notification_command_reports_failure_on_a_bad_webhook()
    {
        Http::fake(['*' => Http::response('nope', 500)]);
        config([
            'wafy.notifications.enabled' => true,
            'wafy.notifications.channels' => ['discord'],
            'wafy.notifications.discord_webhook' => 'https://discord.test/hook',
        ]);

        // La règle ->throw() du canal fait remonter l'erreur -> code de sortie 1.
        $this->artisan('wafy:test-notification')->assertExitCode(1);
    }
}
