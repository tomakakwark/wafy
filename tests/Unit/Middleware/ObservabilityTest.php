<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Models\WafyEvent;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

class ObservabilityTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
    }

    /** @test */
    public function it_records_a_telemetry_event_when_stats_enabled()
    {
        config(['wafy.stats.enabled' => true]);

        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);

        $event = WafyEvent::first();
        $this->assertNotNull($event);
        $this->assertSame('banned', $event->event);
        $this->assertContains('sqli.union_select', (array) $event->rule_ids);
        $this->assertGreaterThanOrEqual(5, $event->score);
    }

    /** @test */
    public function it_records_nothing_when_stats_disabled_by_default()
    {
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);

        $this->assertSame(0, WafyEvent::count());
    }

    /** @test */
    public function wafy_stats_command_reports()
    {
        config(['wafy.stats.enabled' => true]);
        WafyEvent::create(['ip_identity' => '1.2.3.4', 'event' => 'banned', 'rule_ids' => ['sqli.union_select'], 'score' => 5, 'path' => '/x', 'country' => 'RU', 'created_at' => now()]);

        $this->artisan('wafy:stats --json')->assertExitCode(0);
        $this->artisan('wafy:stats')->assertExitCode(0);
    }

    /** @test */
    public function stats_events_are_deduped_within_the_window()
    {
        // Log mode -> no ban -> both requests reach recordEvent; dedup keeps 1.
        config(['wafy.stats.enabled' => true, 'wafy.stats.dedup_seconds' => 60, 'wafy.action' => 'log']);

        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(200);
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(200);

        $this->assertSame(1, WafyEvent::where('event', 'logged')->count());
    }

    /** @test */
    public function it_emits_structured_log_context_on_detection()
    {
        Log::spy();

        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);

        Log::shouldHaveReceived('log')->withArgs(function ($level, $message, $context = []) {
            return is_array($context)
                && (($context['wafy'] ?? false) === true)
                && isset($context['event'])
                && isset($context['decision']);
        })->atLeast()->once();
    }

    /** @test */
    public function logging_can_be_disabled()
    {
        config(['wafy.logging.enabled' => false]);
        Log::spy();

        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);

        // wafyLog is a no-op; only non-wafyLog error paths could log (none here).
        Log::shouldNotHaveReceived('log');
    }
}
