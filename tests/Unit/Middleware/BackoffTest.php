<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Support\Facades\Route;

class BackoffTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
    }

    private function attack(): void
    {
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);
    }

    /** @test */
    public function repeat_offenders_get_escalating_ban_durations()
    {
        config(['wafy.backoff_enabled' => true, 'wafy.backoff_base' => 10, 'wafy.backoff_multiplier' => 2]);

        // First offense -> ~10 min.
        $this->attack();
        $ban = BannedIp::first();
        $this->assertSame(1, $ban->offense_count);
        $this->assertTrue($ban->banned_until->lessThan(now()->addMinutes(15)));

        // Expire it, then re-offend -> offense #2, ~20 min (longer).
        BannedIp::where('id', $ban->id)->update(['banned_until' => now()->subMinute()]);
        $this->attack();

        $ban->refresh();
        $this->assertSame(2, $ban->offense_count);
        $this->assertTrue($ban->banned_until->greaterThan(now()->addMinutes(15)));
    }

    /** @test */
    public function it_escalates_to_a_permanent_ban_after_the_configured_offenses()
    {
        config([
            'wafy.backoff_enabled' => true,
            'wafy.backoff_base' => 5,
            'wafy.escalate_to_permanent_after' => 2,
        ]);

        $this->attack(); // offense #1 -> temporary
        $ban = BannedIp::first();
        $this->assertNotNull($ban->banned_until);

        BannedIp::where('id', $ban->id)->update(['banned_until' => now()->subMinute()]);
        $this->attack(); // offense #2 -> permanent

        $ban->refresh();
        $this->assertSame(2, $ban->offense_count);
        $this->assertNull($ban->banned_until);
    }

    /** @test */
    public function backoff_disabled_keeps_a_fixed_duration()
    {
        config(['wafy.backoff_enabled' => false, 'wafy.ban_duration' => 30]);

        $this->attack();
        $ban = BannedIp::first();
        $this->assertSame(1, $ban->offense_count);
        $this->assertTrue($ban->banned_until->between(now()->addMinutes(25), now()->addMinutes(35)));
    }
}
