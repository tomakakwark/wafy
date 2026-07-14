<?php

namespace Bdsa\Wafy\Tests\Unit\Console;

use Bdsa\Wafy\Tests\TestCase;
use Illuminate\Support\Facades\Cache;

class SetActionTest extends TestCase
{
    /** @test */
    public function it_sets_action_to_block()
    {
        $this->artisan('wafy:action', ['action' => 'block'])
            ->expectsOutput('Wafy action mode set to: block')
            ->assertExitCode(0);

        $this->assertEquals('block', Cache::get('wafy.action'));
    }

    /** @test */
    public function it_sets_action_to_log()
    {
        $this->artisan('wafy:action', ['action' => 'log'])
            ->expectsOutput('Wafy action mode set to: log')
            ->expectsOutput("In 'log' mode, malicious requests are logged but NOT blocked.")
            ->assertExitCode(0);

        $this->assertEquals('log', Cache::get('wafy.action'));
    }

    /** @test */
    public function it_rejects_invalid_action()
    {
        $this->artisan('wafy:action', ['action' => 'invalid'])
            ->expectsOutput('Invalid action. Please use "block" or "log".')
            ->assertExitCode(1);
    }

    /** @test */
    public function it_warns_when_the_cache_driver_is_ephemeral()
    {
        // Testbench defaults to the array cache -> the setting won't persist.
        config(['cache.default' => 'array']);

        $this->artisan('wafy:action', ['action' => 'block'])
            ->expectsOutputToContain('ne persistera pas')
            ->assertExitCode(0);
    }
}