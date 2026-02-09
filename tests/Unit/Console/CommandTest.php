<?php

namespace Bdsa\Wafy\Tests\Unit\Console;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Models\BannedIp;

class CommandTest extends TestCase
{
    /** @test */
    public function it_can_ban_an_ip()
    {
        $this->artisan('wafy:ban', ['ip' => '1.2.3.4'])
            ->expectsOutput('L\'IP 1.2.3.4 a été bannie avec succès.')
            ->assertExitCode(0);

        $this->assertDatabaseHas('banned_ips', ['ip_address' => '1.2.3.4']);
    }

    /** @test */
    public function it_can_unban_an_ip()
    {
        BannedIp::create(['ip_address' => '1.2.3.4']);

        $this->artisan('wafy:unban', ['ip' => '1.2.3.4'])
            ->expectsOutput('L\'IP 1.2.3.4 a été débannie avec succès.')
            ->assertExitCode(0);

        $this->assertDatabaseMissing('banned_ips', ['ip_address' => '1.2.3.4']);
    }

    /** @test */
    public function it_can_list_banned_ips()
    {
        BannedIp::create(['ip_address' => '1.1.1.1']);
        BannedIp::create(['ip_address' => '2.2.2.2']);

        $this->artisan('wafy:list')
            ->expectsOutput('Adresses IP bannies :')
            ->expectsOutput('1.1.1.1')
            ->expectsOutput('2.2.2.2')
            ->assertExitCode(0);
    }
}