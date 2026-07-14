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

        $this->assertDatabaseHas('wafy_banned_ips', [
            'ip_address' => '1.2.3.4',
            'reason' => 'Manual ban via Artisan command',
        ]);
    }

    /** @test */
    public function it_bans_an_ip_with_custom_reason()
    {
        $this->artisan('wafy:ban', ['ip' => '1.2.3.4', '--reason' => 'Spamming'])
            ->expectsOutput('L\'IP 1.2.3.4 a été bannie avec succès.')
            ->assertExitCode(0);

        $this->assertDatabaseHas('wafy_banned_ips', [
            'ip_address' => '1.2.3.4',
            'reason' => 'Spamming',
        ]);
    }

    /** @test */
    public function it_can_unban_an_ip()
    {
        BannedIp::create(['ip_address' => '1.2.3.4']);

        $this->artisan('wafy:unban', ['ip' => '1.2.3.4'])
            ->expectsOutput('L\'IP 1.2.3.4 a été débannie avec succès.')
            ->assertExitCode(0);

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '1.2.3.4']);
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

    /** @test */
    public function it_rejects_an_invalid_ip_on_ban()
    {
        $this->artisan('wafy:ban', ['ip' => 'not-an-ip'])
            ->expectsOutputToContain('Adresse IP invalide')
            ->assertExitCode(1);

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => 'not-an-ip']);
    }

    /** @test */
    public function it_rejects_an_invalid_ip_on_unban()
    {
        $this->artisan('wafy:unban', ['ip' => '999.999.999.999'])
            ->expectsOutputToContain('Adresse IP invalide')
            ->assertExitCode(1);
    }

    /** @test */
    public function it_bans_an_ipv6_address_by_its_prefix()
    {
        $this->artisan('wafy:ban', ['ip' => '2001:db8:1:2::5'])
            ->assertExitCode(0);

        // Manual bans normalise to the same /64 identity the middleware uses.
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '2001:db8:1:2::/64']);
    }
}