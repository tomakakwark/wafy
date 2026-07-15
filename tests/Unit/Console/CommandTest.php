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

    /** @test */
    public function prune_removes_expired_bans_and_keeps_active_ones()
    {
        // Sans backoff, un ban expiré est purgé immédiatement.
        config(['wafy.backoff_enabled' => false]);

        BannedIp::create(['ip_address' => '1.1.1.1', 'banned_until' => now()->subMinute()]); // expiré
        BannedIp::create(['ip_address' => '2.2.2.2', 'banned_until' => now()->addDay()]);     // actif
        BannedIp::create(['ip_address' => '3.3.3.3', 'banned_until' => null]);                 // permanent

        $this->artisan('wafy:prune')->assertExitCode(0);

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '1.1.1.1']);
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '2.2.2.2']);
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '3.3.3.3']);
    }

    /** @test */
    public function prune_keeps_recently_expired_bans_within_the_backoff_grace_window()
    {
        // Avec backoff (défaut), une offense récemment expirée survit pour l'escalade.
        config(['wafy.backoff_enabled' => true, 'wafy.backoff_reset_after' => 30]);

        $recent = BannedIp::create(['ip_address' => '6.6.6.6', 'banned_until' => now()->subMinute(), 'offense_count' => 2]);

        $stale = BannedIp::create(['ip_address' => '7.7.7.7', 'banned_until' => now()->subDay(), 'offense_count' => 1]);
        BannedIp::where('id', $stale->id)->update(['updated_at' => now()->subDays(40)]);

        $this->artisan('wafy:prune')->assertExitCode(0);

        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '6.6.6.6']);     // récent -> gardé
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '7.7.7.7']); // calme > 30j -> oublié
    }

    /** @test */
    public function prune_with_days_removes_bans_older_than_the_retention()
    {
        $old = BannedIp::create(['ip_address' => '4.4.4.4', 'banned_until' => null]);
        BannedIp::where('id', $old->id)->update(['created_at' => now()->subDays(40)]);

        BannedIp::create(['ip_address' => '5.5.5.5', 'banned_until' => null]); // récent

        $this->artisan('wafy:prune', ['--days' => 30])->assertExitCode(0);

        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '4.4.4.4']);
        $this->assertDatabaseHas('wafy_banned_ips', ['ip_address' => '5.5.5.5']);
    }
}