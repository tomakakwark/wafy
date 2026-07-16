<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Tests\Support\FakeGeoIpResolver;
use Bdsa\Wafy\Contracts\GeoIpResolver;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Illuminate\Support\Facades\Route;

class GeoIpTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
    }

    private function fake(array $map): void
    {
        // Public IPs only — geo is skipped for private/reserved addresses.
        $this->app->instance(GeoIpResolver::class, new FakeGeoIpResolver($map));
    }

    private function hit(string $ip, string $uri = '/waf')
    {
        return $this->call('GET', $uri, [], [], [], ['REMOTE_ADDR' => $ip]);
    }

    /** @test */
    public function deny_mode_blocks_a_listed_country_without_banning()
    {
        $this->fake(['8.8.8.8' => ['country' => 'RU']]);
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.mode' => 'deny', 'wafy.geoip.countries' => ['RU'], 'wafy.geoip.action' => 'block']);

        $this->hit('8.8.8.8')->assertStatus(403);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '8.8.8.8']);
    }

    /** @test */
    public function deny_mode_with_ban_action_persists_a_ban()
    {
        $this->fake(['8.8.8.8' => ['country' => 'RU']]);
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.countries' => ['RU'], 'wafy.geoip.action' => 'ban']);

        $this->hit('8.8.8.8')->assertStatus(403);

        $ban = \Bdsa\Wafy\Models\BannedIp::firstWhere('ip_address', '8.8.8.8');
        $this->assertNotNull($ban);
        $this->assertStringContainsString('GeoIP: country RU denied', $ban->reason);
    }

    /** @test */
    public function allow_mode_blocks_a_non_listed_country_but_passes_allowed_and_unknown()
    {
        $this->fake(['9.9.9.9' => ['country' => 'BR'], '1.1.1.1' => ['country' => 'FR']]);
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.mode' => 'allow', 'wafy.geoip.countries' => ['FR']]);

        $this->hit('9.9.9.9')->assertStatus(403);              // BR not allowed
        $this->hit('1.1.1.1')->assertStatus(200)->assertSee('Safe'); // FR allowed
        $this->hit('8.8.8.8')->assertStatus(200);              // unknown -> passes
    }

    /** @test */
    public function it_denies_by_asn_in_any_mode()
    {
        $this->fake(['8.8.8.8' => ['asn' => 14061], '1.1.1.1' => ['asn' => 20001]]);
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.mode' => 'allow', 'wafy.geoip.countries' => [], 'wafy.geoip.deny_asns' => [14061]]);

        $this->hit('8.8.8.8')->assertStatus(403);
        $this->hit('1.1.1.1')->assertStatus(200);
    }

    /** @test */
    public function score_action_only_blocks_with_corroboration()
    {
        $this->fake(['8.8.8.8' => ['country' => 'RU']]);
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.countries' => ['RU'], 'wafy.geoip.action' => 'score', 'wafy.geoip.score' => 3]);

        // Geo (3) alone < threshold (4) -> passes.
        $this->hit('8.8.8.8', '/waf?q=hello')->assertStatus(200);

        // Geo (3) + scanner.sensitive (2) = 5 >= 4 -> blocked.
        $this->hit('8.8.8.8', '/waf?x=' . urlencode('/wp-admin'))->assertStatus(403);
    }

    /** @test */
    public function it_skips_geoip_for_private_ips()
    {
        // Even in allow mode, a private IP must never be geo-blocked (self-DoS guard).
        config(['wafy.ban_private_ips' => false, 'wafy.geoip.enabled' => true, 'wafy.geoip.mode' => 'allow', 'wafy.geoip.countries' => ['FR']]);
        $this->app->instance(GeoIpResolver::class, new FakeGeoIpResolver(['10.0.0.5' => ['country' => 'BR']]));

        $this->hit('10.0.0.5')->assertStatus(200);
        $this->hit('127.0.0.1')->assertStatus(200);
    }

    /** @test */
    public function it_does_nothing_when_disabled()
    {
        $this->fake(['8.8.8.8' => ['country' => 'RU']]);
        // enabled defaults to false -> resolver never consulted even with a deny list.
        config(['wafy.geoip.countries' => ['RU']]);

        $this->hit('8.8.8.8')->assertStatus(200)->assertSee('Safe');
    }

    /** @test */
    public function an_already_banned_ip_is_not_re_banned_by_geoip()
    {
        // GeoIP runs AFTER the active-ban exit, so a banned IP short-circuits
        // without re-banning / inflating offense_count.
        $this->fake(['8.8.8.8' => ['country' => 'RU']]);
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.countries' => ['RU'], 'wafy.geoip.action' => 'ban']);

        \Bdsa\Wafy\Models\BannedIp::create(['ip_address' => '8.8.8.8', 'banned_until' => now()->addDay(), 'offense_count' => 1]);

        $this->hit('8.8.8.8')->assertStatus(403);

        $this->assertSame(1, \Bdsa\Wafy\Models\BannedIp::firstWhere('ip_address', '8.8.8.8')->offense_count);
    }

    /** @test */
    public function a_failing_resolver_does_not_500_the_request()
    {
        // A resolver that throws must fail-open (skip geo), not crash the app.
        $this->app->instance(GeoIpResolver::class, new class implements GeoIpResolver {
            public function country(?string $ip): ?string { throw new \RuntimeException('boom'); }
            public function asn(?string $ip): ?int { throw new \RuntimeException('boom'); }
        });
        config(['wafy.geoip.enabled' => true, 'wafy.geoip.countries' => ['RU']]);

        $this->hit('8.8.8.8')->assertStatus(200)->assertSee('Safe');
    }

    /** @test */
    public function it_obeys_log_mode()
    {
        $this->fake(['8.8.8.8' => ['country' => 'RU']]);
        config(['wafy.action' => 'log', 'wafy.geoip.enabled' => true, 'wafy.geoip.countries' => ['RU'], 'wafy.geoip.action' => 'block']);

        $this->hit('8.8.8.8')->assertStatus(200)->assertSee('Safe');
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '8.8.8.8']);
    }
}
