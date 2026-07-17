<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Console\ManageRules;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Route;

class RulesTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Route::middleware(DetectMaliciousRequests::class)->any('/waf', fn () => 'Safe');
    }

    /** @test */
    public function a_bundled_pack_is_off_until_enabled_then_loads()
    {
        $payload = '/waf?x=' . urlencode("assert(\$_GET['c'])");

        // Off by default: assert()/$_GET[ are not core rules -> passes.
        $this->get($payload)->assertStatus(200);

        // Enabled: two pack rules (3+3) cross the threshold -> blocked.
        config(['wafy.rule_packs' => ['owasp-crs']]);
        $this->get($payload)->assertStatus(403);
    }

    /** @test */
    public function a_single_pack_rule_does_not_block_alone()
    {
        config(['wafy.rule_packs' => ['owasp-crs']]);

        // crs.930.os_files scores 3 (< threshold 4) -> corroboration required.
        $this->get('/waf?f=' . urlencode('/etc/hosts'))->assertStatus(200);
    }

    /** @test */
    public function a_rule_can_be_disabled_and_re_enabled_at_runtime()
    {
        // Disabled first (a 200 leaves no ban to contaminate the next request).
        Cache::forever(ManageRules::CACHE_KEY, ['sqli.union_select']);
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(200);

        // Re-enabled: it blocks again.
        Cache::forget(ManageRules::CACHE_KEY);
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);
    }

    /** @test */
    public function a_config_disabled_rule_does_not_fire()
    {
        config(['wafy.rules' => [
            ['id' => 'x.off', 'score' => 5, 'enabled' => false, 'pattern' => '/PLEASEBLOCKME/'],
        ]]);

        $this->get('/waf?q=PLEASEBLOCKME')->assertStatus(200);
    }

    /** @test */
    public function wafy_rule_command_lists_disables_and_enables()
    {
        $this->artisan('wafy:rule list')
            ->expectsOutputToContain('sqli.union_select')
            ->assertExitCode(0);

        $this->artisan('wafy:rule disable sqli.union_select')->assertExitCode(0);
        $this->assertContains('sqli.union_select', (array) Cache::get(ManageRules::CACHE_KEY, []));
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(200);

        $this->artisan('wafy:rule enable sqli.union_select')->assertExitCode(0);
        $this->get('/waf?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);
    }

    /** @test */
    public function wafy_rule_rejects_an_unknown_id()
    {
        $this->artisan('wafy:rule disable no.such.rule')->assertExitCode(1);
    }

    /** @test */
    public function it_imports_external_rules_and_loads_them()
    {
        $out = sys_get_temp_dir() . '/wafy-imported-' . uniqid() . '.php';
        $src = sys_get_temp_dir() . '/wafy-src-' . uniqid() . '.txt';
        file_put_contents($src, "# custom signatures\nMYSECRETATTACKTOKEN\n");
        config(['wafy.imported_rules_path' => $out]);

        $this->artisan('wafy:rules:import', ['source' => $src, '--score' => 5])->assertExitCode(0);
        $this->assertFileExists($out);

        $this->get('/waf?q=hello-MYSECRETATTACKTOKEN-world')->assertStatus(403);

        @unlink($out);
        @unlink($src);
    }
}
