<?php

namespace Bdsa\Wafy\Tests\Unit\Middleware;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Support\Facades\Route;

class DetectMaliciousRequestsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware(DetectMaliciousRequests::class)->any('/test-waf', function () {
            return 'Safe';
        });
    }

    /** @test */
    public function it_allows_safe_requests()
    {
        $response = $this->get('/test-waf?q=hello');
        $response->assertStatus(200);
    }

    /** @test */
    public function it_detects_sqli_in_query_string()
    {
        $response = $this->get('/test-waf?q=UNION SELECT 1,2,3');
        $response->assertStatus(403);
        $this->assertDatabaseHas('banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_detects_xss_in_body()
    {
        $response = $this->postJson('/test-waf', ['comment' => '<script>alert(1)</script>']);
        $response->assertStatus(403);
        $this->assertDatabaseHas('banned_ips', ['ip_address' => '127.0.0.1']);
    }

    /** @test */
    public function it_detects_lfi_attempts()
    {
        $response = $this->get('/test-waf?file=../../etc/passwd');
        $response->assertStatus(403);
    }
}