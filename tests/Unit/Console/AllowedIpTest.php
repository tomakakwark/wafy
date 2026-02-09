<?php

namespace Bdsa\Wafy\Tests\Console;

use Bdsa\Wafy\Tests\TestCase;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;
use Bdsa\Wafy\Middleware\BlockBannedIp;
use Bdsa\Wafy\Models\BannedIp;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Config;

class AllowedIpTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Route::middleware([BlockBannedIp::class , DetectMaliciousRequests::class])->get('/test-allowed', function () {
            return 'Safe';
        });
    }

    /** @test */
    public function it_allows_banned_ip_if_in_allowed_list()
    {
        // 1. Bannir l'IP manuellement
        BannedIp::create(['ip_address' => '127.0.0.1']);

        // 2. Vérifier qu'elle est bloquée par défaut
        $response = $this->get('/test-allowed');
        $response->assertStatus(403);

        // 3. Ajouter l'IP à la liste blanche
        Config::set('wafy.allowed_ips', ['127.0.0.1']);

        // 4. Vérifier qu'elle passe maintenant
        $response = $this->get('/test-allowed');
        $response->assertStatus(200);
    }

    /** @test */
    public function it_allows_malicious_request_if_ip_is_allowed()
    {
        // 1. Configurer l'IP autorisée
        Config::set('wafy.allowed_ips', ['127.0.0.1']);

        // 2. Envoyer une requête malveillante (SQLi)
        $response = $this->get('/test-allowed?q=UNION SELECT 1');

        // 3. Vérifier qu'elle passe sans être bannie
        $response->assertStatus(200);
        $this->assertDatabaseMissing('banned_ips', ['ip_address' => '127.0.0.1']);
    }
}