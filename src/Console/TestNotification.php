<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Notification;
use Bdsa\Wafy\Models\BannedIp;
use Bdsa\Wafy\Notifications\IpBannedNotification;

class TestNotification extends Command
{
    protected $signature = 'wafy:test-notification {--channel= : Tester uniquement ce canal (mail|slack|discord|teams)}';
    protected $description = 'Envoyer une notification de test sur les canaux configurés';

    public function handle()
    {
        $only = $this->option('channel');
        $channels = $only ? [$only] : (array) config('wafy.notifications.channels', ['mail']);

        if (empty($channels)) {
            $this->error('Aucun canal configuré (wafy.notifications.channels).');
            return 1;
        }

        if (!config('wafy.notifications.enabled')) {
            $this->warn('⚠  wafy.notifications.enabled = false : les alertes réelles sont désactivées. Envoi de test quand même.');
        }

        $ban = $this->sampleBan();

        $destinations = [
            'mail' => config('wafy.notifications.email'),
            'slack' => config('wafy.notifications.slack_webhook'),
            'discord' => config('wafy.notifications.discord_webhook'),
            'teams' => config('wafy.notifications.teams_webhook'),
        ];

        $failed = 0;

        foreach ($channels as $channel) {
            $destination = $destinations[$channel] ?? null;

            if (empty($destination)) {
                $this->warn("•  {$channel} : aucune destination configurée — ignoré.");
                continue;
            }

            try {
                // sendNow contourne la file d'attente pour un retour immédiat.
                Notification::sendNow($ban, (new IpBannedNotification($ban))->only([$channel]));
                $this->info("✔  {$channel} → {$destination}");
            } catch (\Throwable $e) {
                $failed++;
                $this->error("✗  {$channel} : " . $e->getMessage());
            }
        }

        if ($failed > 0) {
            $this->newLine();
            $this->error("{$failed} canal(aux) en échec.");
            return 1;
        }

        return 0;
    }

    /**
     * Build a throwaway (unsaved) ban record to feed the notification.
     */
    private function sampleBan(): BannedIp
    {
        $ban = new BannedIp([
            'ip_address' => '203.0.113.42',
            'reason' => 'WAF score 8/4 in RequestBody (rules: xss.script_tag) — TEST',
        ]);

        $ban->request_data = [
            'method' => 'POST',
            'url' => 'https://example.test/login?token=[REDACTED]',
            'input' => ['comment' => '<script>alert(1)</script>'],
        ];

        return $ban;
    }
}
