<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;

class PruneBans extends Command
{
    protected $signature = 'wafy:prune {--days= : Supprimer aussi les bans plus vieux que N jours (rétention/RGPD)}';
    protected $description = 'Purger les bans temporaires expirés (et, en option, les bans anciens)';

    public function handle()
    {
        // 1. Bans temporaires expirés (banned_until dépassé). En mode backoff, on
        //    ne les supprime qu'après backoff_reset_after jours de calme afin que
        //    le compteur d'offenses survive assez longtemps pour l'escalade.
        $resetAfter = (int) config('wafy.backoff_reset_after', 30);
        $query = BannedIp::whereNotNull('banned_until')->where('banned_until', '<', now());

        if (config('wafy.backoff_enabled', true) && $resetAfter > 0) {
            $query->where('updated_at', '<', now()->subDays($resetAfter));
        }

        $expired = $query->delete();

        $this->info("{$expired} ban(s) temporaire(s) expiré(s) supprimé(s).");

        // 2. Rétention optionnelle : bans plus anciens que N jours.
        $days = $this->option('days');
        if ($days === null || $days === '') {
            $days = config('wafy.retention_days');
        }

        if ($days !== null && $days !== '' && (int) $days > 0) {
            $cutoff = now()->subDays((int) $days);
            $old = BannedIp::where('created_at', '<', $cutoff)->delete();
            $this->info("{$old} ban(s) plus ancien(s) que " . (int) $days . " jour(s) supprimé(s).");
        }

        // 3. Rétention des événements de stats (append-only), si activés.
        $statsRetention = (int) config('wafy.stats.retention_days', 90);
        if (config('wafy.stats.enabled', false) && $statsRetention > 0) {
            try {
                $purged = \Bdsa\Wafy\Models\WafyEvent::where('created_at', '<', now()->subDays($statsRetention))->delete();
                $this->info("{$purged} événement(s) de stats plus vieux que {$statsRetention} jour(s) supprimé(s).");
            } catch (\Throwable $e) {
                // table absente / non migrée : on ignore
            }
        }

        return 0;
    }
}
