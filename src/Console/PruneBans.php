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
        // 1. Bans temporaires expirés (banned_until dépassé).
        $expired = BannedIp::whereNotNull('banned_until')
            ->where('banned_until', '<', now())
            ->delete();

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

        return 0;
    }
}
