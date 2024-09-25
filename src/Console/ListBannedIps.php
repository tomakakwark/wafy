<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;

class ListBannedIps extends Command
{
    protected $signature = 'wafy:list';
    protected $description = 'Lister les adresses IP bannies';

    public function handle()
    {
        // Récupérer toutes les adresses IP bannies
        $bannedIps = BannedIp::all();

        if ($bannedIps->isEmpty()) {
            $this->info('Aucune adresse IP n\'est actuellement bannie.');
            return;
        }

        // Afficher les IP bannies
        $this->info('Adresses IP bannies :');
        foreach ($bannedIps as $bannedIp) {
            $this->line($bannedIp->ip_address);
        }
    }
}
