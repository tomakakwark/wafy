<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;

class UnbanIp extends Command
{
    protected $signature = 'wafy:unban {ip}';
    protected $description = 'Débannir une adresse IP';

    public function handle()
    {
        $ip = $this->argument('ip');

        $bannedIp = BannedIp::where('ip_address', $ip)->first();

        if (!$bannedIp) {
            $this->error('L\'IP ' . $ip . ' n\'est pas bannie.');
            return 1;
        }

        $bannedIp->delete();

        $this->info('L\'IP ' . $ip . ' a été débannie avec succès.');
        return 0;
    }
}
