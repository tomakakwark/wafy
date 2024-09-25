<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;

class BanIp extends Command
{
    protected $signature = 'wafy:ban {ip}';
    protected $description = 'Bannir une adresse IP';

    public function handle()
    {
        $ip = $this->argument('ip');

        if (BannedIp::where('ip_address', $ip)->exists()) {
            $this->error('L\'IP est déjà bannie.');
            return 1;
        }

        BannedIp::create(['ip_address' => $ip]);

        $this->info('L\'IP ' . $ip . ' a été bannie avec succès.');
        return 0;
    }
}
