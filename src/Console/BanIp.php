<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;

class BanIp extends Command
{
    protected $signature = 'wafy:ban {ip} {--reason=Manual ban via Artisan command}';
    protected $description = 'Bannir une adresse IP';

    public function handle()
    {
        $ip = $this->argument('ip');
        $reason = $this->option('reason');

        if (BannedIp::where('ip_address', $ip)->exists()) {
            $this->error('L\'IP est déjà bannie.');
            return 1;
        }

        BannedIp::create([
            'ip_address' => $ip,
            'reason' => $reason,
        ]);

        $this->info('L\'IP ' . $ip . ' a été bannie avec succès.');
        return 0;
    }
}