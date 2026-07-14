<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;
use Bdsa\Wafy\Concerns\HandlesClientIp;

class BanIp extends Command
{
    use HandlesClientIp;

    protected $signature = 'wafy:ban {ip} {--reason=Manual ban via Artisan command}';
    protected $description = 'Bannir une adresse IP';

    public function handle()
    {
        $ip = $this->argument('ip');
        $reason = $this->option('reason');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error('Adresse IP invalide : ' . $ip);
            return 1;
        }

        // Normalise (IPv6 -> /prefix) so manual bans match what the middleware
        // looks up for incoming requests.
        $identity = $this->banIdentity($ip);

        if (BannedIp::where('ip_address', $identity)->exists()) {
            $this->error('L\'IP est déjà bannie.');
            return 1;
        }

        BannedIp::create([
            'ip_address' => $identity,
            'reason' => $reason,
        ]);

        $this->forgetClean($identity);

        $this->info('L\'IP ' . $ip . ' a été bannie avec succès.');
        return 0;
    }
}