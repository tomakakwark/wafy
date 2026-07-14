<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\BannedIp;
use Bdsa\Wafy\Concerns\HandlesClientIp;

class UnbanIp extends Command
{
    use HandlesClientIp;

    protected $signature = 'wafy:unban {ip}';
    protected $description = 'Débannir une adresse IP';

    public function handle()
    {
        $ip = $this->argument('ip');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->error('Adresse IP invalide : ' . $ip);
            return 1;
        }

        $identity = $this->banIdentity($ip);

        $bannedIp = BannedIp::where('ip_address', $identity)->first();

        if (!$bannedIp) {
            $this->error('L\'IP ' . $ip . ' n\'est pas bannie.');
            return 1;
        }

        $bannedIp->delete();

        $this->forgetClean($identity);

        $this->info('L\'IP ' . $ip . ' a été débannie avec succès.');
        return 0;
    }
}
