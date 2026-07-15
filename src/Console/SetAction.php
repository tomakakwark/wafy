<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;

class SetAction extends Command
{
    protected $signature = 'wafy:action {action : The action to take (block|log)}';
    protected $description = 'Set the WAF action mode (block or log)';

    public function handle()
    {
        $action = $this->argument('action');

        if (!in_array($action, ['block', 'log'])) {
            $this->error('Invalid action. Please use "block" or "log".');
            return 1;
        }

        // Runtime override: stored indefinitely until changed or the cache is
        // flushed (consistent with wafy:mode).
        Cache::forever('wafy.action', $action);

        if (in_array(config('cache.default'), ['array', 'null'], true)) {
            $this->warn('⚠  Cache par défaut « ' . config('cache.default') . ' » : ce réglage ne persistera pas d\'une requête à l\'autre. Configurez un cache partagé (redis/database/file) ou éditez config/wafy.php.');
        }

        $this->info("Wafy action mode set to: {$action}");
        $this->info("In 'log' mode, malicious requests are logged but NOT blocked.");
        return 0;
    }
}