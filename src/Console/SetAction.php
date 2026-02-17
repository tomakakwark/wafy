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

        // Cache for 1 year (essentially permanent until cleared or changed)
        Cache::put('wafy.action', $action, now()->addYear());

        $this->info("Wafy action mode set to: {$action}");
        $this->info("In 'log' mode, malicious requests are logged but NOT blocked.");
        return 0;
    }
}