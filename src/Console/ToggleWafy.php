<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;

class ToggleWafy extends Command
{
    protected $signature = 'wafy:mode {status : The status to set (enable/disable)}';

    protected $description = 'Enable or disable the WAF functionality globally.';

    public function handle()
    {
        $status = strtolower($this->argument('status'));

        if (!in_array($status, ['enable', 'disable'])) {
            $this->error('Invalid status. Please use "enable" or "disable".');
            return 1;
        }

        $isEnabled = ($status === 'enable');

        // Update the cache to persist the setting
        cache()->put('wafy.enabled', $isEnabled); // Stores indefinitely

        $this->info("WAF has been slightly {$status}d.");

        return 0;
    }
}