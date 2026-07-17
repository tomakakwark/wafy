<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Middleware\DetectMaliciousRequests;

class ManageRules extends Command
{
    /** Forever-cached array<string> of runtime-disabled rule ids. */
    const CACHE_KEY = 'wafy.disabled_rules';

    protected $signature = 'wafy:rule {action : list|enable|disable} {id? : Rule id (enable/disable)}';
    protected $description = 'Lister les règles de détection ou en activer/désactiver une au runtime.';

    public function handle()
    {
        $action = strtolower((string) $this->argument('action'));

        switch ($action) {
            case 'list':
                return $this->listRules();
            case 'enable':
                return $this->toggle(true);
            case 'disable':
                return $this->toggle(false);
            default:
                $this->error('Action invalide. Utilisez : list, enable, disable.');
                return 1;
        }
    }

    private function knownRules(): array
    {
        return (new DetectMaliciousRequests())->rulesMetadata();
    }

    private function disabledSet(): array
    {
        $ids = cache()->get(self::CACHE_KEY, []);

        return is_array($ids) ? array_values(array_unique(array_map('strval', array_filter($ids, 'is_scalar')))) : [];
    }

    private function listRules()
    {
        $runtime = array_flip($this->disabledSet());
        $rows = [];

        foreach ($this->knownRules() as $id => $meta) {
            if (!empty($meta['static_disabled'])) {
                $state = 'disabled (config)';
            } elseif (isset($runtime[$id])) {
                $state = 'disabled (runtime)';
            } else {
                $state = 'enabled';
            }
            $rows[] = [$id, $meta['score'], $meta['severity'] ?? '-', $state];
        }

        if (empty($rows)) {
            $this->info('Aucune règle configurée.');
            return 0;
        }

        $this->table(['ID', 'Score', 'Severity', 'State'], $rows);
        return 0;
    }

    private function toggle(bool $enable)
    {
        $id = (string) $this->argument('id');
        if ($id === '') {
            $this->error('Un id de règle est requis.');
            return 1;
        }

        $known = $this->knownRules();
        if (!isset($known[$id])) {
            $this->error("Règle inconnue : {$id}. Lancez `wafy:rule list`.");
            return 1;
        }

        $set = $this->disabledSet();

        if ($enable) {
            if (!empty($known[$id]['static_disabled'])) {
                $this->warn("La règle {$id} est désactivée dans la config ('enabled' => false) ; "
                    . "l'activation runtime ne peut pas la réactiver. Éditez config/wafy.php.");
            }
            $set = array_values(array_diff($set, [$id]));
            if (empty($set)) {
                cache()->forget(self::CACHE_KEY);
            } else {
                cache()->forever(self::CACHE_KEY, $set);
            }
            $this->info("Règle {$id} activée (retirée du set de désactivation runtime).");
        } else {
            if (!in_array($id, $set, true)) {
                $set[] = $id;
            }
            cache()->forever(self::CACHE_KEY, array_values($set));
            $this->info("Règle {$id} désactivée au runtime.");
        }

        if (in_array(config('cache.default'), ['array', 'null'], true)) {
            $this->warn('⚠  Cache par défaut « ' . config('cache.default')
                . ' » : ce réglage ne persistera pas d\'une requête à l\'autre. '
                . 'Configurez un cache partagé (redis/database/file).');
        }

        return 0;
    }
}
