<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;
use Bdsa\Wafy\Models\WafyEvent;
use Bdsa\Wafy\Models\BannedIp;

class StatsReport extends Command
{
    protected $signature = 'wafy:stats {--days=7 : Fenêtre en jours} {--top=10 : Nombre d\'entrées par palmarès} {--json : Sortie JSON}';
    protected $description = 'Rapport statistique des détections Wafy (nécessite wafy.stats.enabled).';

    public function handle()
    {
        if (!config('wafy.stats.enabled', false)) {
            $this->warn('wafy.stats.enabled = false : aucune donnée collectée. Activez-le pour enregistrer les événements.');
        }

        $days = max(1, (int) $this->option('days'));
        $top = max(1, (int) $this->option('top'));
        $since = now()->subDays($days);

        try {
            $base = WafyEvent::where('created_at', '>=', $since);

            $total = (clone $base)->count();
            $byEvent = (clone $base)->get(['event'])->groupBy('event')->map->count();
            $topRules = $this->topRuleIds(clone $base, $top);
            $topPaths = $this->topColumn(clone $base, 'path', $top);
            $topCountries = $this->topColumn((clone $base)->whereNotNull('country'), 'country', $top);
            $activeBans = BannedIp::count();
        } catch (\Throwable $e) {
            $this->error('Lecture des stats impossible (migration wafy_events publiée/exécutée ?) : ' . $e->getMessage());
            return 1;
        }

        $report = [
            'window_days' => $days,
            'since' => $since->toIso8601String(),
            'total_events' => $total,
            'by_event' => $byEvent->all(),
            'active_bans' => $activeBans,
            'top_rules' => $topRules,
            'top_paths' => $topPaths,
            'top_countries' => $topCountries,
        ];

        if ($this->option('json')) {
            $this->line(json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            return 0;
        }

        $this->info("Wafy — {$total} détection(s) sur {$days} jour(s), {$activeBans} ban(s) actif(s).");
        $this->line('Par type : ' . collect($byEvent->all())->map(fn ($n, $e) => "{$e}={$n}")->implode('  '));
        $this->renderTable('Top règles', $topRules);
        $this->renderTable('Top chemins', $topPaths);
        $this->renderTable('Top pays', $topCountries);

        return 0;
    }

    private function topRuleIds($query, int $top): array
    {
        $counts = [];
        foreach ($query->get(['rule_ids']) as $row) {
            foreach ((array) $row->rule_ids as $id) {
                $id = (string) $id;
                $counts[$id] = ($counts[$id] ?? 0) + 1;
            }
        }
        arsort($counts);

        return array_slice($counts, 0, $top, true);
    }

    private function topColumn($query, string $column, int $top): array
    {
        $counts = [];
        foreach ($query->get([$column]) as $row) {
            $key = (string) $row->{$column};
            if ($key === '') {
                continue;
            }
            $counts[$key] = ($counts[$key] ?? 0) + 1;
        }
        arsort($counts);

        return array_slice($counts, 0, $top, true);
    }

    private function renderTable(string $title, array $counts): void
    {
        if (empty($counts)) {
            return;
        }
        $this->line('');
        $this->line("<comment>{$title}</comment>");
        $rows = [];
        foreach ($counts as $key => $n) {
            $rows[] = [$key, $n];
        }
        $this->table(['', 'count'], $rows);
    }
}
