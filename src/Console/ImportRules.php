<?php

namespace Bdsa\Wafy\Console;

use Illuminate\Console\Command;

class ImportRules extends Command
{
    protected $signature = 'wafy:rules:import
        {source : chemin d\'un fichier .php|.json|.txt}
        {--pack=imported : préfixe d\'id des règles importées}
        {--score=3 : score par défaut si la source n\'en fournit pas}
        {--severity= : severity par défaut (info|low|medium|high|critical)}
        {--fields= : restreindre à des sujets (liste séparée par des virgules)}
        {--replace : remplacer le fichier importé au lieu de fusionner}
        {--allow-php : autoriser une source .php (elle est EXÉCUTÉE via require)}
        {--dry-run : afficher sans écrire}';

    protected $description = 'Importer des règles de détection depuis un fichier externe (.php/.json/.txt).';

    public function handle()
    {
        $source = (string) $this->argument('source');
        if (!is_file($source) || !is_readable($source)) {
            $this->error('Source introuvable : ' . $source);
            return 1;
        }

        // A .php source is EXECUTED (require) to read its array — refuse unless
        // the operator explicitly acknowledges it. Prefer .json/.txt for untrusted input.
        if (strtolower(pathinfo($source, PATHINFO_EXTENSION)) === 'php' && !$this->option('allow-php')) {
            $this->error('Une source .php est exécutée (require). Confirmez avec --allow-php, ou convertissez en .json/.txt.');
            return 1;
        }

        $raw = $this->parseSource($source);
        if ($raw === null) {
            $this->error('Format non reconnu ou source vide.');
            return 1;
        }

        $defaultScore = max(1, (int) $this->option('score'));
        $severity = (string) $this->option('severity');
        $fields = array_values(array_filter(array_map('trim', explode(',', (string) $this->option('fields')))));
        $prefix = preg_replace('/[^A-Za-z0-9._-]/', '', (string) $this->option('pack'));
        if ($prefix === '') {
            $prefix = 'imported';
        }

        $imported = [];
        $skipped = 0;
        $i = 0;
        foreach ($raw as $entry) {
            $rule = $this->normalizeIncoming($entry, $prefix, $i, $defaultScore, $severity, $fields);
            if ($rule === null) {
                $skipped++;
                continue;
            }
            $imported[$rule['id']] = $rule;
            $i++;
        }

        if (empty($imported)) {
            $this->error('Aucune règle valide (' . $skipped . ' ignorée(s)).');
            return 1;
        }

        $path = config('wafy.imported_rules_path');
        if (!is_string($path) || $path === '') {
            $path = storage_path('app/wafy/imported-rules.php');
        }

        $existing = [];
        if (!$this->option('replace') && is_file($path)) {
            foreach ((array) $this->readArray($path) as $r) {
                if (is_array($r) && isset($r['id'])) {
                    $existing[(string) $r['id']] = $r;
                }
            }
        }
        $merged = array_merge($existing, $imported); // incoming wins on id

        if ($this->option('dry-run')) {
            $this->info(count($imported) . ' valide(s), ' . $skipped . ' ignorée(s). Total fusionné : ' . count($merged) . ' (dry-run).');
            return 0;
        }

        if (!$this->writeRulesFile($path, array_values($merged))) {
            $this->error('Écriture échouée : ' . $path);
            return 1;
        }

        $this->info(count($imported) . ' importée(s), ' . $skipped . ' ignorée(s). Fichier : ' . $path);
        $this->line('Activez-les avec wafy.imported_rules_path (défaut) — elles sont chargées automatiquement.');
        return 0;
    }

    private function parseSource(string $file): ?array
    {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));

        if ($ext === 'php') {
            $data = $this->readArray($file);
            return is_array($data) ? $data : null;
        }
        if ($ext === 'json') {
            $data = json_decode((string) @file_get_contents($file), true);
            return is_array($data) ? $data : null;
        }

        // .txt (or anything else): one regex per line, '#' comments ignored.
        $out = [];
        foreach (preg_split('/\r\n|\r|\n/', (string) @file_get_contents($file)) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $out[] = $line;
        }

        return empty($out) ? null : $out;
    }

    private function readArray(string $path)
    {
        try {
            $data = require $path;
        } catch (\Throwable $e) {
            return null;
        }

        return is_array($data) ? $data : null;
    }

    private function normalizeIncoming($entry, string $prefix, int $i, int $score, string $sev, array $fields): ?array
    {
        if (is_string($entry)) {
            $pattern = $this->ensureRegex($entry);
            $id = $prefix . '.' . $i;
        } elseif (is_array($entry) && !empty($entry['pattern'])) {
            $pattern = $this->ensureRegex((string) $entry['pattern']);
            $id = isset($entry['id']) ? (string) $entry['id'] : $prefix . '.' . $i;
            if (isset($entry['score'])) {
                $score = max(1, (int) $entry['score']);
            }
        } else {
            return null;
        }

        if ($pattern === null || @preg_match($pattern, '') === false) {
            return null; // invalid regex skipped
        }

        $rule = ['id' => $id, 'score' => $score, 'pattern' => $pattern];
        if ($sev !== '') {
            $rule['severity'] = $sev;
        }
        if (!empty($fields)) {
            $rule['fields'] = $fields;
        }

        return $rule;
    }

    private function ensureRegex(string $p): ?string
    {
        $p = trim($p);
        if ($p === '') {
            return null;
        }
        // Already delimited (e.g. /.../i, #...#, ~...~)?
        if (preg_match('/^([\/#~%]).*\1[imsxuADSUXJ]*$/s', $p)) {
            return $p;
        }

        return '/' . str_replace('/', '\/', $p) . '/i'; // wrap a bare pattern
    }

    private function writeRulesFile(string $path, array $rules): bool
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }

        $body = "<?php\n\n// Généré par wafy:rules:import — ne pas éditer à la main.\n\nreturn "
            . var_export(array_values($rules), true) . ";\n";

        return @file_put_contents($path, $body) !== false;
    }
}
