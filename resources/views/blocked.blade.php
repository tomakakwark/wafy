<!doctype html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title>{{ $status ?? 403 }}</title>
    <style>
        :root { color-scheme: light dark; }
        * { box-sizing: border-box; }
        body {
            margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background: #0f1115; color: #e6e6e6; padding: 1.5rem;
        }
        @media (prefers-color-scheme: light) { body { background: #f5f6f8; color: #1a1a1a; } }
        .card {
            max-width: 30rem; width: 100%; text-align: center;
            border: 1px solid rgba(127,127,127,.25); border-radius: 14px;
            padding: 2.5rem 2rem; background: rgba(127,127,127,.06);
        }
        .code { font-size: 3rem; font-weight: 700; letter-spacing: .05em; margin: 0 0 .25rem; }
        .msg { font-size: 1.05rem; opacity: .85; margin: 0; }
        .foot { margin-top: 1.75rem; font-size: .78rem; opacity: .5; }
    </style>
</head>
<body>
    <div class="card">
        <p class="code">{{ $status ?? 403 }}</p>
        <p class="msg">{{ $message ?? 'Request blocked.' }}</p>
        <p class="foot">Protected by Wafy</p>
    </div>
</body>
</html>
