<!DOCTYPE html>
<html>

<head>
    <title>Wafy Alert: IP Banned</title>
</head>

<body>
    <h1>Wafy Alert</h1>
    <p>A malicious request was detected and the following IP has been banned:</p>

    <ul>
        <li><strong>IP Address:</strong> {{ $ip }}</li>
        <li><strong>Reason:</strong> {{ $reason ?? 'N/A' }}</li>
        <li><strong>Time:</strong> {{ now() }}</li>
    </ul>

    <h3>Request Data:</h3>
    <pre>{{ json_encode($request_data ?? [], JSON_PRETTY_PRINT) }}</pre>

    <p>Please review the logs for more details.</p>
</body>

</html>