<?php

namespace Bdsa\Wafy\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Notifications\Notifiable;

class BannedIp extends Model
{
    use Notifiable;

    protected $table = 'wafy_banned_ips';

    // Champs remplissables pour les entrées dans la base de données
    protected $fillable = ['ip_address', 'banned_until', 'reason', 'request_data'];

    protected $casts = [
        'request_data' => 'array',
        'banned_until' => 'datetime',
    ];

    public function routeNotificationForMail($notification)
    {
        return config('wafy.notifications.email');
    }

    public function routeNotificationForSlack($notification)
    {
        return config('wafy.notifications.slack_webhook');
    }
}