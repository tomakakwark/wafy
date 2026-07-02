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

    /**
     * Scope a query to a given IP address.
     */
    public function scopeForIp($query, string $ip)
    {
        return $query->where('ip_address', $ip);
    }

    /**
     * Whether this ban is currently in force (permanent, or not yet expired).
     */
    public function isActive(): bool
    {
        return is_null($this->banned_until) || now()->lessThan($this->banned_until);
    }

    public function routeNotificationForMail($notification)
    {
        return config('wafy.notifications.email');
    }

    public function routeNotificationForSlack($notification)
    {
        return config('wafy.notifications.slack_webhook');
    }
}