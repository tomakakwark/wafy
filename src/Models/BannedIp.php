<?php

namespace Bdsa\Wafy\Models;

use Illuminate\Database\Eloquent\Model;

class BannedIp extends Model
{
    protected $table = 'wafy_banned_ips';

    // Champs remplissables pour les entrées dans la base de données
    protected $fillable = ['ip_address', 'banned_until', 'reason', 'request_data'];

    protected $casts = [
        'request_data' => 'array',
        'banned_until' => 'datetime',
    ];
}