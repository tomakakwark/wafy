<?php

namespace Bdsa\Wafy\Models;

use Illuminate\Database\Eloquent\Model;

class BannedIp extends Model
{
    protected $table = 'banned_ips';

    // Champs remplissables pour les entrées dans la base de données
    protected $fillable = ['ip_address','banned_until'];
}
