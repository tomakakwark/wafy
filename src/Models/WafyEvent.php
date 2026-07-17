<?php

namespace Bdsa\Wafy\Models;

use Illuminate\Database\Eloquent\Model;

class WafyEvent extends Model
{
    protected $table = 'wafy_events';

    public $timestamps = false; // single created_at, append-only

    protected $fillable = ['ip_identity', 'event', 'rule_ids', 'score', 'path', 'country', 'created_at'];

    protected $casts = [
        'rule_ids' => 'array',
        'score' => 'integer',
        'created_at' => 'datetime',
    ];
}
