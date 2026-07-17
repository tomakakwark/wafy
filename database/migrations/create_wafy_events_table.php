<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        if (Schema::hasTable('wafy_events')) {
            return; // idempotent
        }

        Schema::create('wafy_events', function (Blueprint $table) {
            $table->id();
            $table->string('ip_identity', 64)->index();          // IPv4 or /prefix-collapsed IPv6
            $table->string('event', 16)->index();                // 'blocked' | 'banned' | 'logged'
            $table->text('rule_ids')->nullable();                // JSON array (text for sqlite/old-MySQL parity)
            $table->unsignedSmallInteger('score')->default(0);
            $table->string('path', 512)->nullable();
            $table->char('country', 2)->nullable();              // ISO alpha-2; null = unknown
            $table->timestamp('created_at')->nullable()->index(); // append-only, no updated_at
        });
    }

    public function down()
    {
        Schema::dropIfExists('wafy_events');
    }
};
