<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        if (!Schema::hasColumn('wafy_banned_ips', 'offense_count')) {
            Schema::table('wafy_banned_ips', function (Blueprint $table) {
                $table->unsignedInteger('offense_count')->default(0)->after('banned_until');
            });
        }
    }

    public function down()
    {
        if (Schema::hasColumn('wafy_banned_ips', 'offense_count')) {
            Schema::table('wafy_banned_ips', function (Blueprint $table) {
                $table->dropColumn('offense_count');
            });
        }
    }
};
