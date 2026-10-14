<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('project_integrations', function (Blueprint $table) {
            if (! Schema::hasColumn('project_integrations', 'previous_encrypted_client_secret')) {
                $table->text('previous_encrypted_client_secret')
                    ->nullable()
                    ->after('encrypted_client_secret')
                    ->comment('Encrypted previous client secret preserved during rotation grace window.');
            }

            if (! Schema::hasColumn('project_integrations', 'previous_secret_expires_at')) {
                $table->timestamp('previous_secret_expires_at')
                    ->nullable()
                    ->after('previous_encrypted_client_secret')
                    ->comment('Expiration timestamp for the previous secret grace period.');
            }

            if (! Schema::hasColumn('project_integrations', 'verification_status')) {
                $table->enum('verification_status', ['unverified', 'verified', 'failed'])
                    ->default('unverified')
                    ->after('status')
                    ->comment('Operational health and contract verification state.');
            }

            if (! Schema::hasColumn('project_integrations', 'verification_error')) {
                $table->text('verification_error')
                    ->nullable()
                    ->after('verification_status')
                    ->comment('Last verification probe error message if probe failed.');
            }

            if (! Schema::hasColumn('project_integrations', 'last_verified_at')) {
                $table->timestamp('last_verified_at')
                    ->nullable()
                    ->after('verification_error')
                    ->comment('Timestamp of the most recent active contract verification probe.');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('project_integrations', function (Blueprint $table) {
            $columnsToDrop = [];
            foreach ([
                'previous_encrypted_client_secret',
                'previous_secret_expires_at',
                'verification_status',
                'verification_error',
                'last_verified_at',
            ] as $col) {
                if (Schema::hasColumn('project_integrations', $col)) {
                    $columnsToDrop[] = $col;
                }
            }

            if (! empty($columnsToDrop)) {
                $table->dropColumn($columnsToDrop);
            }
        });
    }
};
