<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Facades\Crypt;

class ProjectIntegration extends Model
{
    use HasFactory;

    /**
     * Permitted projection fields for external project integrations.
     */
    public const VALID_PROJECTION_FIELDS = [
        'employee_code',
        'f_name',
        'l_name',
        'full_name',
        'name_with_initials',
        'id_type',
        'id_number',
        'date_of_birth',
        'email',
        'phone',
        'phone_primary',
        'phone_secondary',
        'address_line_1',
        'city',
        'state',
        'country',
        'postal_code',
        'department_code',
        'designation_code',
        'reporting_manager_code',
        'start_date',
        'end_date',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'project_id',
        'api_base_url',
        'auth_method',
        'client_id',
        'client_secret',
        'encrypted_client_secret',
        'redirect_uris',
        'allowed_user_fields',
        'allowed_resources',
        'allowed_resource_fields',
        'sync_enabled',
        'sso_enabled',
        'status',
        'previous_encrypted_client_secret',
        'previous_secret_expires_at',
        'verification_status',
        'verification_error',
        'last_verified_at',
        'last_health_check_at',
        'last_sync_catalog_at',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'encrypted_client_secret',
        'previous_encrypted_client_secret',
        'client_secret',
    ];

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'redirect_uris' => 'array',
            'allowed_user_fields' => 'array',
            'allowed_resources' => 'array',
            'allowed_resource_fields' => 'array',
            'sync_enabled' => 'boolean',
            'sso_enabled' => 'boolean',
            'previous_secret_expires_at' => 'datetime',
            'last_verified_at' => 'datetime',
            'last_health_check_at' => 'datetime',
            'last_sync_catalog_at' => 'datetime',
        ];
    }

    /**
     * Get the project associated with this integration configuration.
     */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class, 'project_id');
    }

    /**
     * Encrypt and store the client secret integration credential.
     */
    public function setClientSecretAttribute(?string $value): void
    {
        $this->attributes['encrypted_client_secret'] = $value ? Crypt::encryptString($value) : null;
    }

    /**
     * Decrypt and retrieve the plaintext integration credential for outbound requests.
     */
    public function getDecryptedClientSecret(): ?string
    {
        if (empty($this->encrypted_client_secret)) {
            return null;
        }

        try {
            return Crypt::decryptString($this->encrypted_client_secret);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Decrypt and retrieve the previous client secret during rotation grace period.
     */
    public function getDecryptedPreviousClientSecret(): ?string
    {
        if (empty($this->previous_encrypted_client_secret)) {
            return null;
        }

        try {
            return Crypt::decryptString($this->previous_encrypted_client_secret);
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * Determine if a previous secret is currently active within its grace period.
     */
    public function hasActivePreviousSecret(): bool
    {
        return ! empty($this->previous_encrypted_client_secret)
            && $this->previous_secret_expires_at !== null
            && $this->previous_secret_expires_at->isFuture();
    }
}
