<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class ProjectIntegrationResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'project_id' => $this->project_id,
            'api_base_url' => $this->api_base_url,
            'auth_method' => $this->auth_method,
            'client_id' => $this->client_id,
            // SECURITY: Never return raw credentials to client/browser
            'has_client_secret' => ! empty($this->encrypted_client_secret),
            'has_previous_secret' => $this->hasActivePreviousSecret(),
            'previous_secret_expires_at' => $this->previous_secret_expires_at?->toIso8601String(),
            'redirect_uris' => $this->redirect_uris ?? [],
            'allowed_user_fields' => $this->allowed_user_fields,
            'sync_enabled' => $this->sync_enabled,
            'sso_enabled' => $this->sso_enabled,
            'status' => $this->status,
            'verification_status' => $this->verification_status ?? 'unverified',
            'verification_error' => $this->verification_error,
            'last_verified_at' => $this->last_verified_at?->toIso8601String(),
            'last_health_check_at' => $this->last_health_check_at?->toIso8601String(),
            'last_sync_catalog_at' => $this->last_sync_catalog_at?->toIso8601String(),
            'created_at' => $this->created_at?->toIso8601String(),
            'updated_at' => $this->updated_at?->toIso8601String(),
        ];
    }
}
