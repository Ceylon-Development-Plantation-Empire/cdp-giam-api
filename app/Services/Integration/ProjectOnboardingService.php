<?php

namespace App\Services\Integration;

use App\Exceptions\IntegrationActivationException;
use App\Models\Project;
use App\Models\ProjectIntegration;
use App\Models\SyncJob;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use RuntimeException;

/**
 * Generic, capability-driven service for onboarding, registering, and managing downstream projects.
 *
 * This service is the single standard for:
 *   1. Operational dynamic project onboarding via REST API & UI
 *   2. CLI project onboarding (php artisan giam:onboard-project {code})
 *   3. Fresh-environment and CI bootstrap seeding (ProjectRegistrySeeder)
 *
 * SECURITY INVARIANTS:
 * - Never supports hardcoded plaintext credentials.
 * - Resolves required credentials from environment-backed configuration keys when present.
 * - Encrypts all client secrets at rest using authenticated cryptography.
 * - Never logs, dumps, serializes, or exposes secret values in standard responses.
 * - Strictly transactional and idempotent.
 */
class ProjectOnboardingService
{
    /**
     * Register project catalog metadata without requiring credentials.
     */
    public function registerProject(array $data): Project
    {
        $code = strtolower(trim((string) ($data['code'] ?? '')));

        if (empty($code)) {
            throw new InvalidArgumentException('Project code is required.');
        }

        return Project::updateOrCreate(
            ['code' => $code],
            [
                'name' => (string) ($data['name'] ?? ucfirst($code)),
                'description' => $data['description'] ?? null,
                'base_url' => rtrim((string) ($data['base_url'] ?? ''), '/'),
                'icon_url' => $data['icon_url'] ?? null,
                'status' => (string) ($data['status'] ?? 'active'),
            ]
        );
    }

    /**
     * Configure endpoints and capabilities for a project integration.
     */
    public function configureIntegration(Project $project, array $data): ProjectIntegration
    {
        $existing = $project->integration;

        $defaultUserFields = ProjectIntegration::VALID_PROJECTION_FIELDS;

        $updateData = [
            'api_base_url' => (string) ($data['api_base_url'] ?? ($project->base_url ? $project->base_url . '/api/giam/integration' : '')),
            'auth_method' => (string) ($data['auth_method'] ?? ($existing?->auth_method ?? 'bearer_token')),
            'sync_enabled' => (bool) ($data['sync_enabled'] ?? ($existing?->sync_enabled ?? false)),
            'sso_enabled' => (bool) ($data['sso_enabled'] ?? ($existing?->sso_enabled ?? false)),
            'status' => (string) ($data['status'] ?? ($existing?->status ?? 'offline')),
            'allowed_user_fields' => $data['allowed_user_fields'] ?? ($existing?->allowed_user_fields ?? $defaultUserFields),
            'redirect_uris' => $data['redirect_uris'] ?? ($existing?->redirect_uris ?? []),
        ];

        if (array_key_exists('client_id', $data)) {
            $updateData['client_id'] = $data['client_id'] !== null ? trim((string) $data['client_id']) : null;
        }

        if (! empty($data['client_secret'])) {
            $updateData['encrypted_client_secret'] = Crypt::encryptString(trim((string) $data['client_secret']));
        } elseif (array_key_exists('client_secret', $data) && $data['client_secret'] === null) {
            $updateData['encrypted_client_secret'] = null;
        }

        if (array_key_exists('allowed_resources', $data)) {
            $updateData['allowed_resources'] = $data['allowed_resources'];
        }

        if (array_key_exists('allowed_resource_fields', $data)) {
            $updateData['allowed_resource_fields'] = $data['allowed_resource_fields'];
        }

        return ProjectIntegration::updateOrCreate(
            ['project_id' => $project->id],
            $updateData
        );
    }

    /**
     * Provision cryptographically secure client ID and secret for a project.
     * Returns the plaintext secret ONCE for administrative one-time display.
     *
     * @return array{client_id: string, client_secret: string}
     */
    public function provisionCredentials(Project $project, ?string $clientId = null, ?string $clientSecret = null): array
    {
        $integration = $project->integration ?? ProjectIntegration::create([
            'project_id' => $project->id,
            'api_base_url' => $project->base_url ? $project->base_url . '/api/giam/integration' : '',
            'status' => 'offline',
            'auth_method' => 'bearer_token',
            'sync_enabled' => false,
            'sso_enabled' => false,
            'allowed_user_fields' => ProjectIntegration::VALID_PROJECTION_FIELDS,
            'redirect_uris' => [],
        ]);

        $finalClientId = ! empty($clientId) ? trim($clientId) : 'giam_' . str_replace('-', '_', $project->code) . '_' . bin2hex(random_bytes(4));
        $finalClientSecret = ! empty($clientSecret) ? trim($clientSecret) : bin2hex(random_bytes(32));

        $integration->client_id = $finalClientId;
        $integration->setClientSecretAttribute($finalClientSecret);
        $integration->save();

        return [
            'client_id' => $finalClientId,
            'client_secret' => $finalClientSecret,
        ];
    }

    /**
     * Rotate project client secret with a 24-hour zero-downtime transition grace period.
     *
     * @param Project $project
     * @param int $gracePeriodHours Hours previous secret remains valid for SSO code exchanges (default: 24)
     * @return array{client_id: string, client_secret: string, grace_period_hours: int, previous_secret_expires_at: ?string}
     */
    public function rotateCredentials(Project $project, int $gracePeriodHours = 24): array
    {
        $integration = $project->integration;

        if (! $integration || empty($integration->client_id)) {
            throw new RuntimeException("Cannot rotate credentials for project [{$project->code}]: No credentials provisioned.");
        }

        $newSecret = bin2hex(random_bytes(32));

        // Preserve current active secret into transition slot with grace expiration
        $currentEncrypted = $integration->encrypted_client_secret;
        if (! empty($currentEncrypted)) {
            $integration->previous_encrypted_client_secret = $currentEncrypted;
            $integration->previous_secret_expires_at = now()->addHours($gracePeriodHours);
        }

        $integration->setClientSecretAttribute($newSecret);
        $integration->save();

        return [
            'client_id' => (string) $integration->client_id,
            'client_secret' => $newSecret,
            'grace_period_hours' => $gracePeriodHours,
            'previous_secret_expires_at' => $integration->previous_secret_expires_at?->toIso8601String(),
        ];
    }

    /**
     * Immediately revoke the previous rotated secret after downstream configuration is confirmed.
     */
    public function revokePreviousSecret(Project $project): bool
    {
        $integration = $project->integration;

        if ($integration) {
            $integration->update([
                'previous_encrypted_client_secret' => null,
                'previous_secret_expires_at' => null,
            ]);
        }

        return true;
    }

    /**
     * Revoke client credentials for a project integration.
     */
    public function revokeCredentials(Project $project): bool
    {
        $integration = $project->integration;

        if ($integration) {
            $integration->update([
                'client_id' => null,
                'encrypted_client_secret' => null,
                'previous_encrypted_client_secret' => null,
                'previous_secret_expires_at' => null,
                'sync_enabled' => false,
                'sso_enabled' => false,
                'status' => 'offline',
            ]);
        }

        return true;
    }

    /**
     * Actively verify downstream project connectivity and authentication contract.
     *
     * @return array{verified: bool, status: string, verification_status: string, latency_ms: ?int, http_status: ?int, error: ?string}
     */
    public function verifyIntegration(Project $project): array
    {
        $healthService = app(ProjectHealthCheckService::class);
        $result = $healthService->check($project);

        $isHealthy = ($result['status'] ?? '') === 'healthy';

        return [
            'verified' => $isHealthy,
            'status' => $isHealthy ? 'verified' : 'failed',
            'verification_status' => $isHealthy ? 'verified' : 'failed',
            'latency_ms' => $result['latency_ms'] ?? null,
            'http_status' => $result['http_status'] ?? null,
            'error' => $isHealthy ? null : ($result['error'] ?? 'Health probe failed'),
        ];
    }

    /**
     * Validate and activate a project integration.
     *
     * @throws IntegrationActivationException When required configuration or credentials are missing.
     */
    public function activateIntegration(Project $project): ProjectIntegration
    {
        $integration = $project->integration;

        if (! $integration) {
            throw new IntegrationActivationException("Cannot activate integration for [{$project->code}]: No integration configured.");
        }

        $missing = [];
        if (empty($integration->api_base_url)) {
            $missing[] = 'api_base_url';
        }

        if (in_array($integration->auth_method, ['bearer_token', 'oauth2', 'hmac'])) {
            if (empty($integration->client_id)) {
                $missing[] = 'client_id';
            }
            if (empty($integration->encrypted_client_secret)) {
                $missing[] = 'client_secret';
            }
        }

        if (! empty($missing)) {
            throw new IntegrationActivationException(
                "Cannot activate integration for [{$project->code}]: Missing required configuration: " . implode(', ', $missing),
                $missing
            );
        }

        $integration->update([
            'status' => 'healthy',
            'sso_enabled' => true,
            'sync_enabled' => true,
        ]);

        // Wake up any deferred or pending sync jobs for this project so they execute immediately
        SyncJob::where('project_id', $project->id)
            ->whereIn('status', ['PENDING', 'RETRYING'])
            ->update([
                'next_retry_at' => now(),
            ]);

        return $integration->fresh();
    }

    /**
     * Deactivate a project integration.
     */
    public function deactivateIntegration(Project $project): ProjectIntegration
    {
        $integration = $project->integration;

        if ($integration) {
            $integration->update([
                'status' => 'offline',
                'sso_enabled' => false,
                'sync_enabled' => false,
            ]);
        }

        return $integration?->fresh() ?? new ProjectIntegration();
    }

    /**
     * Onboard or update a single approved downstream project and its integration.
     *
     * @param string $code Canonical project code (e.g. credix, stockly, centrix)
     * @param bool $strict When true, throws RuntimeException if declared required credentials are missing.
     *                     When false (used by ProjectRegistrySeeder), registers the project and leaves
     *                     unconfigured integrations inactive without throwing.
     * @return Project The freshly persisted project model with its integration loaded
     *
     * @throws InvalidArgumentException When the project code is not in config/projects.php
     * @throws RuntimeException When required integration credentials are unavailable and strict mode is on.
     */
    public function onboard(string $code, bool $strict = true): Project
    {
        $normalizedCode = strtolower(trim($code));

        $definition = config("projects.definitions.{$normalizedCode}");

        if (empty($definition) || ! is_array($definition)) {
            throw new InvalidArgumentException(
                "Unknown or unapproved project code: [{$normalizedCode}]. " .
                "Only approved projects registered in config/projects.php can be onboarded."
            );
        }

        // 1. Resolve project core attributes generically
        $baseUrl = $this->resolveBaseUrl($definition);

        $projectData = [
            'name' => (string) ($definition['name'] ?? ucfirst($normalizedCode)),
            'description' => $definition['description'] ?? null,
            'base_url' => $baseUrl,
            'icon_url' => $definition['icon_url'] ?? null,
            'status' => (string) ($definition['status'] ?? 'active'),
        ];

        // 2. Resolve project integration attributes generically
        $integ = $definition['integration'] ?? [];

        $apiUrl = $this->resolveApiUrl($integ);
        $clientId = $this->resolveClientId($integ);
        $clientSecret = $this->resolveClientSecret($integ);

        // Check required environment-backed credentials
        $hasRequiredCredentials = $this->checkRequiredCredentials($integ, $clientId, $clientSecret);

        if (! $hasRequiredCredentials) {
            if ($strict) {
                // In strict mode (CLI explicit onboarding or strict activation), throw missing key exception
                $this->validateRequiredCredentials($integ, $clientId, $clientSecret);
            }
        }

        $redirectUris = $this->resolveRedirectUris($integ, $baseUrl);

        // Determine activation state
        $syncEnabled = (bool) ($integ['sync_enabled'] ?? false);
        $ssoEnabled = (bool) ($integ['sso_enabled'] ?? false);
        $status = (string) ($integ['status'] ?? 'healthy');

        $existingProject = Project::where('code', $normalizedCode)->first();
        $existingInteg = $existingProject?->integration;

        // If credentials are required by the integration auth_method but not present in environment/config,
        // do not mark the integration active/healthy during non-strict seeding unless already configured in DB!
        $requiresCredentials = in_array((string) ($integ['auth_method'] ?? 'bearer_token'), ['bearer_token', 'oauth2', 'hmac']);
        if ($requiresCredentials && ! $hasRequiredCredentials) {
            if ($existingInteg && ! empty($existingInteg->client_id)) {
                $clientId = $existingInteg->client_id;
                $status = $existingInteg->status;
                $syncEnabled = (bool) $existingInteg->sync_enabled;
                $ssoEnabled = (bool) $existingInteg->sso_enabled;
            } else {
                $syncEnabled = false;
                $ssoEnabled = false;
                $status = 'offline';
            }
        }

        $integrationData = [
            'api_base_url' => $apiUrl,
            'auth_method' => (string) ($integ['auth_method'] ?? 'bearer_token'),
            'status' => $status,
            'sync_enabled' => $syncEnabled,
            'sso_enabled' => $ssoEnabled,
        ];

        if ($clientId !== null) {
            $integrationData['client_id'] = $clientId;
        } elseif (! $existingInteg || empty($existingInteg->client_id)) {
            $integrationData['client_id'] = null;
        }

        if ($clientSecret !== null) {
            $integrationData['client_secret'] = $clientSecret;
        }

        if ($redirectUris !== null) {
            $integrationData['redirect_uris'] = $redirectUris;
        }

        if (array_key_exists('allowed_user_fields', $integ)) {
            $integrationData['allowed_user_fields'] = $integ['allowed_user_fields'];
        }

        if (array_key_exists('allowed_resources', $integ)) {
            $integrationData['allowed_resources'] = $integ['allowed_resources'];
        }

        if (array_key_exists('allowed_resource_fields', $integ)) {
            $integrationData['allowed_resource_fields'] = $integ['allowed_resource_fields'];
        }

        // 3. Persist atomically inside database transaction
        return DB::transaction(function () use ($normalizedCode, $projectData, $integrationData) {
            $project = Project::updateOrCreate(
                ['code' => $normalizedCode],
                $projectData
            );

            ProjectIntegration::updateOrCreate(
                ['project_id' => $project->id],
                $integrationData
            );

            return $project->fresh('integration');
        });
    }

    /**
     * Check if all declared required credentials are present.
     */
    protected function checkRequiredCredentials(array $integ, ?string $clientId, ?string $clientSecret): bool
    {
        $required = $integ['required_credentials'] ?? [];

        if (empty($required) || ! is_array($required)) {
            return true;
        }

        foreach ($required as $field => $credentialIdentifier) {
            $value = match ($field) {
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                default => null,
            };

            if (empty($value) || trim((string) $value) === '') {
                return false;
            }
        }

        return true;
    }

    /**
     * Resolve the base URL for the project.
     */
    protected function resolveBaseUrl(array $definition): string
    {
        if (! empty($definition['base_url_config_key'])) {
            $configured = config($definition['base_url_config_key']);
            if (! empty($configured)) {
                return rtrim((string) $configured, '/');
            }
            return (string) ($definition['base_url_fallback'] ?? '');
        }

        return (string) ($definition['base_url'] ?? '');
    }

    /**
     * Resolve the integration API base URL.
     */
    protected function resolveApiUrl(array $integ): string
    {
        if (! empty($integ['api_url_config_key'])) {
            $configured = config($integ['api_url_config_key']);
            if (! empty($configured)) {
                return (string) $configured;
            }
            return (string) ($integ['api_base_url_fallback'] ?? '');
        }

        return (string) ($integ['api_base_url'] ?? '');
    }

    /**
     * Resolve client ID from configuration reference key or direct null.
     */
    protected function resolveClientId(array $integ): ?string
    {
        if (! empty($integ['client_id_config_key'])) {
            $configured = config($integ['client_id_config_key']);
            return ! empty($configured) ? trim((string) $configured) : null;
        }

        return array_key_exists('client_id', $integ) && $integ['client_id'] !== null
            ? trim((string) $integ['client_id'])
            : null;
    }

    /**
     * Resolve client secret from configuration reference key or direct null.
     */
    protected function resolveClientSecret(array $integ): ?string
    {
        if (! empty($integ['client_secret_config_key'])) {
            $configured = config($integ['client_secret_config_key']);
            return ! empty($configured) ? trim((string) $configured) : null;
        }

        return array_key_exists('client_secret', $integ) && $integ['client_secret'] !== null
            ? trim((string) $integ['client_secret'])
            : null;
    }

    /**
     * Resolve redirect URIs, replacing {base_url} placeholders when present.
     */
    protected function resolveRedirectUris(array $integ, string $baseUrl): ?array
    {
        if (! empty($integ['redirect_uris_patterns']) && is_array($integ['redirect_uris_patterns'])) {
            $trimmedBase = rtrim($baseUrl, '/');
            return array_map(function (string $uri) use ($trimmedBase) {
                return str_replace('{base_url}', $trimmedBase, $uri);
            }, $integ['redirect_uris_patterns']);
        }

        if (array_key_exists('redirect_uris', $integ)) {
            return $integ['redirect_uris'];
        }

        return null;
    }

    /**
     * Validate that all declared required credentials are present.
     *
     * SECURITY NOTE: Never logs or prints resolved credential values; only identifies missing key names.
     */
    protected function validateRequiredCredentials(array $integ, ?string $clientId, ?string $clientSecret): void
    {
        $required = $integ['required_credentials'] ?? [];

        if (empty($required) || ! is_array($required)) {
            return;
        }

        foreach ($required as $field => $credentialIdentifier) {
            $value = match ($field) {
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                default => null,
            };

            if (empty($value) || trim((string) $value) === '') {
                throw new RuntimeException("Missing required integration credential: [{$credentialIdentifier}]");
            }
        }
    }
}
