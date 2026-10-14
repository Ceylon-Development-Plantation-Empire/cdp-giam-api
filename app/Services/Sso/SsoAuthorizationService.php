<?php

namespace App\Services\Sso;

use App\Models\Project;
use App\Models\ProjectIntegration;
use App\Models\SsoAuthCode;
use App\Models\User;
use App\Models\UserProjectAccess;
use App\Services\Audit\AuditLoggerService;
use App\Services\Sync\DataProjectionService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Service orchestrating OAuth2/OIDC SSO authorization code issuance,
 * PKCE S256 verification, and downstream token exchange with dual-key rate limiting.
 *
 * Authorization codes are persisted in the MySQL `sso_auth_codes` table via the
 * SsoAuthCode Eloquent model. Only the SHA-256 hash (`code_hash`) is stored;
 * the raw authorization code is never stored in the database. Codes have a 60-second TTL
 * and are bound to user_id, project_id, and redirect_uri.
 *
 * Single-use redemption is protected by a database transaction with exclusive row-level
 * locking (`lockForUpdate()`), guaranteeing atomic check-and-consume and eliminating
 * concurrent double-redemption race conditions.
 */
class SsoAuthorizationService
{
    public function __construct(
        protected DataProjectionService $dataProjectionService,
        protected AuditLoggerService $auditLogger
    ) {}

    /**
     * Issue a single-use, 60-second authorization code with PKCE S256 challenge.
     * Persists SHA-256 hash into MySQL `sso_auth_codes` bound to user, project, and redirect_uri.
     * Raw 64-character code is returned transiently for browser redirection only.
     *
     * @param User $user
     * @param int $projectId
     * @param string $redirectUri
     * @param string|null $codeChallenge
     * @param string|null $codeChallengeMethod
     * @param string|null $state
     * @return array<string, mixed>
     * @throws HttpException
     */
    public function issueAuthorizationCode(
        User $user,
        int $projectId,
        string $redirectUri,
        ?string $codeChallenge = null,
        ?string $codeChallengeMethod = 'S256',
        ?string $state = null
    ): array {
        // 1. Validate user and linked employee active status
        if (! $user->is_active || ! $user->can_login) {
            throw new HttpException(403, 'User account is deactivated or login is disabled.');
        }

        if ($user->employee && ! $user->employee->is_active) {
            throw new HttpException(403, 'Employee record is inactive.');
        }

        // 2. Strict PKCE method validation: Only S256 allowed if code challenge is provided
        if ($codeChallenge !== null && $codeChallengeMethod !== 'S256') {
            throw \Illuminate\Validation\ValidationException::withMessages([
                'code_challenge_method' => ["Only the 'S256' code challenge method is permitted."],
            ]);
        }
        if ($codeChallenge === null) {
            $codeChallengeMethod = null;
        }

        // 3. Project status & SSO enablement
        $project = Project::with('integration')->findOrFail($projectId);
        if ($project->status !== 'active') {
            throw new HttpException(422, "Project [{$project->code}] is not active.");
        }

        if (! $project->integration || ! $project->integration->sso_enabled) {
            throw new HttpException(422, "SSO is not enabled for project [{$project->code}].");
        }

        // 4. Exact match against pre-registered redirect_uris allowlist
        $allowedUris = $project->integration->redirect_uris ?? [];
        if (! in_array($redirectUri, $allowedUris, true)) {
            throw \Illuminate\Validation\ValidationException::withMessages([
                'redirect_uri' => ['The specified redirect_uri is not authorized for this project.'],
            ]);
        }

        // 5. Verify user has ACTIVE project access
        $access = UserProjectAccess::where('user_id', $user->id)
            ->where('project_id', $project->id)
            ->first();

        if (! $access || $access->status !== 'ACTIVE') {
            $status = $access ? $access->status : 'NOT_ASSIGNED';
            throw new HttpException(403, "Access denied: User does not have ACTIVE access to project [{$project->code}]. Current status: {$status}.");
        }

        // 6. Generate single-use authorization code
        $code = Str::random(64);
        $codeHash = hash('sha256', $code);

        SsoAuthCode::create([
            'code_hash' => $codeHash,
            'user_id' => $user->id,
            'project_id' => $project->id,
            'redirect_uri' => $redirectUri,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
            'expires_at' => now()->addSeconds(60),
            'used_at' => null,
        ]);

        $this->auditLogger->log(
            action: 'SSO_CODE_ISSUED',
            entityType: 'SsoAuthCode',
            entityId: $codeHash,
            beforeData: null,
            afterData: [
                'user_id' => $user->id,
                'project_id' => $project->id,
                'redirect_uri' => $redirectUri,
                'expires_at' => now()->addSeconds(60)->toIso8601String(),
            ],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $user->id
        );

        $separator = str_contains($redirectUri, '?') ? '&' : '?';
        $redirectUrl = $redirectUri . $separator . 'code=' . urlencode($code) . ($state !== null ? '&state=' . urlencode($state) : '');

        return [
            'authorization_code' => $code,
            'redirect_url' => $redirectUrl,
            'expires_in' => 60,
        ];
    }

    /**
     * Exchange an authorization code for project-scoped identity and tokens.
     * Authenticates downstream project client credentials, looks up authorization code
     * by SHA-256 hash in MySQL `sso_auth_codes`, verifies 60s expiration, validates
     * PKCE S256 challenge, burns code via `used_at = now()`, and projects user attributes.
     *
     * @param string $code
     * @param string|null $codeVerifier
     * @param string $clientId
     * @param string $clientSecret
     * @param string $clientIp
     * @return array<string, mixed>
     * @throws HttpException
     */
    public function exchangeCodeForToken(
        string $code,
        ?string $codeVerifier = null,
        string $clientId,
        string $clientSecret,
        string $clientIp
    ): array {
        $ipLockoutKey = "sso_token_lockout:ip:{$clientId}:{$clientIp}";
        $clientLockoutKey = "sso_token_lockout:client:{$clientId}";

        // 1. Dual-Key Lockout check: 5 attempts per IP or 10 attempts globally per client_id in 15 mins
        if (RateLimiter::tooManyAttempts($ipLockoutKey, 5)) {
            $seconds = RateLimiter::availableIn($ipLockoutKey);
            throw new HttpException(429, "Too many failed authentication attempts from this IP. Locked out for {$seconds} seconds.");
        }

        if (RateLimiter::tooManyAttempts($clientLockoutKey, 10)) {
            $seconds = RateLimiter::availableIn($clientLockoutKey);
            throw new HttpException(429, "Too many failed authentication attempts for client ID [{$clientId}]. Locked out for {$seconds} seconds.");
        }

        // 2. Authenticate downstream project client (supporting rotation grace period)
        $integration = ProjectIntegration::with('project')
            ->where('client_id', $clientId)
            ->first();

        $activeSecret = $integration?->getDecryptedClientSecret();
        $isPrimaryMatch = $activeSecret !== null && hash_equals((string) $activeSecret, $clientSecret);
        $isPreviousMatch = false;

        if (! $isPrimaryMatch && $integration && $integration->hasActivePreviousSecret()) {
            $prevSecret = $integration->getDecryptedPreviousClientSecret();
            if ($prevSecret !== null && hash_equals((string) $prevSecret, $clientSecret)) {
                $isPreviousMatch = true;
            }
        }

        if (! $integration || (! $isPrimaryMatch && ! $isPreviousMatch)) {
            RateLimiter::hit($ipLockoutKey, 900);
            RateLimiter::hit($clientLockoutKey, 900);
            throw new HttpException(401, 'Invalid client credentials.');
        }

        $project = $integration->project;

        // 3. Atomically check and consume authorization code within a locked transaction
        $codeHash = hash('sha256', $code);
        $burnAndReject = null;

        [$user, $access] = DB::transaction(function () use (
            $codeHash,
            $project,
            $codeVerifier,
            $ipLockoutKey,
            $clientLockoutKey,
            &$burnAndReject
        ) {
            // Retrieve matching SsoAuthCode with exclusive row-level lock
            $authCode = SsoAuthCode::with(['user.employee'])
                ->where('code_hash', $codeHash)
                ->where('project_id', $project->id)
                ->lockForUpdate()
                ->first();

            if (! $authCode) {
                RateLimiter::hit($ipLockoutKey, 900);
                RateLimiter::hit($clientLockoutKey, 900);
                throw new HttpException(400, 'Invalid authorization code.');
            }

            // Check single-use
            if ($authCode->used_at !== null) {
                RateLimiter::hit($ipLockoutKey, 900);
                RateLimiter::hit($clientLockoutKey, 900);
                throw new HttpException(400, 'Authorization code has already been redeemed.');
            }

            // Check expiry (60s TTL)
            if ($authCode->expires_at->isPast()) {
                RateLimiter::hit($ipLockoutKey, 900);
                RateLimiter::hit($clientLockoutKey, 900);
                throw new HttpException(400, 'Authorization code has expired.');
            }

            // 4. PKCE RFC 7636 Verification if code_challenge was provided at authorization time
            if (! empty($authCode->code_challenge)) {
                $computedChallenge = rtrim(strtr(base64_encode(hash('sha256', (string) $codeVerifier, true)), '+/', '-_'), '=');
                if (! hash_equals((string) $authCode->code_challenge, $computedChallenge)) {
                    RateLimiter::hit($ipLockoutKey, 900);
                    RateLimiter::hit($clientLockoutKey, 900);
                    throw new HttpException(400, 'PKCE code_verifier verification failed.');
                }
            }

            // 5. Re-validate user_project_access status = ACTIVE at redemption time
            $access = UserProjectAccess::with(['roles', 'permissions'])
                ->where('user_id', $authCode->user_id)
                ->where('project_id', $authCode->project_id)
                ->first();

            // Mark code used under the exclusive row lock
            $authCode->update(['used_at' => now()]);

            if (! $access || $access->status !== 'ACTIVE') {
                $status = $access ? $access->status : 'REVOKED';
                $burnAndReject = new HttpException(403, "Redemption rejected: User access to [{$project->code}] is no longer ACTIVE ({$status}).");

                return [null, null];
            }

            return [$authCode->user, $access];
        });

        if ($burnAndReject !== null) {
            throw $burnAndReject;
        }

        RateLimiter::clear($ipLockoutKey);
        RateLimiter::clear($clientLockoutKey);

        // 6. Project user profile and roles strictly through DataProjectionService
        $projectedProfile = $this->dataProjectionService->project(
            user: $user,
            project: $project,
            roleIds: $access->roles->pluck('id')->toArray(),
            permissionIds: $access->permissions->pluck('id')->toArray()
        );

        $this->auditLogger->log(
            action: 'SSO_TOKEN_EXCHANGED',
            entityType: 'SsoAuthCode',
            entityId: $codeHash,
            beforeData: null,
            afterData: [
                'user_id' => $user->id,
                'project_id' => $project->id,
                'client_id' => $clientId,
            ],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $user->id
        );

        return [
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'user' => $projectedProfile,
        ];
    }

    /**
     * Handle project logout telemetry. Project sessions are decoupled; GIAM session remains intact.
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $externalRef
     * @param string|null $sessionId
     * @return array<string, string>
     * @throws HttpException
     */
    public function handleLogoutTelemetry(
        string $clientId,
        string $clientSecret,
        string $externalRef,
        ?string $sessionId = null
    ): array {
        $integration = ProjectIntegration::with('project')
            ->where('client_id', $clientId)
            ->first();

        if (! $integration || ! hash_equals((string) $integration->getDecryptedClientSecret(), $clientSecret)) {
            throw new HttpException(401, 'Invalid project credentials for logout telemetry.');
        }

        $this->auditLogger->log(
            action: 'SSO_LOGOUT_TELEMETRY',
            entityType: 'ProjectSession',
            entityId: $externalRef,
            beforeData: null,
            afterData: [
                'project' => $integration->project->code,
                'external_ref' => $externalRef,
                'session_id' => $sessionId,
            ],
            status: 'SUCCESS',
            projectId: $integration->project_id,
            actorUserId: null
        );

        return [
            'status' => 'acknowledged',
            'message' => 'Project session termination telemetry logged. GIAM master session preserved.',
        ];
    }
}
