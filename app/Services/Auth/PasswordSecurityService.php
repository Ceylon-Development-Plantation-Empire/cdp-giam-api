<?php

namespace App\Services\Auth;

use App\Mail\PasswordResetLinkMail;
use App\Models\PasswordResetToken;
use App\Models\User;
use App\Services\Audit\AuditLoggerService;
use App\Services\Sync\DataProjectionService;
use Exception;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Service governing password policy enforcement, cryptographically secure
 * temporary password generation, and self-service password reset tokens.
 */
class PasswordSecurityService
{
    public function __construct(
        protected AuditLoggerService $auditLogger,
        protected DataProjectionService $projectionService
    ) {}

    /**
     * Generate a cryptographically secure temporary password satisfying password policy.
     *
     * @return string
     */
    public function generateTemporaryPassword(): string
    {
        // Generate a 16-character password with letters, numbers, and symbols
        $pwd = Str::password(16, letters: true, numbers: true, symbols: true, spaces: false);

        // Ensure all policy requirements are strictly satisfied
        if (! preg_match('/[A-Z]/', $pwd)) {
            $pwd .= 'A';
        }
        if (! preg_match('/[a-z]/', $pwd)) {
            $pwd .= 'a';
        }
        if (! preg_match('/[0-9]/', $pwd)) {
            $pwd .= '9';
        }
        if (! preg_match('/[^A-Za-z0-9]/', $pwd)) {
            $pwd .= '@';
        }

        return $pwd;
    }

    /**
     * Authoritative backend validation of password policy:
     * Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 digit, 1 special character.
     *
     * @param string $password
     * @return void
     * @throws HttpException
     */
    public function enforcePasswordPolicy(string $password): void
    {
        if (strlen($password) < 8) {
            throw new HttpException(422, 'Password must be at least 8 characters long.');
        }
        if (! preg_match('/[A-Z]/', $password)) {
            throw new HttpException(422, 'Password must contain at least one uppercase letter.');
        }
        if (! preg_match('/[a-z]/', $password)) {
            throw new HttpException(422, 'Password must contain at least one lowercase letter.');
        }
        if (! preg_match('/[0-9]/', $password)) {
            throw new HttpException(422, 'Password must contain at least one number.');
        }
        if (! preg_match('/[^A-Za-z0-9]/', $password)) {
            throw new HttpException(422, 'Password must contain at least one special character.');
        }
    }

    /**
     * Request a self-service password reset.
     * Guaranteed enumeration-safe: public response does not leak existence or reset-restricted state.
     *
     * @param string $identifier
     * @param string|null $ip
     * @return array<string, string>
     */
    public function requestSelfServiceReset(string $identifier, ?string $ip = null): array
    {
        $user = User::where('username', $identifier)
            ->orWhere('email', $identifier)
            ->first();

        // If user exists and can perform self-service reset (< 3 resets)
        if ($user && $user->is_active && $user->can_login) {
            if ($user->self_service_reset_count < 3) {
                // Invalidate all previous active reset tokens for this user
                PasswordResetToken::where('user_id', $user->id)->delete();

                // Generate raw token and store its SHA-256 hash
                $rawToken = bin2hex(random_bytes(32));
                $tokenHash = hash('sha256', $rawToken);

                PasswordResetToken::create([
                    'user_id' => $user->id,
                    'token_hash' => $tokenHash,
                    'expires_at' => now()->addMinutes(15),
                    'created_at' => now(),
                ]);

                // Send email if real mail configuration is provided (never log token)
                $this->sendResetEmailSafe($user, $rawToken);

                $this->auditLogger->log(
                    action: 'USER_PASSWORD_RESET_REQUESTED',
                    entityType: 'User',
                    entityId: (string) $user->id,
                    actorUserId: null,
                    metadata: ['ip' => $ip]
                );
            }
        }

        // Always return enumeration-safe message
        return [
            'status' => 'success',
            'message' => 'If a valid account matches that identifier, password reset instructions have been dispatched.',
        ];
    }

    /**
     * Redeem a self-service password reset token.
     * Transactional single-use token redemption with row locking.
     *
     * @param string $rawToken
     * @param string $newPassword
     * @param string|null $ip
     * @return User
     * @throws HttpException
     */
    public function redeemResetToken(string $rawToken, string $newPassword, ?string $ip = null): User
    {
        $this->enforcePasswordPolicy($newPassword);

        $tokenHash = hash('sha256', $rawToken);

        return DB::transaction(function () use ($tokenHash, $newPassword, $ip) {
            // Lock and retrieve token record
            $tokenRecord = PasswordResetToken::where('token_hash', $tokenHash)
                ->lockForUpdate()
                ->first();

            if (! $tokenRecord) {
                throw new HttpException(422, 'Invalid or expired password reset token.');
            }

            if ($tokenRecord->expires_at < now()) {
                $tokenRecord->delete();
                throw new HttpException(422, 'Password reset token has expired. Please request a new reset.');
            }

            $user = User::where('id', $tokenRecord->user_id)
                ->lockForUpdate()
                ->firstOrFail();

            if (! $user->is_active || ! $user->can_login) {
                $tokenRecord->delete();
                throw new HttpException(403, 'Account is inactive or login disabled.');
            }

            // Immediately destroy the token (single use)
            $tokenRecord->delete();

            // Enforce lifetime 3-reset cap
            if ($user->self_service_reset_count >= 3) {
                throw new HttpException(422, 'Self-service password reset limit reached. Please request administrator assistance.');
            }

            // Increment reset count, update password, clear must_change_password
            $user->self_service_reset_count += 1;
            $user->password = Hash::make($newPassword);
            $user->must_change_password = false;
            $user->password_changed_at = now();
            $user->failed_login_attempts = 0;
            $user->lockout_until = null;
            $user->save();

            $this->auditLogger->log(
                action: 'USER_PASSWORD_RESET_SELF_SERVICE',
                entityType: 'User',
                entityId: (string) $user->id,
                actorUserId: $user->id,
                metadata: [
                    'ip' => $ip,
                    'self_service_reset_count' => $user->self_service_reset_count,
                ]
            );

            // Trigger credential verifier projection to active projects
            $this->projectionService->syncCredentialChange($user, $user->password);

            // Revoke all existing JWTs for this user across all sessions
            \App\Services\Auth\SimpleJwtService::revokeAllForUser($user->id);

            return $user;
        });
    }

    /**
     * Safely dispatch reset email without leaking secrets into logs if unconfigured.
     */
    protected function sendResetEmailSafe(User $user, string $rawToken): void
    {
        $frontendUrl = config('app.frontend_url') ?? env('FRONTEND_URL', 'http://localhost:3000');
        $resetUrl = "{$frontendUrl}/reset-password?token={$rawToken}";

        try {
            // Check if mail credentials configured
            if (config('mail.default') === 'smtp' && empty(config('mail.mailers.smtp.username'))) {
                // Outlook delivery blocked by configuration - do not log token
                return;
            }

            Mail::to($user->email)->send(new PasswordResetLinkMail($user, $resetUrl));
        } catch (Exception $e) {
            // Silently swallow external transport failure to avoid breaking user flow or leaking token to logs
        }
    }
}
