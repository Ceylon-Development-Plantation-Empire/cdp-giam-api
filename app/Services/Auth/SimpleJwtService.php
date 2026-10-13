<?php

namespace App\Services\Auth;

use App\Models\User;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * Service generating and validating signed HS256 JWTs for GIAM Principals
 * using APP_KEY with server-side revocation registry support.
 */
class SimpleJwtService
{
    /**
     * Generate a signed HS256 JWT for the GIAM Principal.
     *
     * @param User $user
     * @param int $ttlSeconds
     * @return string
     */
    public static function generateToken(User $user, int $ttlSeconds = 86400): string
    {
        $now = microtime(true);
        $header = self::base64UrlEncode(json_encode([
            'alg' => 'HS256',
            'typ' => 'JWT',
        ]));

        $payload = self::base64UrlEncode(json_encode([
            'iss' => config('app.url', 'http://127.0.0.1:8000'),
            'sub' => $user->id,
            'username' => $user->username,
            'employee_code' => $user->employee_code,
            'jti' => bin2hex(random_bytes(16)),
            'iat' => (int) floor($now),
            'iat_v' => $now,
            'exp' => (int) floor($now) + $ttlSeconds,
        ]));

        $secret = config('app.key');
        $signature = self::base64UrlEncode(hash_hmac('sha256', "{$header}.{$payload}", $secret, true));

        return "{$header}.{$payload}.{$signature}";
    }

    /**
     * Validate and decode a signed HS256 JWT. Returns User ID if valid and unrevoked.
     *
     * @param string $token
     * @return int|null
     */
    public static function validateToken(string $token): ?int
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return null;
        }

        [$headerB64, $payloadB64, $sigB64] = $parts;

        $secret = config('app.key');
        $expectedSig = self::base64UrlEncode(hash_hmac('sha256', "{$headerB64}.{$payloadB64}", $secret, true));

        if (! hash_equals($expectedSig, $sigB64)) {
            return null;
        }

        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        if (! $payload || ! isset($payload['sub'], $payload['exp'])) {
            return null;
        }

        if (time() > $payload['exp']) {
            return null;
        }

        // Check if individual token has been revoked
        $jti = isset($payload['jti']) && is_string($payload['jti']) && trim($payload['jti']) !== ''
            ? trim($payload['jti'])
            : null;
        $tokenId = $jti ?? hash('sha256', $sigB64);

        try {
            // Guard against insecure isolated cache driver in production
            if (app()->environment('production') && in_array(config('cache.default'), ['file', 'array', null], true)) {
                Log::critical('Insecure local cache store configured in production: ' . config('cache.default') . '. Refusing token validation to prevent isolated revocation bypass.');
                return null;
            }

            if (Cache::has("giam_jwt_revoked:{$tokenId}")) {
                return null;
            }

            // Check if user has a global revocation event issued after this token's creation
            $userRevokedAt = Cache::get("giam_jwt_revoked_user:{$payload['sub']}");
            if ($userRevokedAt !== null) {
                $tokenIssuedAt = (float) ($payload['iat_v'] ?? $payload['iat'] ?? 0);
                if ((float) $userRevokedAt >= $tokenIssuedAt) {
                    return null;
                }
            }
        } catch (\Throwable $e) {
            Log::error('JWT revocation store check failed: ' . $e->getMessage());
            // Fail-secure: Cannot guarantee token is unrevoked if store check fails; deny authentication
            return null;
        }

        return (int) $payload['sub'];
    }

    /**
     * Revoke a specific token by adding its ID to the revocation cache for its remaining lifetime.
     *
     * @param string $token
     * @return bool
     */
    public static function revokeToken(string $token): bool
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            return false;
        }

        [$headerB64, $payloadB64, $sigB64] = $parts;

        $payload = json_decode(self::base64UrlDecode($payloadB64), true);
        if (! $payload || ! isset($payload['exp'])) {
            return false;
        }

        $remainingTtl = max(60, (int) ($payload['exp'] - time()));
        $jti = isset($payload['jti']) && is_string($payload['jti']) && trim($payload['jti']) !== ''
            ? trim($payload['jti'])
            : null;
        $tokenId = $jti ?? hash('sha256', $sigB64);

        try {
            Cache::put("giam_jwt_revoked:{$tokenId}", true, $remainingTtl);
            return true;
        } catch (\Throwable $e) {
            Log::error('Failed to revoke JWT in cache: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Revoke all active tokens for a specific user (e.g. on logout-all, password change, deactivation).
     *
     * @param int|string $userId
     * @param int $ttlSeconds Window to reject older tokens (default 24 hours)
     * @return bool
     */
    public static function revokeAllForUser(int|string $userId, int $ttlSeconds = 86400): bool
    {
        try {
            Cache::put("giam_jwt_revoked_user:{$userId}", microtime(true), $ttlSeconds);
            return true;
        } catch (\Throwable $e) {
            Log::error('Failed to revoke all user JWTs in cache: ' . $e->getMessage());
            return false;
        }
    }

    public static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64UrlDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', 3 - (3 + strlen($data)) % 4));
    }
}
