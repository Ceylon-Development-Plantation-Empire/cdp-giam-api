<?php

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\Auth\SimpleJwtService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateGiamSessionOrBearer
{
    /**
     * Authenticate request via either Bearer JWT or Web Session cookie.
     */
    public function handle(Request $request, Closure $next): Response
    {
        // 1. Check Bearer Token
        $bearer = $request->bearerToken();
        if (! $bearer && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            if (preg_match('/Bearer\s+(\S+)/i', $_SERVER['HTTP_AUTHORIZATION'], $matches)) {
                $bearer = $matches[1];
            }
        }
        if (! $bearer && function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
            $authHeader = $headers['Authorization'] ?? $headers['authorization'] ?? null;
            if ($authHeader && preg_match('/Bearer\s+(\S+)/i', $authHeader, $matches)) {
                $bearer = $matches[1];
            }
        }

        if ($bearer) {
            $userId = SimpleJwtService::validateToken($bearer);
            if ($userId) {
                $user = User::find($userId);
                if ($user && (! $user->lockout_until || ! $user->lockout_until->isFuture())) {
                    Auth::guard('web')->setUser($user);
                    Auth::setUser($user);
                    $request->setUserResolver(fn () => $user);
                    return $next($request);
                }
            }

            // Explicit Bearer token was provided but failed validation (invalid, expired, revoked, or locked out).
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        // 2. Check Web Session
        if (Auth::guard('web')->check()) {
            $user = Auth::guard('web')->user();
            if ($user && (! $user->lockout_until || ! $user->lockout_until->isFuture())) {
                // CSRF Protection for state-changing HTTP requests using session cookies:
                // Simple requests (HTML forms / un-preflighted requests) cannot set custom headers or JSON payloads.
                if (in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
                    $hasSecurityHeader = $request->hasHeader('X-Requested-With')
                        || $request->hasHeader('X-CSRF-TOKEN')
                        || $request->hasHeader('X-XSRF-TOKEN');

                    if (! $hasSecurityHeader && ! $request->isJson()) {
                        return response()->json(['message' => 'CSRF verification failed: missing security header.'], 403);
                    }
                }
                $request->setUserResolver(fn () => $user);
                return $next($request);
            }
            Auth::guard('web')->logout();
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }

        return response()->json(['message' => 'Unauthenticated.'], 401);
    }
}
