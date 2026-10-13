<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\UserProjectAccess;
use App\Services\Audit\AuditLoggerService;
use App\Services\Auth\AuthenticationService;
use App\Services\Auth\PasswordResetAssistanceService;
use App\Services\Auth\PasswordSecurityService;
use App\Services\Integration\ProjectClientFactory;
use App\Services\Sync\DataProjectionService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function __construct(
        protected AuthenticationService $authService,
        protected AuditLoggerService $auditLogger,
        protected ProjectClientFactory $clientFactory,
        protected PasswordSecurityService $securityService,
        protected PasswordResetAssistanceService $assistanceService,
        protected DataProjectionService $projectionService
    ) {}

    public function login(LoginRequest $request): JsonResponse
    {
        $user = $this->authService->login(
            login: $request->input('login'),
            password: $request->input('password'),
            request: $request,
            remember: (bool) $request->input('remember', false)
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Login successful.',
            'data' => [
                'user' => [
                    'id' => $user->id,
                    'employee_code' => $user->employee_code,
                    'name' => $user->name,
                    'username' => $user->username,
                    'email' => $user->email,
                    'user_type' => $user->user_type,
                    'is_active' => $user->is_active,
                    'can_login' => $user->can_login,
                    'must_change_password' => (bool) $user->must_change_password,
                    'self_service_reset_count' => (int) $user->self_service_reset_count,
                    'last_login_at' => $user->last_login_at?->toIso8601String(),
                ],
                'employee' => $user->employee ? [
                    'id' => $user->employee->id,
                    'employee_code' => $user->employee->employee_code,
                    'full_name' => $user->employee->full_name,
                    'name_with_initials' => $user->employee->name_with_initials,
                    'employee_type' => $user->employee->employee_type,
                    'department_code' => $user->employee->department_code,
                    'designation_code' => $user->employee->designation_code,
                    'branch_code' => $user->employee->branch_code,
                ] : null,
                'roles' => $user->roles->pluck('name')->toArray(),
                'permissions' => $user->getAllPermissions()->pluck('name')->toArray(),
                'modules' => $user->getAllPermissions()->map(fn ($p) => $p->permissionGroup?->module?->code)->filter()->unique()->values()->toArray(),
                'token' => \App\Services\Auth\SimpleJwtService::generateToken($user),
                'token_type' => 'Bearer',
            ],
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        $bearer = $request->bearerToken();
        if (! $bearer && isset($_SERVER['HTTP_AUTHORIZATION'])) {
            if (preg_match('/Bearer\s+(\S+)/i', $_SERVER['HTTP_AUTHORIZATION'], $matches)) {
                $bearer = $matches[1];
            }
        }
        if ($bearer) {
            $revoked = \App\Services\Auth\SimpleJwtService::revokeToken($bearer);
            if (! $revoked) {
                Log::error('Logout token revocation failed to persist in shared revocation store.');
            }
        }

        $this->authService->logout($request);

        return response()->json([
            'status' => 'success',
            'message' => 'Successfully logged out.',
        ]);
    }

    public function me(Request $request): JsonResponse
    {
        $user = $request->user()->load(['employee', 'roles.permissions']);

        return response()->json([
            'status' => 'success',
            'data' => [
                'user' => [
                    'id' => $user->id,
                    'employee_code' => $user->employee_code,
                    'name' => $user->name,
                    'username' => $user->username,
                    'email' => $user->email,
                    'user_type' => $user->user_type,
                    'is_active' => $user->is_active,
                    'can_login' => $user->can_login,
                    'must_change_password' => (bool) $user->must_change_password,
                    'self_service_reset_count' => (int) $user->self_service_reset_count,
                    'last_login_at' => $user->last_login_at?->toIso8601String(),
                ],
                'employee' => $user->employee ? [
                    'id' => $user->employee->id,
                    'employee_code' => $user->employee->employee_code,
                    'full_name' => $user->employee->full_name,
                    'name_with_initials' => $user->employee->name_with_initials,
                    'employee_type' => $user->employee->employee_type,
                    'department_code' => $user->employee->department_code,
                    'designation_code' => $user->employee->designation_code,
                    'branch_code' => $user->employee->branch_code,
                ] : null,
                'roles' => $user->roles->pluck('name')->toArray(),
                'permissions' => $user->getAllPermissions()->pluck('name')->toArray(),
                'modules' => $user->getAllPermissions()->map(fn ($p) => $p->permissionGroup?->module?->code)->filter()->unique()->values()->toArray(),
            ],
        ]);
    }

    public function changePassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'new_password' => 'required|string|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        $user = $request->user();

        if (! Hash::check($request->input('current_password'), $user->password)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Current password does not match our records.',
            ], 422);
        }

        // Authoritatively enforce password policy
        $this->securityService->enforcePasswordPolicy($request->input('new_password'));

        // Hash and update GIAM master credential
        $newHash = Hash::make($request->input('new_password'));
        $user->password = $newHash;
        $user->must_change_password = false;
        $user->password_changed_at = now();
        $user->failed_login_attempts = 0;
        $user->lockout_until = null;
        $user->save();

        // Safe audit log (ZERO passwords or verifiers logged)
        $this->auditLogger->log(
            action: 'USER_PASSWORD_CHANGED',
            entityType: 'User',
            entityId: (string) $user->id,
            beforeData: null,
            afterData: ['user_id' => $user->id, 'action' => 'credential_updated'],
            status: 'SUCCESS',
            actorUserId: $user->id
        );
        // Propagate updated bcrypt verifier to downstream projects
        $this->projectionService->syncCredentialChange($user, $newHash);

        // Revoke all existing JWTs for this user across all sessions
        \App\Services\Auth\SimpleJwtService::revokeAllForUser($user->id);

        return response()->json([
            'status' => 'success',
            'message' => 'Password updated successfully.',
        ]);
    }

    /**
     * POST /api/v1/auth/forgot-password
     * Public self-service password reset request (enumeration-safe).
     */
    public function forgotPassword(Request $request): JsonResponse
    {
        $identifier = $request->input('login') ?? $request->input('email') ?? $request->input('username');
        if (! $identifier || ! is_string($identifier)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Username or email identifier is required.',
            ], 422);
        }

        $result = $this->securityService->requestSelfServiceReset($identifier, $request->ip());

        return response()->json($result);
    }

    /**
     * POST /api/v1/auth/reset-password
     * Redeem a self-service password reset token.
     */
    public function resetPassword(Request $request): JsonResponse
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required|string',
            'password' => 'required|string|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => 'error',
                'message' => 'Validation failed',
                'errors' => $validator->errors(),
            ], 422);
        }

        $this->securityService->redeemResetToken(
            rawToken: $request->input('token'),
            newPassword: $request->input('password'),
            ip: $request->ip()
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Password reset successfully. You may now login with your new password.',
        ]);
    }

    /**
     * POST /api/v1/auth/password-reset-assistance
     * Public assistance request when self-service reset limit is reached (enumeration-safe).
     */
    public function requestAssistance(Request $request): JsonResponse
    {
        $identifier = $request->input('login') ?? $request->input('email') ?? $request->input('username');
        if (! $identifier || ! is_string($identifier)) {
            return response()->json([
                'status' => 'error',
                'message' => 'Username or email identifier is required.',
            ], 422);
        }

        $result = $this->assistanceService->submitRequest($identifier, $request->ip());

        return response()->json($result);
    }

    public function myProjects(Request $request): JsonResponse
    {
        $user = $request->user();

        // Return only ACTIVE assigned projects for the authenticated user
        $accesses = UserProjectAccess::with([
            'project.integration',
            'project.modules',
            'roles',
            'permissions',
        ])
            ->where('user_id', $user->id)
            ->where('status', 'ACTIVE')
            ->get();

        $projects = $accesses->map(function ($access) {
            $project = $access->project;
            $integration = $project->integration;

            $redirectUris = $integration?->redirect_uris ?? [];
            $launchUrl = ! empty($redirectUris) ? $redirectUris[0] : null;

            // Resolved assigned roles
            $assignedRoles = $access->roles->map(fn ($r) => [
                'id' => $r->id,
                'name' => $r->name,
                'code' => $r->code,
                'description' => $r->description,
                'is_active' => (bool) $r->is_active,
            ])->values()->toArray();

            // Downstream project modules (for reference)
            $modules = $project->modules->map(fn ($m) => [
                'id' => $m->id,
                'code' => $m->code,
                'name' => $m->name,
                'description' => $m->description,
            ])->values()->toArray();

            // Directly assigned permissions (fine-grained overrides)
            $directPerms = $access->permissions->map(fn ($p) => [
                'id' => $p->id,
                'name' => $p->name,
                'code' => $p->code,
                'is_granted' => (bool) ($p->pivot->is_granted ?? true),
            ])->values()->toArray();

            return [
                'id' => $project->id,
                'code' => $project->code,
                'name' => $project->name,
                'description' => $project->description,
                'status' => $project->status,
                'access_status' => $access->status,
                'launch_url' => $launchUrl,
                'sso_enabled' => (bool) ($integration?->sso_enabled ?? false),
                'roles' => $assignedRoles,
                'modules' => $modules,
                'permission_groups' => [], // Do not fabricate local role-to-permission mapping from catalog
                'permissions' => $directPerms,
                'assigned_roles_count' => count($assignedRoles),
                'direct_permission_overrides_count' => count($directPerms),
                'modules_count' => count($modules),
                'roles_count' => count($assignedRoles),
                'permissions_count' => count($directPerms),
            ];
        });

        return response()->json([
            'status' => 'success',
            'data' => $projects,
        ]);
    }
}
