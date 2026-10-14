<?php

namespace App\Services\User;

use App\Mail\NewAccountCredentialsMail;
use App\Models\Employee;
use App\Models\Role;
use App\Models\User;
use App\Services\Access\ProjectAccessAssignmentService;
use App\Services\Audit\AuditLoggerService;
use App\Services\Auth\PasswordSecurityService;
use App\Services\Integration\ProjectClientFactory;
use App\Services\Rbac\PermissionGrantAuthorityService;
use App\Services\Sync\DataProjectionService;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * Service governing employee lifecycle, principal provisioning, internal Spatie RBAC assignment,
 * privilege escalation prevention, and transient credential delivery.
 */
class UserCreationService
{
    public function __construct(
        protected AuditLoggerService $auditLogger,
        protected ProjectAccessAssignmentService $projectAccessService,
        protected ProjectClientFactory $clientFactory,
        protected PasswordSecurityService $securityService,
        protected DataProjectionService $dataProjectionService,
        protected PermissionGrantAuthorityService $grantAuthorityService
    ) {}

    /**
     * Create an employee master record and optionally provision a linked GIAM Principal account.
     *
     * @param array<string, mixed> $data
     * @param User|null $actor
     * @return Employee
     * @throws HttpException
     */
    public function createEmployee(array $data, ?User $actor = null): Employee
    {
        $createdUser = null;
        $createdUserPassword = null;

        $employee = DB::transaction(function () use ($data, $actor, &$createdUser, &$createdUserPassword) {
            $employeeData = collect($data)->except([
                'create_user_account',
                'username',
                'password',
                'user_type',
                'can_login',
                'roles',
                'project_access',
                'requested_project_name',
                'nature_of_role',
            ])->toArray();

            $employee = Employee::create($employeeData);

            // Atomically create ProjectAccessRequest if provided by HR
            if (! empty($data['requested_project_name']) && ! empty($data['nature_of_role'])) {
                $submitterId = $actor ? $actor->id : \App\Models\User::first()?->id;
                if (! $submitterId) {
                    throw new \RuntimeException('Cannot submit project access request without an authenticated user.');
                }

                \App\Models\ProjectAccessRequest::create([
                    'employee_id' => $employee->id,
                    'requested_project_name' => trim($data['requested_project_name']),
                    'nature_of_role' => trim($data['nature_of_role']),
                    'status' => 'PENDING',
                    'submitted_by_user_id' => $submitterId,
                ]);
            }

            $this->auditLogger->log(
                action: 'EMPLOYEE_CREATED',
                entityType: 'Employee',
                entityId: $employee->employee_code,
                beforeData: null,
                afterData: $employee->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            // If requested, provision linked login account
            if (! empty($data['create_user_account'])) {
                if (! $actor || ! $actor->hasPermissionTo('USER_CREATE', 'web')) {
                    throw new HttpException(403, 'Forbidden: You do not have permission to create user login accounts.');
                }

                $roles = $data['roles'] ?? [];
                if (empty($roles)) {
                    throw new HttpException(422, 'A valid GIAM internal role must be explicitly selected.');
                }

                $targetRoles = Role::whereIn('name', $roles)->where('guard_name', 'web')->with('permissions')->get();
                if ($targetRoles->count() !== count($roles)) {
                    throw new HttpException(422, 'One or more selected GIAM internal roles are invalid or do not exist.');
                }

                $this->grantAuthorityService->validateRoleAssignment($actor, $targetRoles);

                $rawPassword = $data['password'] ?? $this->securityService->generateTemporaryPassword();
                $userType = $data['user_type'] ?? 'staff';

                $user = User::create([
                    'employee_code' => $employee->employee_code,
                    'name' => $employee->full_name,
                    'username' => $data['username'] ?? strtolower($employee->employee_code),
                    'email' => $employee->email,
                    'password' => Hash::make($rawPassword),
                    'user_type' => $userType,
                    'is_active' => $employee->is_active ?? true,
                    'can_login' => $data['can_login'] ?? true,
                    'must_change_password' => true,
                    'password_changed_at' => now(),
                ]);

                $user->syncRoles($roles);

                $createdUser = $user;
                $createdUserPassword = $rawPassword;

                $this->auditLogger->log(
                    action: 'USER_CREATED',
                    entityType: 'User',
                    entityId: (string) $user->id,
                    beforeData: null,
                    afterData: $user->toArray(),
                    status: 'SUCCESS',
                    actorUserId: $actor?->id
                );

                // Phase B: Persist Project Access Assignments if provided
                if (! empty($data['project_access']) && is_array($data['project_access'])) {
                    if ($actor && ! $actor->hasPermissionTo('ACCESS_ASSIGN', 'web')) {
                        throw new HttpException(403, 'Forbidden: You do not have permission to assign project access.');
                    }

                    foreach ($data['project_access'] as $projectId => $assignments) {
                        $roleIds = $assignments['roles'] ?? [];
                        $permIds = $assignments['permissions'] ?? [];
                        if (! empty($roleIds) || ! empty($permIds)) {
                            $this->projectAccessService->assignAccess(
                                user: $user,
                                projectId: (int) $projectId,
                                roleIds: $roleIds,
                                permissionIds: $permIds,
                                actor: $actor ?? $user
                            );
                        }
                    }
                }
            }

            return $employee->load('user');
        });

        // After DB transaction commits: Deliver credential email safely outside transaction boundary
        if ($createdUser && $createdUserPassword) {
            $this->sendNewAccountEmailSafe($createdUser, $createdUserPassword, $actor);
        }

        return $employee;
    }

    /**
     * Update an employee record, synchronize linked user attributes, and trigger downstream project syncs.
     *
     * @param Employee $employee
     * @param array<string, mixed> $data
     * @param User|null $actor
     * @return Employee
     * @throws \App\Exceptions\OptimisticLockException
     * @throws HttpException
     */
    public function updateEmployee(Employee $employee, array $data, ?User $actor = null): Employee
    {
        return DB::transaction(function () use ($employee, $data, $actor) {
            $beforeData = $employee->toArray();

            // Check version explicitly before update to ensure lock
            if (isset($data['version']) && (int) $data['version'] !== (int) $employee->version) {
                throw new \App\Exceptions\OptimisticLockException(
                    "Concurrency conflict on employees ID {$employee->id}: expected version {$data['version']}, but found {$employee->version}."
                );
            }

            // employee_code cannot be changed through edit/update
            if (isset($data['employee_code']) && $data['employee_code'] !== $employee->employee_code) {
                throw new HttpException(422, 'The employee code is immutable and cannot be changed.');
            }

            $updateData = collect($data)->except(['employee_code', 'version'])->filter(fn ($v) => $v !== null)->toArray();
            $employee->fill($updateData);
            $employee->save();

            // Synchronize common fields to linked user if one exists
            $linkedUser = $employee->user;
            if ($linkedUser) {
                $userUpdates = [];
                if (isset($data['full_name']) && $data['full_name'] !== $linkedUser->name) {
                    $userUpdates['name'] = $data['full_name'];
                }
                if (isset($data['email']) && $data['email'] !== $linkedUser->email) {
                    // Check uniqueness against other users
                    $conflict = User::where('email', $data['email'])
                        ->where('id', '!=', $linkedUser->id)
                        ->exists();
                    if ($conflict) {
                        throw new HttpException(422, 'The official email is already taken by another GIAM user account.');
                    }
                    $userUpdates['email'] = $data['email'];
                }
                if (isset($data['is_active'])) {
                    $userUpdates['is_active'] = (bool) $data['is_active'];
                }
                if (! empty($userUpdates)) {
                    $linkedUser->update($userUpdates);
                }
            }

            $this->auditLogger->log(
                action: 'EMPLOYEE_UPDATED',
                entityType: 'Employee',
                entityId: $employee->employee_code,
                beforeData: $beforeData,
                afterData: $employee->fresh()->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            // Trigger downstream update sync for active project accesses
            $userToSync = $linkedUser ?? ($employee->fresh()->user);
            if ($userToSync) {
                $this->syncActiveProjects($userToSync);
            }

            return $employee->fresh(['user', 'province', 'zone', 'region', 'branch', 'department', 'designation']);
        });
    }

    /**
     * Create a standalone GIAM Principal user account for an existing employee.
     *
     * @param array<string, mixed> $data
     * @param User|null $actor
     * @return User
     * @throws HttpException
     */
    public function createUser(array $data, ?User $actor = null): User
    {
        $rawPassword = $data['password'] ?? null;
        if (empty($rawPassword)) {
            $rawPassword = $this->securityService->generateTemporaryPassword();
        }

        $user = DB::transaction(function () use ($data, $actor, $rawPassword) {
            $roles = $data['roles'] ?? [];
            if (empty($roles)) {
                throw new HttpException(422, 'A valid GIAM internal role must be explicitly selected.');
            }

            $targetRoles = Role::whereIn('name', $roles)->where('guard_name', 'web')->with('permissions')->get();
            if ($targetRoles->count() !== count($roles)) {
                throw new HttpException(422, 'One or more selected GIAM internal roles are invalid or do not exist.');
            }

            $this->grantAuthorityService->validateRoleAssignment($actor, $targetRoles);

            $user = User::create([
                'employee_code' => $data['employee_code'],
                'name' => $data['name'],
                'username' => $data['username'],
                'email' => $data['email'],
                'password' => Hash::make($rawPassword),
                'user_type' => $data['user_type'] ?? 'staff',
                'is_active' => $data['is_active'] ?? true,
                'can_login' => $data['can_login'] ?? true,
                'must_change_password' => true,
                'password_changed_at' => now(),
            ]);

            $user->syncRoles($roles);

            $this->auditLogger->log(
                action: 'USER_CREATED',
                entityType: 'User',
                entityId: (string) $user->id,
                beforeData: null,
                afterData: $user->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            return $user->load(['employee', 'roles', 'permissions']);
        });

        // After commit: Send notification without persisting plaintext password into queue
        $this->sendNewAccountEmailSafe($user, $rawPassword, $actor);

        return $user;
    }

    public function sendNewAccountEmailSafeExternal(User $user, string $rawPassword, ?User $actor = null): bool
    {
        return $this->sendNewAccountEmailSafe($user, $rawPassword, $actor);
    }

    protected function sendNewAccountEmailSafe(User $user, string $rawPassword, ?User $actor = null): bool
    {
        $frontendUrl = config('app.frontend_url') ?? env('FRONTEND_URL', 'http://localhost:3000');
        $loginUrl = rtrim($frontendUrl, '/') . '/login';

        try {
            $defaultMailer = config('mail.default');

            if ($defaultMailer === 'smtp' && empty(config('mail.mailers.smtp.username'))) {
                // Outlook delivery blocked by missing configuration
                $user->credential_delivery = [
                    'status' => 'skipped',
                    'message' => 'Credentials email delivery skipped: SMTP credentials not configured.',
                ];
                return false;
            }

            Mail::to($user->email)->send(new NewAccountCredentialsMail($user, $rawPassword, $loginUrl));

            $this->auditLogger->log(
                action: 'MAIL_SUBMITTED',
                entityType: 'User',
                entityId: (string) $user->id,
                beforeData: null,
                afterData: [
                    'recipient_email' => $user->email,
                    'mail_type' => 'NEW_ACCOUNT_CREDENTIALS',
                    'transport' => $defaultMailer,
                    'delivery_status' => 'SUBMITTED_TO_TRANSPORT',
                    'disclaimer' => 'Accepted by mail transport; inbox delivery subject to recipient mail server heuristics.',
                ],
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            $user->credential_delivery = [
                'status' => 'submitted',
                'message' => 'Credentials email successfully submitted to mail transport.',
            ];

            return true;
        } catch (\Throwable $e) {
            $this->auditLogger->log(
                action: 'MAIL_FAILED',
                entityType: 'User',
                entityId: (string) $user->id,
                beforeData: null,
                afterData: [
                    'recipient_email' => $user->email,
                    'mail_type' => 'NEW_ACCOUNT_CREDENTIALS',
                    'error_type' => get_class($e),
                ],
                status: 'WARNING',
                actorUserId: $actor?->id
            );

            \Illuminate\Support\Facades\Log::warning("New account credentials mail failed for user ID {$user->id}: " . $e->getMessage());

            $user->credential_delivery = [
                'status' => 'failed',
                'message' => 'Account created, but credentials email delivery failed. You may resend credentials.',
            ];

            return false;
        }
    }

    /**
     * Resend/regenerate temporary credentials for a user safely.
     * Generates a new temporary password, updates password hash, forces password change,
     * invalidates old temporary password, syncs credential verifier to active projects,
     * and dispatches credentials email.
     *
     * @param User $user
     * @param User|null $actor
     * @return array<string, mixed>
     * @throws HttpException
     */
    public function resendCredentials(User $user, ?User $actor = null): array
    {
        if (! $user->is_active || ! $user->can_login) {
            throw new HttpException(422, 'Cannot resend credentials for an inactive or disabled user.');
        }

        // Generate a fresh cryptographically secure temporary password
        $newTempPassword = $this->securityService->generateTemporaryPassword();

        // Atomically update password hash, force password change, invalidate previous credentials
        DB::transaction(function () use ($user, $newTempPassword, $actor) {
            $user->password = Hash::make($newTempPassword);
            $user->must_change_password = true;
            $user->password_changed_at = now();
            $user->failed_login_attempts = 0;
            $user->lockout_until = null;
            $user->save();

            $this->auditLogger->log(
                action: 'USER_CREDENTIALS_REGENERATED',
                entityType: 'User',
                entityId: (string) $user->id,
                beforeData: null,
                afterData: [
                    'user_id' => $user->id,
                    'username' => $user->username,
                    'email' => $user->email,
                    'must_change_password' => true,
                ],
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            // Invalidate all active JWT tokens for user across all instances
            \App\Services\Auth\SimpleJwtService::revokeAllForUser($user->id);
        });

        // External side effects outside DB transaction boundary
        // 1. Synchronize credential change to Centrix / active projects
        $this->dataProjectionService->syncCredentialChange($user, $user->password);

        // 2. Dispatch credentials mail to user's official email
        $mailSent = $this->sendNewAccountEmailSafe($user, $newTempPassword, $actor);

        return [
            'status' => 'success',
            'message' => $mailSent
                ? 'New temporary credentials generated and dispatched to the user\'s official email address.'
                : 'New temporary credentials generated, but email delivery encountered an issue. Please verify mail transport logs.',
            'mail_submitted' => $mailSent,
        ];
    }

    /**
     * Update GIAM Principal attributes, internal roles, and synchronize with downstream projects.
     *
     * @param User $user
     * @param array<string, mixed> $data
     * @param User|null $actor
     * @return User
     * @throws \App\Exceptions\OptimisticLockException
     * @throws HttpException
     */
    public function updateUser(User $user, array $data, ?User $actor = null): User
    {
        return DB::transaction(function () use ($user, $data, $actor) {
            $beforeData = $user->toArray();

            // Optimistic lock check
            if (isset($data['version']) && (int) $data['version'] !== (int) $user->version) {
                throw new \App\Exceptions\OptimisticLockException(
                    "Concurrency conflict on users ID {$user->id}: expected version {$data['version']}, but found {$user->version}."
                );
            }

            // employee_code cannot be changed through edit/update
            if (isset($data['employee_code']) && $data['employee_code'] !== $user->employee_code) {
                throw new HttpException(422, 'The employee code is immutable and cannot be changed.');
            }

            // Privilege escalation and self-lockout validation
            if (isset($data['roles'])) {
                $targetRoles = Role::whereIn('name', $data['roles'])->where('guard_name', 'web')->with('permissions')->get();
                if ($targetRoles->count() !== count($data['roles'])) {
                    throw new HttpException(422, 'One or more selected GIAM internal roles are invalid or do not exist.');
                }

                $this->grantAuthorityService->validateRoleAssignment($actor, $targetRoles, $user);
                $this->grantAuthorityService->validateUserRoleSelfLockout($actor, $user, $targetRoles);

                $user->syncRoles($data['roles']);
            }

            $fillable = collect($data)->except(['roles', 'version', 'employee_code'])->filter(fn ($v) => $v !== null)->toArray();
            if (isset($fillable['password'])) {
                $fillable['password'] = Hash::make($fillable['password']);
                $fillable['password_changed_at'] = now();
            }
            $user->fill($fillable);
            $user->save();

            // Sync name/email back to employee if changed
            $employee = $user->employee;
            if ($employee) {
                $empUpdates = [];
                if (isset($data['name']) && $data['name'] !== $employee->full_name) {
                    $empUpdates['full_name'] = $data['name'];
                }
                if (isset($data['email']) && $data['email'] !== $employee->email) {
                    $empUpdates['email'] = $data['email'];
                }
                if (! empty($empUpdates)) {
                    $employee->update($empUpdates);
                }
            }

            $this->auditLogger->log(
                action: 'USER_UPDATED',
                entityType: 'User',
                entityId: (string) $user->id,
                beforeData: $beforeData,
                afterData: $user->fresh()->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            // Revoke active JWTs if permissions, roles, or password were changed
            if (isset($data['roles']) || isset($fillable['password'])) {
                \App\Services\Auth\SimpleJwtService::revokeAllForUser($user->id);
            }

            // Trigger downstream update sync for active project accesses
            $this->syncActiveProjects($user->fresh());

            return $user->fresh(['employee', 'roles', 'permissions']);
        });
    }

    /**
     * Dispatch UPDATE_USER outbox sync jobs for all currently ACTIVE user project accesses.
     * Registers SyncJob (operation UPDATE_USER, status PENDING) and dispatches
     * \App\Jobs\ExecuteSyncJob after transaction commit.
     *
     * @param User $user
     * @return void
     */
    public function syncActiveProjects(User $user): void
    {
        $activeAccesses = \App\Models\UserProjectAccess::with(['project.integration', 'roles', 'permissions'])
            ->where('user_id', $user->id)
            ->where('status', 'ACTIVE')
            ->get();

        foreach ($activeAccesses as $access) {
            $project = $access->project;
            if (! $project || ! $project->integration) {
                continue;
            }

            $projectedPayload = $this->dataProjectionService->project(
                user: $user,
                project: $project,
                roleIds: $access->roles->pluck('id')->toArray(),
                permissionIds: $access->permissions->pluck('id')->toArray()
            );

            $syncJob = \App\Models\SyncJob::create([
                'idempotency_key' => (string) Str::uuid(),
                'user_id' => $user->id,
                'project_id' => $project->id,
                'operation' => 'UPDATE_USER',
                'payload' => $projectedPayload,
                'status' => 'PENDING',
                'attempt_count' => 0,
                'max_attempts' => 5,
            ]);

            \App\Jobs\ExecuteSyncJob::dispatch($syncJob)->afterCommit();
        }
    }

    /**
     * Update active/login status of a user and propagate to downstream projects.
     *
     * @param User $user
     * @param array<string, mixed> $data
     * @param User|null $actor
     * @return User
     * @throws \App\Exceptions\OptimisticLockException
     */
    public function updateUserStatus(User $user, array $data, ?User $actor = null): User
    {
        return DB::transaction(function () use ($user, $data, $actor) {
            $beforeData = $user->toArray();

            // Optimistic lock check
            if (isset($data['version']) && (int) $data['version'] !== (int) $user->version) {
                throw new \App\Exceptions\OptimisticLockException(
                    "Concurrency conflict on users ID {$user->id}: expected version {$data['version']}, but found {$user->version}."
                );
            }

            if (array_key_exists('is_active', $data)) {
                $user->is_active = (bool) $data['is_active'];
            }
            if (array_key_exists('can_login', $data)) {
                $user->can_login = (bool) $data['can_login'];
            }
            $user->save();

            $action = (! $user->is_active || ! $user->can_login) ? 'USER_DEACTIVATED' : 'USER_UPDATED';

            if (! $user->is_active || ! $user->can_login) {
                \App\Services\Auth\SimpleJwtService::revokeAllForUser($user->id);
            }

            $this->auditLogger->log(
                action: $action,
                entityType: 'User',
                entityId: (string) $user->id,
                beforeData: $beforeData,
                afterData: $user->fresh()->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor?->id
            );

            // Propagate status change to connected downstream projects with ACTIVE access
            $activeAccesses = \App\Models\UserProjectAccess::with('project.integration')
                ->where('user_id', $user->id)
                ->where('status', 'ACTIVE')
                ->get();

            foreach ($activeAccesses as $access) {
                $project = $access->project;
                if (! $project || ! $project->integration) {
                    continue;
                }

                try {
                    $client = $this->clientFactory->make($project, timeoutSeconds: 3);
                    $integration = $project->integration;
                    $hasNamespace = str_ends_with(rtrim($integration->api_base_url, '/'), '/api/giam/integration');
                    $prefix = $hasNamespace ? '' : '/api/giam/integration';

                    $client->post("{$prefix}/users/{$user->id}/status", [
                        'is_active' => (bool) $user->is_active,
                        'can_login' => (bool) $user->can_login,
                    ]);
                } catch (\Exception $e) {
                    \Illuminate\Support\Facades\Log::warning("Downstream status sync deferred for project [{$project->code}]: {$e->getMessage()}");
                }
            }

            return $user->fresh(['employee', 'roles', 'permissions']);
        });
    }
}
