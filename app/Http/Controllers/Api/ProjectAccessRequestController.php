<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Employee;
use App\Models\Project;
use App\Models\ProjectAccessRequest;
use App\Models\ProjectRole;
use App\Services\Access\ProjectAccessAssignmentService;
use App\Services\Audit\AuditLoggerService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpKernel\Exception\HttpException;

class ProjectAccessRequestController extends Controller
{
    public function __construct(
        protected ProjectAccessAssignmentService $assignmentService,
        protected AuditLoggerService $auditLogger
    ) {}

    /**
     * Get aggregated counts of project access requests by status.
     * Gated by ACCESS_VIEW.
     */
    public function counts(Request $request): JsonResponse
    {
        $actor = $request->user();
        if (! $actor || ! $actor->hasPermissionTo('ACCESS_VIEW', 'web')) {
            throw new HttpException(403, 'Forbidden: Insufficient permissions to view access requests.');
        }

        $counts = ProjectAccessRequest::selectRaw("
            SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) as pending,
            SUM(CASE WHEN status = 'FULFILLED' THEN 1 ELSE 0 END) as fulfilled,
            SUM(CASE WHEN status = 'REJECTED' THEN 1 ELSE 0 END) as rejected,
            COUNT(*) as total
        ")->first();

        return response()->json([
            'status' => 'success',
            'data' => [
                'pending' => (int) ($counts->pending ?? 0),
                'fulfilled' => (int) ($counts->fulfilled ?? 0),
                'rejected' => (int) ($counts->rejected ?? 0),
                'total' => (int) ($counts->total ?? 0),
            ],
        ]);
    }

    /**
     * List project access requests (Workflow 2: Access Requests view).
     * Gated by ACCESS_VIEW.
     */
    public function index(Request $request): JsonResponse
    {
        $actor = $request->user();
        if (! $actor || ! $actor->hasPermissionTo('ACCESS_VIEW', 'web')) {
            throw new HttpException(403, 'Forbidden: Insufficient permissions to view access requests.');
        }

        $query = ProjectAccessRequest::with([
            'employee.user',
            'submittedBy:id,name,username,email',
            'reviewedBy:id,name,username,email',
            'resolvedProject:id,code,name',
            'userProjectAccess',
        ]);

        if ($status = $request->input('status')) {
            $query->where('status', strtoupper($status));
        }

        $requests = $query->orderBy('created_at', 'desc')
            ->paginate($request->integer('per_page', 15));

        return response()->json([
            'status' => 'success',
            'data' => $requests->items(),
            'meta' => [
                'current_page' => $requests->currentPage(),
                'last_page' => $requests->lastPage(),
                'per_page' => $requests->perPage(),
                'total' => $requests->total(),
            ],
        ]);
    }

    /**
     * Show a single project access request with employee and resolution metadata.
     * Gated by ACCESS_VIEW.
     */
    public function show(Request $request, int $id): JsonResponse
    {
        $actor = $request->user();
        if (! $actor || ! $actor->hasPermissionTo('ACCESS_VIEW', 'web')) {
            throw new HttpException(403, 'Forbidden: Insufficient permissions to view access requests.');
        }

        $accessRequest = ProjectAccessRequest::with([
            'employee.user',
            'submittedBy:id,name,username,email',
            'reviewedBy:id,name,username,email',
            'resolvedProject:id,code,name',
            'userProjectAccess',
        ])->findOrFail($id);

        return response()->json([
            'status' => 'success',
            'data' => $accessRequest,
        ]);
    }

    /**
     * Resolve and fulfill a pending request by assigning real project access.
     * Gated by ACCESS_ASSIGN.
     * Protected by DB transaction, row-locking (lockForUpdate), and strict project role scoping.
     */
    public function resolve(Request $request, int $id): JsonResponse
    {
        $actor = $request->user();
        if (! $actor || ! $actor->hasPermissionTo('ACCESS_ASSIGN', 'web')) {
            throw new HttpException(403, 'Forbidden: Insufficient permissions to assign project access.');
        }

        $validated = $request->validate([
            'project_id' => ['required', 'integer', 'exists:projects,id'],
            'role_ids' => ['required', 'array', 'min:1'],
            'role_ids.*' => ['integer', 'exists:project_roles,id'],
            'permission_ids' => ['nullable', 'array'],
            'permission_ids.*' => ['integer', 'exists:project_permissions,id'],
        ]);

        return DB::transaction(function () use ($validated, $id, $actor) {
            // Row lock request to prevent concurrent double resolution
            $accessRequest = ProjectAccessRequest::where('id', $id)
                ->lockForUpdate()
                ->firstOrFail();

            if ($accessRequest->status !== 'PENDING') {
                return response()->json([
                    'status' => 'error',
                    'code' => 'INVALID_STATE',
                    'message' => "Cannot resolve request with status [{$accessRequest->status}]. Only PENDING requests can be resolved.",
                ], 409);
            }

            $employee = $accessRequest->employee;
            if (! $employee) {
                return response()->json([
                    'status' => 'error',
                    'code' => 'EMPLOYEE_NOT_FOUND',
                    'message' => 'Associated employee record not found.',
                ], 404);
            }

            // Verify that the Employee has a linked GIAM Principal / User
            $user = $employee->user;
            if (! $user) {
                return response()->json([
                    'status' => 'error',
                    'code' => 'USER_ACCOUNT_REQUIRED',
                    'message' => "Employee [{$employee->employee_code}] does not have a linked GIAM User account. A user account must be created before assigning project access.",
                ], 422);
            }

            $project = Project::findOrFail($validated['project_id']);

            // Strict Server-Side Project-Scoping Validation:
            // Verify that every role_id in role_ids belongs strictly to the target project and is active
            $validRoleCount = ProjectRole::where('project_id', $project->id)
                ->whereIn('id', $validated['role_ids'])
                ->where('is_active', true)
                ->count();

            if ($validRoleCount !== count($validated['role_ids'])) {
                return response()->json([
                    'status' => 'error',
                    'code' => 'INVALID_PROJECT_ROLES',
                    'message' => "One or more selected roles do not belong to project [{$project->name}] or are inactive.",
                ], 422);
            }

            // Execute the authoritative Step 3 assignment service (atomic outbox & access write)
            $userProjectAccess = $this->assignmentService->assignAccess(
                user: $user,
                projectId: $project->id,
                roleIds: $validated['role_ids'],
                permissionIds: $validated['permission_ids'] ?? [],
                actor: $actor
            );

            // Transition request state to FULFILLED atomically
            $accessRequest->update([
                'status' => 'FULFILLED',
                'resolved_project_id' => $project->id,
                'user_project_access_id' => $userProjectAccess->id,
                'reviewed_by_user_id' => $actor->id,
                'reviewed_at' => now(),
                'fulfilled_at' => now(),
            ]);

            $this->auditLogger->log(
                action: 'PROJECT_ACCESS_REQUEST_FULFILLED',
                entityType: 'ProjectAccessRequest',
                entityId: (string) $accessRequest->id,
                beforeData: ['status' => 'PENDING'],
                afterData: $accessRequest->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor->id,
                projectId: $project->id
            );

            return response()->json([
                'status' => 'success',
                'message' => "Project access granted and request #{$accessRequest->id} marked as FULFILLED.",
                'data' => [
                    'request' => $accessRequest->fresh(['resolvedProject', 'reviewedBy']),
                    'access' => $userProjectAccess,
                ],
            ]);
        });
    }

    /**
     * Reject a pending project access request.
     * Gated strictly by ACCESS_ASSIGN.
     * Protected by DB transaction and row-locking (lockForUpdate).
     */
    public function reject(Request $request, int $id): JsonResponse
    {
        $actor = $request->user();
        if (! $actor || ! $actor->hasPermissionTo('ACCESS_ASSIGN', 'web')) {
            throw new HttpException(403, 'Forbidden: Insufficient permissions to reject access requests.');
        }

        return DB::transaction(function () use ($id, $actor) {
            $accessRequest = ProjectAccessRequest::where('id', $id)
                ->lockForUpdate()
                ->firstOrFail();

            if ($accessRequest->status !== 'PENDING') {
                return response()->json([
                    'status' => 'error',
                    'code' => 'INVALID_STATE',
                    'message' => "Cannot reject request with status [{$accessRequest->status}]. Only PENDING requests can be rejected.",
                ], 409);
            }

            $accessRequest->update([
                'status' => 'REJECTED',
                'reviewed_by_user_id' => $actor->id,
                'reviewed_at' => now(),
            ]);

            $this->auditLogger->log(
                action: 'PROJECT_ACCESS_REQUEST_REJECTED',
                entityType: 'ProjectAccessRequest',
                entityId: (string) $accessRequest->id,
                beforeData: ['status' => 'PENDING'],
                afterData: $accessRequest->toArray(),
                status: 'SUCCESS',
                actorUserId: $actor->id
            );

            return response()->json([
                'status' => 'success',
                'message' => "Project access request #{$accessRequest->id} rejected.",
                'data' => $accessRequest->fresh(['reviewedBy']),
            ]);
        });
    }
}
