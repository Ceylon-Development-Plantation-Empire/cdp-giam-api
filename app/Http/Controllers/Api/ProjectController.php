<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Http\Requests\Project\StoreProjectRequest;
use App\Http\Requests\Project\UpdateProjectRequest;
use App\Http\Resources\ProjectResource;
use App\Models\Project;
use App\Models\ProjectIntegration;
use App\Services\Audit\AuditLoggerService;
use App\Services\Integration\ProjectOnboardingService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;

class ProjectController extends Controller
{
    public function __construct(
        protected AuditLoggerService $auditLogger
    ) {}

    /**
     * Store a newly created project.
     */
    public function store(StoreProjectRequest $request, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $validated = $request->validated();
        $project = $onboardingService->registerProject($validated);
        $onboardingService->configureIntegration($project, $validated);

        $this->auditLogger->log(
            action: 'PROJECT_CREATED',
            entityType: 'Project',
            entityId: $project->code,
            beforeData: null,
            afterData: $project->fresh('integration')->toArray(),
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return (new ProjectResource($project->fresh('integration')))
            ->response()
            ->setStatusCode(201);
    }

    /**
     * Display a listing of projects.
     */
    public function index(Request $request): AnonymousResourceCollection
    {
        $query = Project::with('integration')
            ->withCount(['modules', 'roles', 'permissions']);

        if ($status = $request->input('status')) {
            $query->where('status', $status);
        }

        if ($search = $request->input('search')) {
            $query->where(function ($q) use ($search) {
                $q->where('name', 'like', "%{$search}%")
                  ->orWhere('code', 'like', "%{$search}%");
            });
        }

        $projects = $query->orderBy('name', 'asc')
                          ->paginate($request->integer('per_page', 15));

        return ProjectResource::collection($projects);
    }

    /**
     * Display the specified project.
     */
    public function show(int|string $id): ProjectResource
    {
        $project = Project::with('integration')
            ->withCount(['modules', 'roles', 'permissions'])
            ->where('id', $id)
            ->orWhere('code', $id)
            ->firstOrFail();

        return new ProjectResource($project);
    }

    /**
     * Update the specified project.
     */
    public function update(UpdateProjectRequest $request, int|string $id): ProjectResource
    {
        $project = Project::where('id', $id)
            ->orWhere('code', $id)
            ->firstOrFail();

        $beforeData = $project->toArray();
        $project->update($request->validated());

        $this->auditLogger->log(
            action: 'PROJECT_UPDATED',
            entityType: 'Project',
            entityId: $project->code,
            beforeData: $beforeData,
            afterData: $project->fresh()->toArray(),
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return new ProjectResource($project->fresh('integration'));
    }

    /**
     * Disable the specified project.
     */
    public function destroy(Request $request, int|string $id): JsonResponse
    {
        $project = Project::where('id', $id)
            ->orWhere('code', $id)
            ->firstOrFail();

        $beforeData = $project->toArray();
        $project->update(['status' => 'disabled']);

        $this->auditLogger->log(
            action: 'PROJECT_DISABLED',
            entityType: 'Project',
            entityId: $project->code,
            beforeData: $beforeData,
            afterData: ['status' => 'disabled'],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Project has been disabled successfully.',
        ]);
    }
}
