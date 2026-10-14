<?php

namespace App\Http\Controllers\Api;

use App\Exceptions\IntegrationActivationException;
use App\Http\Controllers\Controller;
use App\Http\Requests\Project\UpdateProjectIntegrationRequest;
use App\Http\Resources\ProjectIntegrationResource;
use App\Models\Project;
use App\Services\Audit\AuditLoggerService;
use App\Services\Integration\ProjectHealthCheckService;
use App\Services\Integration\ProjectOnboardingService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class ProjectIntegrationController extends Controller
{
    public function __construct(
        protected ProjectHealthCheckService $healthCheckService,
        protected AuditLoggerService $auditLogger
    ) {}

    /**
     * Display the integration configuration for a project.
     */
    public function show(int|string $projectId): ProjectIntegrationResource
    {
        $project = Project::where('id', $projectId)
            ->orWhere('code', $projectId)
            ->firstOrFail();

        $integration = $project->integration;

        if (! $integration) {
            abort(404, 'Project integration not configured.');
        }

        return new ProjectIntegrationResource($integration);
    }

    /**
     * Update or create the integration configuration for a project.
     */
    public function update(UpdateProjectIntegrationRequest $request, int|string $projectId, ProjectOnboardingService $onboardingService): ProjectIntegrationResource
    {
        $project = Project::where('id', $projectId)
            ->orWhere('code', $projectId)
            ->firstOrFail();

        $beforeData = $project->integration?->toArray();

        $integration = $onboardingService->configureIntegration($project, $request->validated());

        $this->auditLogger->log(
            action: 'PROJECT_INTEGRATION_UPDATED',
            entityType: 'ProjectIntegration',
            entityId: (string) $integration->id,
            beforeData: $beforeData,
            afterData: $integration->fresh()->toArray(),
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return new ProjectIntegrationResource($integration->fresh());
    }

    /**
     * Perform a connectivity and health check for the project integration.
     */
    public function healthCheck(int|string $projectId): JsonResponse
    {
        $project = Project::with('integration')
            ->where('id', $projectId)
            ->orWhere('code', $projectId)
            ->firstOrFail();

        $result = $this->healthCheckService->check($project);

        return response()->json([
            'status' => 'success',
            'data' => $result,
        ]);
    }

    /**
     * Actively verify downstream project connectivity and authentication contract.
     */
    public function verify(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        $result = $onboardingService->verifyIntegration($project);

        $this->auditLogger->log(
            action: 'PROJECT_INTEGRATION_VERIFIED',
            entityType: 'ProjectIntegration',
            entityId: (string) ($project->integration?->id ?? 'unknown'),
            beforeData: null,
            afterData: $result,
            status: $result['verified'] ? 'SUCCESS' : 'WARNING',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => $result['verified'] ? 'success' : 'error',
            'message' => $result['verified']
                ? "Connectivity and authentication verified successfully with [{$project->name}]."
                : "Verification probe failed: {$result['error']}",
            'data' => $result,
        ], $result['verified'] ? 200 : 422);
    }

    /**
     * Provision cryptographically secure credentials for a project.
     */
    public function provisionCredentials(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        $credentials = $onboardingService->provisionCredentials(
            $project,
            $request->input('client_id'),
            $request->input('client_secret')
        );

        $this->auditLogger->log(
            action: 'PROJECT_CREDENTIALS_PROVISIONED',
            entityType: 'ProjectIntegration',
            entityId: (string) ($project->integration?->id ?? 'unknown'),
            beforeData: null,
            afterData: ['client_id' => $credentials['client_id']],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Credentials provisioned successfully. Copy and securely configure the client secret now. It will not be shown again.',
            'data' => $credentials,
        ], 201);
    }

    /**
     * Rotate project client secret with a 24-hour transition grace period.
     */
    public function rotateCredentials(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        $graceHours = (int) $request->input('grace_period_hours', 24);
        if ($graceHours < 0 || $graceHours > 168) {
            $graceHours = 24;
        }

        $credentials = $onboardingService->rotateCredentials($project, $graceHours);

        $this->auditLogger->log(
            action: 'PROJECT_CREDENTIALS_ROTATED',
            entityType: 'ProjectIntegration',
            entityId: (string) ($project->integration?->id ?? 'unknown'),
            beforeData: null,
            afterData: [
                'client_id' => $credentials['client_id'],
                'grace_period_hours' => $graceHours,
                'previous_secret_expires_at' => $credentials['previous_secret_expires_at'],
            ],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => 'success',
            'message' => "Client secret rotated successfully with a {$graceHours}-hour zero-downtime transition grace period. Update the downstream project configuration and securely revoke the previous secret.",
            'data' => $credentials,
        ]);
    }

    /**
     * Immediately revoke the previous rotated secret after downstream configuration is confirmed.
     */
    public function revokePreviousSecret(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        $onboardingService->revokePreviousSecret($project);

        $this->auditLogger->log(
            action: 'PROJECT_PREVIOUS_SECRET_REVOKED',
            entityType: 'ProjectIntegration',
            entityId: (string) ($project->integration?->id ?? 'unknown'),
            beforeData: null,
            afterData: ['previous_secret_revoked' => true],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Previous client secret revoked successfully.',
        ]);
    }

    /**
     * Revoke client credentials for a project.
     */
    public function revokeCredentials(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        $onboardingService->revokeCredentials($project);

        $this->auditLogger->log(
            action: 'PROJECT_CREDENTIALS_REVOKED',
            entityType: 'ProjectIntegration',
            entityId: (string) ($project->integration?->id ?? 'unknown'),
            beforeData: null,
            afterData: ['revoked' => true],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => 'success',
            'message' => 'Project integration credentials revoked successfully.',
        ]);
    }

    /**
     * Activate a project integration.
     */
    public function activate(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        try {
            $integration = $onboardingService->activateIntegration($project);

            $this->auditLogger->log(
                action: 'PROJECT_INTEGRATION_ACTIVATED',
                entityType: 'ProjectIntegration',
                entityId: (string) $integration->id,
                beforeData: null,
                afterData: ['status' => 'healthy', 'sso_enabled' => true, 'sync_enabled' => true],
                status: 'SUCCESS',
                projectId: $project->id,
                actorUserId: $request->user()?->id
            );

            return response()->json([
                'status' => 'success',
                'message' => "Integration for [{$project->name}] activated successfully.",
                'data' => new ProjectIntegrationResource($integration),
            ]);
        } catch (IntegrationActivationException $e) {
            return response()->json([
                'status' => 'error',
                'message' => $e->getMessage(),
                'missing_fields' => $e->getMissingFields(),
            ], 422);
        }
    }

    /**
     * Deactivate a project integration.
     */
    public function deactivate(Request $request, int|string $projectId, ProjectOnboardingService $onboardingService): JsonResponse
    {
        $project = Project::with('integration')->where('id', $projectId)->orWhere('code', $projectId)->firstOrFail();

        $integration = $onboardingService->deactivateIntegration($project);

        $this->auditLogger->log(
            action: 'PROJECT_INTEGRATION_DEACTIVATED',
            entityType: 'ProjectIntegration',
            entityId: (string) $integration->id,
            beforeData: null,
            afterData: ['status' => 'offline', 'sso_enabled' => false, 'sync_enabled' => false],
            status: 'SUCCESS',
            projectId: $project->id,
            actorUserId: $request->user()?->id
        );

        return response()->json([
            'status' => 'success',
            'message' => "Integration for [{$project->name}] deactivated.",
            'data' => new ProjectIntegrationResource($integration),
        ]);
    }
}
