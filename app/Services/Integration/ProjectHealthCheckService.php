<?php

namespace App\Services\Integration;

use App\Models\Project;
use App\Services\Audit\AuditLoggerService;
use Exception;
use Illuminate\Support\Facades\Log;

/**
 * Service executing downstream project integration health probes, recording
 * network round-trip latencies and logging status changes.
 */
class ProjectHealthCheckService
{
    public function __construct(
        protected ProjectClientFactory $clientFactory,
        protected AuditLoggerService $auditLogger
    ) {}

    /**
     * Perform an active HTTP health probe against downstream project endpoint.
     *
     * @param Project $project
     * @return array<string, mixed>
     */
    public function check(Project $project): array
    {
        $integration = $project->integration;

        if (! $integration) {
            return [
                'status' => 'offline',
                'latency_ms' => null,
                'error' => 'No integration configured.',
            ];
        }

        $startTime = microtime(true);
        $status = 'offline';
        $statusCode = null;
        $errorMessage = null;

        try {
            $client = $this->clientFactory->make($project, timeoutSeconds: 3);

            // Probe downstream health endpoint (supports /health-check and /health conventions)
            $baseUrl = rtrim((string) $integration->api_base_url, '/');
            $response = $client->get("{$baseUrl}/health-check");
            if ($response->status() === 404) {
                $response = $client->get("{$baseUrl}/health");
            }

            $latencyMs = round((microtime(true) - $startTime) * 1000);
            $statusCode = $response->status();

            if ($response->successful()) {
                $status = 'healthy';
            } elseif ($response->serverError()) {
                $status = 'offline';
                $errorMessage = "Server returned HTTP {$statusCode}";
            } else {
                $status = 'degraded';
                $errorMessage = "Server returned HTTP {$statusCode}";
            }
        } catch (Exception $e) {
            $latencyMs = round((microtime(true) - $startTime) * 1000);
            $status = 'offline';
            $errorMessage = $e->getMessage();
            Log::warning("Health check failed for project [{$project->code}]: {$errorMessage}");
        }

        // Update database record including verification tracking
        $integration->update([
            'status' => $status,
            'last_health_check_at' => now(),
            'verification_status' => $status === 'healthy' ? 'verified' : 'failed',
            'verification_error' => $status === 'healthy' ? null : $errorMessage,
            'last_verified_at' => now(),
        ]);

        $this->auditLogger->log(
            action: 'PROJECT_HEALTH_CHECK',
            entityType: 'Project',
            entityId: $project->code,
            beforeData: null,
            afterData: [
                'status' => $status,
                'latency_ms' => $latencyMs,
                'http_status' => $statusCode,
            ],
            status: $status === 'healthy' ? 'SUCCESS' : 'WARNING',
            projectId: $project->id,
            metadata: ['error' => $errorMessage]
        );

        return [
            'project_code' => $project->code,
            'status' => $status,
            'latency_ms' => $latencyMs,
            'http_status' => $statusCode,
            'error' => $errorMessage,
            'checked_at' => now()->toIso8601String(),
        ];
    }
}
