<?php

use App\Http\Controllers\Api\AuditLogController;
use App\Http\Controllers\Api\AuthController;
use App\Http\Controllers\Api\BulkImportController;
use App\Http\Controllers\Api\DraftController;
use App\Http\Controllers\Api\EmployeeController;
use App\Http\Controllers\Api\GiamRbacController;
use App\Http\Controllers\Api\Integrations\ProjectResourceController;
use App\Http\Controllers\Api\PasswordResetAssistanceAdminController;
use App\Http\Controllers\Api\ProjectAccessRequestController;
use App\Http\Controllers\Api\ProjectApiKeyAdminController;
use App\Http\Controllers\Api\ProjectCatalogController;
use App\Http\Controllers\Api\ProjectController;
use App\Http\Controllers\Api\ProjectIntegrationController;
use App\Http\Controllers\Api\ReportController;
use App\Http\Controllers\Api\SyncJobController;
use App\Http\Controllers\Api\UserController;
use App\Http\Controllers\Api\UserProjectAccessController;
use App\Http\Middleware\AuthenticateGiamSessionOrBearer;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Version 1 API Routes
|--------------------------------------------------------------------------
|
| Canonical RESTful API v1 endpoints for GIAM (Global Identity & Access
| Management). Mirrors the architecture and routing structure of CDP Connect.
|
*/

Route::prefix('v1')->group(function () {
    // Health Check endpoint
    Route::get('/health-check', function () {
        return response()->json([
            'status' => 'healthy',
            'service' => 'GIAM API v1',
            'timestamp' => now()->toIso8601String(),
        ]);
    });

    // Public Authentication & Password Reset endpoints
    Route::prefix('auth')->group(function () {
        Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:auth')->name('login');
        Route::post('/forgot-password', [AuthController::class, 'forgotPassword'])->middleware('throttle:password-reset');
        Route::post('/reset-password', [AuthController::class, 'resetPassword'])->middleware('throttle:password-reset');
        Route::post('/password-reset-assistance', [AuthController::class, 'requestAssistance'])->middleware('throttle:password-reset');
    });

    // Authenticated & Verified GIAM session or Bearer token endpoints
    Route::middleware([AuthenticateGiamSessionOrBearer::class, 'giam.can_login', 'throttle:api'])->group(function () {
        // Auth session
        Route::prefix('auth')->group(function () {
            Route::post('/logout', [AuthController::class, 'logout']);
            Route::get('/me', [AuthController::class, 'me']);
            Route::post('/change-password', [AuthController::class, 'changePassword'])->middleware('throttle:password-reset');
            Route::get('/my-projects', [AuthController::class, 'myProjects']);
        });

        // Password Reset Assistance Administration
        Route::prefix('admin/password-reset-requests')->group(function () {
            Route::get('/', [PasswordResetAssistanceAdminController::class, 'index'])->middleware('giam.permission:USER_VIEW');
            Route::post('/{id}/approve', [PasswordResetAssistanceAdminController::class, 'approve'])->middleware(['giam.permission:USER_UPDATE', 'throttle:sensitive-writes']);
            Route::post('/{id}/reject', [PasswordResetAssistanceAdminController::class, 'reject'])->middleware(['giam.permission:USER_UPDATE', 'throttle:sensitive-writes']);
        });

        // Employees Management
        Route::prefix('employees')->group(function () {
            Route::get('/template', [BulkImportController::class, 'downloadEmployeeTemplate'])->middleware('giam.permission:EMPLOYEE_CREATE');
            Route::post('/bulk-import', [BulkImportController::class, 'importEmployees'])->middleware(['giam.permission:EMPLOYEE_CREATE', 'throttle:sensitive-writes']);
            Route::get('/', [EmployeeController::class, 'index'])->middleware('giam.permission:EMPLOYEE_VIEW,USER_VIEW');
            Route::post('/', [EmployeeController::class, 'store'])->middleware(['giam.permission:EMPLOYEE_CREATE,USER_CREATE', 'throttle:sensitive-writes']);
            Route::get('/{id}', [EmployeeController::class, 'show'])->middleware('giam.permission:EMPLOYEE_VIEW,USER_VIEW');
            Route::put('/{id}', [EmployeeController::class, 'update'])->middleware(['giam.permission:EMPLOYEE_UPDATE,USER_UPDATE', 'throttle:sensitive-writes']);
            Route::delete('/{id}', [EmployeeController::class, 'destroy'])->middleware(['giam.permission:USER_DEACTIVATE', 'throttle:sensitive-writes']);
        });

        // Users Management & Drafts
        Route::prefix('users')->group(function () {
            Route::get('/template', [BulkImportController::class, 'downloadUserTemplate'])->middleware('giam.permission:USER_CREATE');
            Route::post('/bulk-import', [BulkImportController::class, 'importUsers'])->middleware(['giam.permission:USER_CREATE', 'throttle:sensitive-writes']);

            // Multi-step drafts
            Route::post('/drafts', [DraftController::class, 'store'])->middleware(['giam.permission:USER_CREATE', 'throttle:sensitive-writes']);
            Route::get('/drafts/{token}', [DraftController::class, 'show'])->middleware('giam.permission:USER_CREATE');
            Route::delete('/drafts/{token}', [DraftController::class, 'destroy'])->middleware('giam.permission:USER_CREATE');

            // Users CRUD
            Route::get('/', [UserController::class, 'index'])->middleware('giam.permission:USER_VIEW');
            Route::post('/', [UserController::class, 'store'])->middleware(['giam.permission:USER_CREATE', 'throttle:sensitive-writes']);
            Route::get('/{id}', [UserController::class, 'show'])->middleware('giam.permission:USER_VIEW');
            Route::put('/{id}', [UserController::class, 'update'])->middleware(['giam.permission:USER_UPDATE', 'throttle:sensitive-writes']);
            Route::patch('/{id}/status', [UserController::class, 'updateStatus'])->middleware(['giam.permission:USER_DEACTIVATE', 'throttle:sensitive-writes']);
            Route::post('/{id}/resend-credentials', [UserController::class, 'resendCredentials'])->middleware(['giam.permission:USER_UPDATE', 'throttle:sensitive-writes']);
            Route::delete('/{id}', [UserController::class, 'destroy'])->middleware(['giam.permission:USER_DEACTIVATE', 'throttle:sensitive-writes']);
            Route::post('/{id}/restore', [UserController::class, 'restore'])->middleware(['giam.permission:USER_DEACTIVATE', 'throttle:sensitive-writes']);

            // Multi-Project Access Assignment, Inspection, Update & Revocation
            Route::get('/{userId}/project-access', [UserProjectAccessController::class, 'index'])->middleware('giam.permission:ACCESS_VIEW');
            Route::post('/{userId}/project-access', [UserProjectAccessController::class, 'store'])->middleware(['giam.permission:ACCESS_ASSIGN', 'throttle:sensitive-writes']);
            Route::get('/{userId}/project-access/{projectId}', [UserProjectAccessController::class, 'show'])->middleware('giam.permission:ACCESS_VIEW');
            Route::match(['put', 'patch'], '/{userId}/project-access/{projectId}', [UserProjectAccessController::class, 'update'])->middleware(['giam.permission:ACCESS_ASSIGN', 'throttle:sensitive-writes']);
            Route::delete('/{userId}/project-access/{projectId}', [UserProjectAccessController::class, 'destroy'])->middleware(['giam.permission:ACCESS_REVOKE', 'throttle:sensitive-writes']);
        });

        // HR Project Access Requests (Workflow 2)
        Route::prefix('project-access-requests')->group(function () {
            Route::get('/counts', [ProjectAccessRequestController::class, 'counts'])->middleware('giam.permission:ACCESS_VIEW');
            Route::get('/', [ProjectAccessRequestController::class, 'index'])->middleware('giam.permission:ACCESS_VIEW');
            Route::get('/{id}', [ProjectAccessRequestController::class, 'show'])->middleware('giam.permission:ACCESS_VIEW');
            Route::post('/{id}/resolve', [ProjectAccessRequestController::class, 'resolve'])->middleware(['giam.permission:ACCESS_ASSIGN', 'throttle:sensitive-writes']);
            Route::post('/{id}/reject', [ProjectAccessRequestController::class, 'reject'])->middleware(['giam.permission:ACCESS_ASSIGN', 'throttle:sensitive-writes']);
        });

        // Projects Registry & Integrations (Read, Status & Health/Sync Operations)
        Route::prefix('projects')->group(function () {
            Route::get('/', [ProjectController::class, 'index'])->middleware('giam.permission:PROJECT_VIEW');
            Route::post('/', [ProjectController::class, 'store'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::get('/{id}', [ProjectController::class, 'show'])->middleware('giam.permission:PROJECT_VIEW');
            Route::put('/{id}', [ProjectController::class, 'update'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::delete('/{id}', [ProjectController::class, 'destroy'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);

            // Project Integration Settings & Health Check
            Route::get('/{id}/integration', [ProjectIntegrationController::class, 'show'])->middleware('giam.permission:PROJECT_MANAGE');
            Route::put('/{id}/integration', [ProjectIntegrationController::class, 'update'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/health-check', [ProjectIntegrationController::class, 'healthCheck'])->middleware('giam.permission:PROJECT_MANAGE');
            Route::post('/{id}/integration/verify', [ProjectIntegrationController::class, 'verify'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/credentials', [ProjectIntegrationController::class, 'provisionCredentials'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/credentials/provision', [ProjectIntegrationController::class, 'provisionCredentials'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/credentials/rotate', [ProjectIntegrationController::class, 'rotateCredentials'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/credentials/revoke', [ProjectIntegrationController::class, 'revokeCredentials'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/credentials/revoke-previous', [ProjectIntegrationController::class, 'revokePreviousSecret'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/activate', [ProjectIntegrationController::class, 'activate'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/integration/deactivate', [ProjectIntegrationController::class, 'deactivate'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);

            // RBAC Catalog Discovery & Display
            Route::get('/{id}/catalog', [ProjectCatalogController::class, 'show'])->middleware('giam.permission:PROJECT_VIEW');
            Route::post('/{id}/sync-catalog', [ProjectCatalogController::class, 'sync'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:catalog-sync']);

            // Project Inbound API Keys Management
            Route::get('/{id}/api-keys', [ProjectApiKeyAdminController::class, 'index'])->middleware('giam.permission:PROJECT_MANAGE');
            Route::post('/{id}/api-keys', [ProjectApiKeyAdminController::class, 'store'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
            Route::post('/{id}/api-keys/{keyId}/revoke', [ProjectApiKeyAdminController::class, 'revoke'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
        });

        // Outbox Sync Jobs & Manual Retry
        Route::prefix('sync-jobs')->group(function () {
            Route::get('/', [SyncJobController::class, 'index'])->middleware('giam.permission:PROJECT_VIEW');
            Route::get('/{id}', [SyncJobController::class, 'show'])->middleware('giam.permission:PROJECT_VIEW');
            Route::post('/{id}/retry', [SyncJobController::class, 'retry'])->middleware(['giam.permission:PROJECT_MANAGE', 'throttle:sensitive-writes']);
        });

        // Audit Trail & Security Event Logs
        Route::prefix('audit-logs')->group(function () {
            Route::get('/', [AuditLogController::class, 'index'])->middleware('giam.permission:AUDIT_VIEW');
            Route::get('/{id}', [AuditLogController::class, 'show'])->middleware('giam.permission:AUDIT_VIEW');
        });

        // Access & Compliance Reporting (CSV / PDF)
        Route::prefix('reports')->group(function () {
            Route::get('/access', [ReportController::class, 'accessReport'])->middleware('giam.permission:REPORT_VIEW');
            Route::get('/access/export/csv', [ReportController::class, 'exportAccessCsv'])->middleware('giam.permission:REPORT_EXPORT');
            Route::get('/access/export/pdf', [ReportController::class, 'exportAccessPdf'])->middleware('giam.permission:REPORT_EXPORT');
            Route::get('/audit/export/csv', [ReportController::class, 'exportAuditCsv'])->middleware(['giam.permission:REPORT_EXPORT', 'giam.permission:AUDIT_VIEW']);
        });

        // GIAM Internal RBAC Hierarchy, Roles, Modules, Permission Groups, and Permissions
        Route::prefix('rbac')->group(function () {
            Route::get('/hierarchy', [GiamRbacController::class, 'hierarchy'])->middleware('giam.permission:GIAM_ROLE_VIEW');

            // Roles (Protected strictly by GIAM_ROLE_VIEW to prevent unauthorized HR inspection)
            Route::get('/roles', [GiamRbacController::class, 'roles'])->middleware('giam.permission:GIAM_ROLE_VIEW');
            Route::get('/roles/{id}', [GiamRbacController::class, 'showRole'])->middleware('giam.permission:GIAM_ROLE_VIEW');
            Route::post('/roles', [GiamRbacController::class, 'storeRole'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::put('/roles/{id}', [GiamRbacController::class, 'updateRole'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::delete('/roles/{id}', [GiamRbacController::class, 'destroyRole'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::put('/roles/{id}/permissions', [GiamRbacController::class, 'syncRolePermissions'])->middleware('giam.permission:GIAM_ROLE_MANAGE');

            // Modules
            Route::get('/modules', [GiamRbacController::class, 'modules'])->middleware('giam.permission:GIAM_ROLE_VIEW');
            Route::post('/modules', [GiamRbacController::class, 'storeModule'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::put('/modules/{id}', [GiamRbacController::class, 'updateModule'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::delete('/modules/{id}', [GiamRbacController::class, 'destroyModule'])->middleware('giam.permission:GIAM_ROLE_MANAGE');

            // Permission Groups
            Route::get('/permission-groups', [GiamRbacController::class, 'permissionGroups'])->middleware('giam.permission:GIAM_ROLE_VIEW');
            Route::post('/permission-groups', [GiamRbacController::class, 'storePermissionGroup'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::put('/permission-groups/{id}', [GiamRbacController::class, 'updatePermissionGroup'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::delete('/permission-groups/{id}', [GiamRbacController::class, 'destroyPermissionGroup'])->middleware('giam.permission:GIAM_ROLE_MANAGE');

            // Permissions
            Route::get('/permissions', [GiamRbacController::class, 'permissions'])->middleware('giam.permission:GIAM_ROLE_VIEW');
            Route::post('/permissions', [GiamRbacController::class, 'storePermission'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::put('/permissions/{id}', [GiamRbacController::class, 'updatePermission'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
            Route::delete('/permissions/{id}', [GiamRbacController::class, 'destroyPermission'])->middleware('giam.permission:GIAM_ROLE_MANAGE');
        });
    });

    // Inbound Project Resource APIs (Authenticated via X-API-KEY)
    Route::prefix('integrations/resources')->middleware(['project.api_key', 'throttle:project-resource-api'])->group(function () {
        // Employee master resources
        Route::middleware('project.resource:employees:read')->group(function () {
            Route::get('/employees', [ProjectResourceController::class, 'employees']);
            Route::get('/employees/{employeeCode}', [ProjectResourceController::class, 'showEmployee']);
        });

        // Organizational reference resources
        Route::get('/departments', [ProjectResourceController::class, 'departments'])
            ->middleware('project.resource:departments:read');

        Route::get('/designations', [ProjectResourceController::class, 'designations'])
            ->middleware('project.resource:designations:read');

        Route::get('/branches', [ProjectResourceController::class, 'branches'])
            ->middleware('project.resource:branches:read');

        Route::get('/regions', [ProjectResourceController::class, 'regions'])
            ->middleware('project.resource:regions:read');

        Route::get('/zones', [ProjectResourceController::class, 'zones'])
            ->middleware('project.resource:zones:read');

        Route::get('/provinces', [ProjectResourceController::class, 'provinces'])
            ->middleware('project.resource:provinces:read');
    });
});
