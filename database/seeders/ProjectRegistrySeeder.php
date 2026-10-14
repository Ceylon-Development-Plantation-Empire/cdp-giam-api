<?php

namespace Database\Seeders;

use App\Services\Integration\ProjectOnboardingService;
use Illuminate\Database\Seeder;

class ProjectRegistrySeeder extends Seeder
{
    public function __construct(
        protected ?ProjectOnboardingService $onboardingService = null
    ) {
        $this->onboardingService = $onboardingService ?? app(ProjectOnboardingService::class);
    }

    /**
     * Run the database seeds.
     *
     * Used exclusively for fresh environment provisioning, CI testing, and controlled
     * initial bootstrap of all approved downstream project definitions.
     *
     * Normal operational onboarding of individual downstream projects must use:
     *   php artisan giam:onboard-project {code}
     */
    public function run(?ProjectOnboardingService $onboardingService = null): void
    {
        $service = $onboardingService ?? $this->onboardingService;

        $projectCodes = array_keys(config('projects.definitions', []));

        foreach ($projectCodes as $code) {
            $service->onboard($code, strict: false);
        }
    }
}
