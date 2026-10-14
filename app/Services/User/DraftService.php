<?php

namespace App\Services\User;

use App\Models\User;
use App\Models\UserCreationDraft;
use Illuminate\Support\Str;

/**
 * Service managing temporary multi-step user creation wizard drafts.
 *
 * Draft states are persisted in the MySQL database table `user_creation_drafts` via
 * the UserCreationDraft Eloquent model with a 7-day expiration (`expires_at`).
 * They are not stored in Redis or generic cache.
 */
class DraftService
{
    /**
     * Prohibited sensitive keys that must NEVER be persisted in drafts.
     */
    public const PROHIBITED_KEYS = [
        'password',
        'password_confirmation',
        'new_password',
        'current_password',
        'secret',
        'client_secret',
        'token',
        'access_token',
        'refresh_token',
        'api_key',
        'auth_token',
        'remember_token',
    ];

    /**
     * Recursively strip prohibited credentials and sensitive fields from draft data.
     *
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    public function sanitizeFormData(array $data): array
    {
        $sanitized = [];
        foreach ($data as $key => $value) {
            $normalizedKey = strtolower(trim((string) $key));
            if (in_array($normalizedKey, self::PROHIBITED_KEYS, true) ||
                str_ends_with($normalizedKey, '_password') ||
                str_ends_with($normalizedKey, '_secret') ||
                str_ends_with($normalizedKey, '_token')) {
                continue;
            }

            if (is_array($value)) {
                $sanitized[$key] = $this->sanitizeFormData($value);
            } else {
                $sanitized[$key] = $value;
            }
        }

        return $sanitized;
    }

    /**
     * Save or update a draft state.
     *
     * @param User $creator
     * @param array<string, mixed> $formData
     * @param int $step
     * @param string|null $draftToken
     * @return UserCreationDraft
     */
    public function saveDraft(User $creator, array $formData, int $step, ?string $draftToken = null): UserCreationDraft
    {
        $token = $draftToken ?: (string) Str::uuid();
        $cleanData = $this->sanitizeFormData($formData);

        return UserCreationDraft::updateOrCreate(
             ['draft_token' => $token],
             [
                 'creator_user_id' => $creator->id,
                 'current_step' => $step,
                 'form_data' => $cleanData,
                 'expires_at' => now()->addDays(7),
             ]
        );
    }

    /**
     * Retrieve an active unexpired draft for the creator.
     *
     * @param string $token
     * @param User $creator
     * @return UserCreationDraft|null
     */
    public function getDraft(string $token, User $creator): ?UserCreationDraft
    {
        $draft = UserCreationDraft::where('draft_token', $token)
            ->where('creator_user_id', $creator->id)
            ->where('expires_at', '>', now())
            ->first();

        if ($draft && is_array($draft->form_data)) {
            $draft->form_data = $this->sanitizeFormData($draft->form_data);
        }

        return $draft;
    }

    /**
     * Delete an active draft.
     *
     * @param string $token
     * @param User $creator
     * @return bool
     */
    public function deleteDraft(string $token, User $creator): bool
    {
        return (bool) UserCreationDraft::where('draft_token', $token)
            ->where('creator_user_id', $creator->id)
            ->delete();
    }
}
