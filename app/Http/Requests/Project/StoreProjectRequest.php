<?php

namespace App\Http\Requests\Project;

use App\Services\Security\UrlSecurityValidator;
use Closure;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreProjectRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        $urlValidator = app(UrlSecurityValidator::class);

        return [
            'code' => ['required', 'string', 'max:50', 'alpha_dash', 'unique:projects,code'],
            'name' => ['required', 'string', 'max:100'],
            'description' => ['nullable', 'string'],
            'base_url' => [
                'required',
                'url',
                'max:255',
                function (string $attribute, mixed $value, Closure $fail) use ($urlValidator) {
                    if (is_string($value)) {
                        $check = $urlValidator->validate($value);
                        if (! $check['valid']) {
                            $fail($check['error'] ?? 'Invalid base URL.');
                        }
                    }
                },
            ],
            'icon_url' => ['nullable', 'string', 'max:255'],
            'status' => ['sometimes', Rule::in(['active', 'maintenance', 'disabled'])],
            'api_base_url' => [
                'nullable',
                'url',
                'max:255',
                function (string $attribute, mixed $value, Closure $fail) use ($urlValidator) {
                    if (is_string($value) && ! empty($value)) {
                        $check = $urlValidator->validate($value);
                        if (! $check['valid']) {
                            $fail($check['error'] ?? 'Invalid API base URL.');
                        }
                    }
                },
            ],
            'auth_method' => ['nullable', Rule::in(['bearer_token', 'api_key', 'oauth2', 'hmac'])],
            'redirect_uris' => ['nullable', 'array'],
            'redirect_uris.*' => [
                'url',
                function (string $attribute, mixed $value, Closure $fail) use ($urlValidator) {
                    if (is_string($value)) {
                        $check = $urlValidator->validate($value);
                        if (! $check['valid']) {
                            $fail($check['error'] ?? 'Invalid redirect URI.');
                        }
                    }
                },
            ],
            'allowed_user_fields' => ['nullable', 'array'],
        ];
    }
}
