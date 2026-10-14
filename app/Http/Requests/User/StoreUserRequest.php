<?php

namespace App\Http\Requests\User;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class StoreUserRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Prepare the data for validation.
     */
    protected function prepareForValidation(): void
    {
        if ($this->has('role') && ! $this->has('roles')) {
            $this->merge(['roles' => [$this->input('role')]]);
        }
        if ($this->has('giam_role') && ! $this->has('roles')) {
            $this->merge(['roles' => [$this->input('giam_role')]]);
        }
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, \Illuminate\Contracts\Validation\ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'employee_code' => ['required', 'string', 'exists:employees,employee_code', 'unique:users,employee_code'],
            'name' => ['required', 'string', 'max:255'],
            'username' => ['required', 'string', 'max:100', 'unique:users,username'],
            'email' => ['required', 'email', 'max:255', 'unique:users,email'],
            'password' => ['nullable', 'string', 'min:8'],
            'user_type' => ['sometimes', Rule::in(['staff', 'admin', 'system'])],
            'can_login' => ['sometimes', 'boolean'],
            'is_active' => ['sometimes', 'boolean'],
            'roles' => ['required', 'array', 'min:1'],
            'roles.*' => ['required', 'string', Rule::exists('roles', 'name')->where('guard_name', 'web')],
        ];
    }
    
    /**
     * Get custom messages for validator errors.
     *
     * @return array<string, string>
     */
    public function messages(): array
    {
        return [
            'roles.required' => 'A valid GIAM internal role must be explicitly selected.',
            'roles.min' => 'A valid GIAM internal role must be explicitly selected.',
            'roles.*.exists' => 'The selected GIAM internal role is invalid or does not exist.',
        ];
    }

    /**
     * Configure the validator instance with soft-deleted account collision detection.
     */
    public function withValidator(\Illuminate\Validation\Validator $validator): void
    {
        $validator->after(function ($validator) {
            $employeeCode = $this->input('employee_code');
            if ($employeeCode) {
                $trashed = \App\Models\User::onlyTrashed()->where('employee_code', $employeeCode)->first();
                if ($trashed) {
                    $validator->errors()->forget('employee_code');
                    $validator->errors()->add(
                        'employee_code',
                        "A soft-deleted account already exists with employee code '{$employeeCode}'. Restore the existing account (ID {$trashed->id}) to preserve identity continuity and audit history."
                    );
                }
            }
            $username = $this->input('username');
            if ($username) {
                $trashedUser = \App\Models\User::onlyTrashed()->where('username', $username)->first();
                if ($trashedUser) {
                    $validator->errors()->forget('username');
                    $validator->errors()->add(
                        'username',
                        "A soft-deleted account already exists with username '{$username}'. Restore the existing account (ID {$trashedUser->id}) to preserve identity continuity and audit history."
                    );
                }
            }
            $email = $this->input('email');
            if ($email) {
                $trashedEmail = \App\Models\User::onlyTrashed()->where('email', $email)->first();
                if ($trashedEmail) {
                    $validator->errors()->forget('email');
                    $validator->errors()->add(
                        'email',
                        "A soft-deleted account already exists with email '{$email}'. Restore the existing account (ID {$trashedEmail->id}) to preserve identity continuity and audit history."
                    );
                }
            }
        });
    }
}
