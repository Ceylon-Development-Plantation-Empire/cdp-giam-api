<?php

namespace App\Http\Requests\Draft;

use Illuminate\Foundation\Http\FormRequest;

class SaveDraftRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Prepare the data for validation, stripping prohibited credentials.
     */
    protected function prepareForValidation(): void
    {
        if ($this->has('form_data') && is_array($this->input('form_data'))) {
            $formData = $this->input('form_data');
            $cleanData = app(\App\Services\User\DraftService::class)->sanitizeFormData($formData);
            $this->merge(['form_data' => $cleanData]);
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
            'draft_token' => ['nullable', 'string', 'max:64'],
            'current_step' => ['required', 'integer', 'between:1,3'],
            'form_data' => ['required', 'array'],
        ];
    }
}
