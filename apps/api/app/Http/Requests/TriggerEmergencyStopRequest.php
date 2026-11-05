<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class TriggerEmergencyStopRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    /**
     * @return array<string, list<string>>
     */
    public function rules(): array
    {
        return [
            'project_id' => ['nullable', 'string', 'max:64'],
            'scan_run_id' => ['nullable', 'string', 'max:64'],
            'reason' => ['nullable', 'string', 'max:512'],
            'revoke_project_grants' => ['nullable', 'boolean'],
        ];
    }
}

