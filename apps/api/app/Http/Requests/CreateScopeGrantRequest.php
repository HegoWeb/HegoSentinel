<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class CreateScopeGrantRequest extends FormRequest
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
            'written_permission_ref' => ['required', 'string', 'min:3', 'max:190'],
            'domain_control_proof' => ['required', 'string', 'min:3', 'max:255', 'different:written_permission_ref'],
            'authorization_statement' => ['nullable', 'string'],
            'hostname' => ['nullable', 'string', 'max:190'],
            'port' => ['nullable', 'integer', 'min:1', 'max:65535'],
            'path_prefix' => ['nullable', 'string', 'max:255'],
            'repository_path' => ['nullable', 'string', 'max:512'],
            'max_request_budget' => ['nullable', 'integer', 'min:1', 'max:25'],
        ];
    }
}

