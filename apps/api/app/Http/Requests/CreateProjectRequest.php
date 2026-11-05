<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class CreateProjectRequest extends FormRequest
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
            'name' => ['required', 'string', 'min:3', 'max:190'],
            'environment' => ['nullable', 'string', 'in:local-demo,staging,production'],
            'stack' => ['nullable', 'array'],
            'hostname' => ['nullable', 'string', 'max:190'],
            'repository_path' => ['nullable', 'string', 'max:512'],
            'written_permission_ref' => ['nullable', 'string', 'max:190'],
        ];
    }
}
