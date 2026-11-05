<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class TriggerScanRequest extends FormRequest
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
            'project_id' => ['required', 'string', 'max:64'],
            'grant_id' => ['nullable', 'string', 'max:64'],
            'mode' => ['nullable', 'string', 'in:offline-fixture,local-source,restricted-remote'],
            'fixture_variant' => ['nullable', 'string', 'in:baseline,remediated'],
            'repository_path' => ['nullable', 'string', 'max:512'],
        ];
    }
}

