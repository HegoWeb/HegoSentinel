<?php

declare(strict_types=1);

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;

final class AuthRegisterRequest extends FormRequest
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
            'email' => ['required', 'string', 'email', 'max:190'],
            'name' => ['required', 'string', 'min:2', 'max:190'],
            'password' => ['required', 'string', 'min:10', 'max:255'],
            'organization_name' => ['nullable', 'string', 'max:190'],
            'preferred_locale' => ['nullable', 'string', 'in:tr,en'],
        ];
    }
}

