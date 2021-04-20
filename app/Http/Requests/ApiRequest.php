<?php

namespace App\Http\Requests;

use App\Traits\ApiResponse;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Symfony\Component\HttpFoundation\Response;

abstract class ApiRequest extends FormRequest
{
    use ApiResponse;

    abstract public function rules();

    protected function failedValidation(Validator $validator)
    {
        throw new HttpResponseException($this->apiErrors($validator->errors(), Response::HTTP_UNPROCESSABLE_ENTITY));
    }

    protected function failedAuthorization()
    {
        throw new HttpResponseException($this->apiError(null, Response::HTTP_UNAUTHORIZED));
    }
}