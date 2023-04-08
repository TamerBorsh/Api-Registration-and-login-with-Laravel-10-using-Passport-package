<?php

namespace App\Http\Controllers\Api\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Http\Requests\Auth\RegisterRequest;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class LoginController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api')->only(['user']);
    }

    public function user()
    {
        return Auth::user();
    }

    public function authenticate(LoginRequest $request)
    {
        $user = User::where('email', $request->post('email'))->first();
        if (!$user) {
            return response()->json(
                ['code' => Response::HTTP_NOT_FOUND, 'message' => __('The user does not exist')],
                Response::HTTP_NOT_FOUND
            );
        }
        // return $user;
        if (Hash::check($request->post('password'), $user->password)) {

            $token = $user->createToken('User-Api')->accessToken;

            return response()->json([
                'code' => Response::HTTP_OK,
                'access_token' => $token,
                'token_type' => 'Bearer',
                'message' => 'User login successfully',
            ], Response::HTTP_OK);
        } else {
            return response()->json([
                'code' => Response::HTTP_UNAUTHORIZED,
                'error' => 'Unauthorized'
            ], Response::HTTP_UNAUTHORIZED);
        }
    }

    public function register(RegisterRequest $request)
    {
            $isCreate = User::create($request->only(['name', 'email', 'password']));
            if ($isCreate) {
                $token = $isCreate->createToken('User-Api')->accessToken;
                return response()->json([
                    'code' => Response::HTTP_CREATED,
                    'access_token' => $token,
                    'token_type' => 'Bearer',
                    'message' => __('You have been registered successfully'),
                ], Response::HTTP_CREATED);
            }else{
                return response()->json([
                    'code' => Response::HTTP_BAD_REQUEST,
                    'error' => 'BAD_REQUEST'
                ], Response::HTTP_BAD_REQUEST);
            }

    }
}
