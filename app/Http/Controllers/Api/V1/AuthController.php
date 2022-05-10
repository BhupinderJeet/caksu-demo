<?php

namespace App\Http\Controllers\Api\V1;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Tymon\JWTAuth\JWTAuth;
use App\Models\DeviceToken;
use App\Models\User;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    protected $jwtAuth;
    public function __construct( JWTAuth $jwtAuth )
    {
        $this->jwtAuth = $jwtAuth;
        $this->middleware('auth:api', ['except' => ['register', 'login', 'logout']]);
    }

    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|between:2,100',
            'email' => 'required|email|unique:users|max:50',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            $res = [
                'message' => $validator->messages()->first()
            ];
            return response()->json($res, 422);
        }


        $data = $request->all();
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return response()->json(['message' => 'Email Address is invalid.'], 422);
        }

        $user = new User();
        $user->name = $data['name'];
        $user->email = $data['email'];
        $user->password = bcrypt($data['password']);
        $result = $user->save();
        // return $result;
        if($result) {
            $token = $this->jwtAuth->fromUser($user);
            if(isset($data['device_token']) && isset($data['device_type'])) {
                if(trim($data['device_token']) != "" && trim($data['device_type']) != "" && in_array($data['device_type'], [1, 2])) {
                    $device = new DeviceToken();
                    $device->user_id = $user->id;
                    $device->device_type = $data['device_type'];
                    $device->device_token = $data['device_token'];
                    if(!$device->save()) {
                        $res = ['message' => 'Something went wrong, please try again.'];
                        $code = 422;
                        return response()->json($res, $code);
                    }
                }
            }

            $res = ['message' => 'Registered successfully.', 'token' => $token, 'user' => $user->toArray()];
            $code = 200;
        }   else {
            $res = ['message' => 'Something went wrong, please try again.'];
            $code = 500;
        }
        return response()->json($res, $code);
    }

    /**
     * Get a JWT token via given credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required',
            'device_token' => 'required',
            'device_type' => 'required|in:1,2'
        ]);

        if ($validator->fails()) {
            $res = [
                'success' => false,
                'message' => $validator->messages()->first()
            ];
            return response()->json($res, 422);
        }

        $data = $request->all();
        if (!filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            return response()->json(['success' => false, 'message' => 'Email Address is invalid.'], 422);
        }


        $user = User::where('email', $data['email'])->first();
        if(!$user) {
            return response()->json(['success' => false, 'message' => 'Email & password do not match.'], 422);
        }

        if($user->block_unblock == 1) {
            return response()->json(['success' => false, 'message' => 'Your account is blocked, Please contact Store Manager.'], 422);
        }
        $credentials = $request->only('email', 'password');

        if ($token = auth()->attempt($credentials)) {
            $token_save = DeviceToken::updateOrCreate(['device_token' => $data['device_token'], 'device_type' => $data['device_type']], ['user_id' => $user->id]);

            if(!$token_save) {
                $res = ['success' => false, 'message' => 'Could not save device token.'];
                return response()->json($res, 500);
            }

            $user = auth()->user();
            $res = [
                'success' => true,
                'message' => 'Login successfully.',
                'token' => $token,
                'data' => $user->toArray()
            ];
            return response()->json($res);
        }
        $res = ['success' => false, 'message' => 'Email or Password do not match.'];
        return response()->json($res, 403);
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'device_token' => 'required',
            'device_type' => 'required|in:1,2'
        ]);

        if ($validator->fails()) {
            $res = [
                'success' => false,
                'message' => $validator->messages()->first()
            ];
            return response()->json($res);
        }

        $data = $request->all();
        $user_id = auth('api')->user()->id;
        $token = $this->jwtAuth->parseToken();
        $this->jwtAuth->invalidate($token);

        $data = $request->all();

        $resp = DeviceToken::where('device_token', $data['device_token'])->where('user_id', $user_id)->delete();

        return response()->json(['success'=>true, 'message' => 'Successfully logged out.']);
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard();
    }
}
