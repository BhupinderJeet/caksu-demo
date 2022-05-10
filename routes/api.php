<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });
Route::group([ 'middleware' => 'api', 'prefix' => 'auth' ], function ($router) {
    Route::post('register', 'App\Http\Controllers\Api\V1\AuthController@register');
    Route::post('login', 'App\Http\Controllers\Api\V1\AuthController@login');
});
Route::group([ 'middleware' => 'jwt.verify' ], function ($router) {
    Route::post('logout', 'App\Http\Controllers\Api\V1\AuthController@logout');
});