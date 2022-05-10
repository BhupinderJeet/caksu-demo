<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class DeviceToken extends Model
{
    use HasFactory;
    protected $table = "device_token";
    protected $fillable = [
        'user_id', 'device_token', 'device_type'
    ];
}
