<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use App\Models\User;

class AuthController extends Controller
{
    /**
     * Login user menggunakan autentikasi bawaan Laravel yang aman.
     */
    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email'    => 'required|email',
            'password' => 'required|string',
        ]);

        if (!Auth::attempt($credentials)) {
            return response()->json(['error' => 'Invalid credentials'], 401);
        }

        $user  = Auth::user();
        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'message' => 'Login berhasil',
            'token'   => $token,
        ]);
    }

    /**
     * Register user baru menggunakan Password Hashing (bcrypt/argon2) dan Eloquent ORM.
     */
    public function register(Request $request)
    {
        $validated = $request->validate([
            'name'     => 'required|string|max:255',
            'email'    => 'required|email|unique:users,email',
            'password' => 'required|string|min:8',
        ]);

        $user = User::create([
            'name'     => $validated['name'],
            'email'    => $validated['email'],
            'password' => Hash::make($validated['validated_password'] ?? $validated['password']),
        ]);

        return response()->json([
            'message' => 'Registrasi berhasil',
            'user_id' => $user->id,
        ], 201);
    }

    /**
     * Reset password menggunakan token acak aman (CSPRNG) dan Query Builder terparameter.
     */
    public function resetPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users,email',
        ]);

        $email      = $request->input('email');
        $resetToken = Str::random(40);

        User::where('email', $email)->update([
            'reset_token' => Hash::make($resetToken),
            'updated_at'  => now(),
        ]);

        return response()->json([
            'message' => 'Token reset berhasil dibuat dan dikirim',
        ]);
    }

    /**
     * Logout user / Hapus token saat ini.
     */
    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Logged out successfully',
        ]);
    }
}