<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class PaymentController extends Controller
{
    /**
     * Memproses pembayaran secara aman tanpa menyimpan hardcoded secret.
     */
    public function process(Request $request)
    {
        $validated = $request->validate([
            'amount'   => 'required|numeric|min:1',
            'order_id' => 'required|string',
        ]);

        // Secret & Server Key dipanggil saat runtime via config/env, tidak di-hardcode
        $serverKey = config('services.midtrans.server_key');

        return response()->json([
            'status'   => 'pending',
            'order_id' => $validated['order_id'],
            'amount'   => $validated['amount'],
        ]);
    }

    /**
     * Mengambil detail transaksi secara aman dengan verifikasi hak akses (Mencegah IDOR & SQL Injection).
     */
    public function getTransaction(Request $request)
    {
        $validated = $request->validate([
            'transaction_id' => 'required|integer',
        ]);

        // Gunakan Parameter Binding untuk mencegah SQL Injection
        // Dan kunci berdasarkan auth()->id() untuk mencegah IDOR (Insecure Direct Object Reference)
        $transaction = DB::select(
            "SELECT * FROM transactions WHERE id = ? AND user_id = ?",
            [$validated['transaction_id'], auth()->id()]
        );

        if (empty($transaction)) {
            return response()->json(['error' => 'Transaksi tidak ditemukan atau akses ditolak'], 404);
        }

        return response()->json($transaction[0]);
    }
}