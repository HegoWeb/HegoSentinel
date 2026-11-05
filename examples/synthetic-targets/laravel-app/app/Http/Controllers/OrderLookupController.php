<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class OrderLookupController
{
    public function show(Request $request)
    {
        $orderCode = $request->input('code');
        // Intentional synthetic vulnerability for HegoSentinel CODE-001 test
        $query = DB::raw("SELECT id, status FROM orders WHERE code = '" . $orderCode);
        return DB::select($query);
    }
}

