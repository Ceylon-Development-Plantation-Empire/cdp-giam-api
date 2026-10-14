<?php

$envOrigins = env('CORS_ALLOWED_ORIGINS');
$origins = $envOrigins !== null && $envOrigins !== ''
    ? array_values(array_filter(array_map('trim', explode(',', $envOrigins)), fn ($o) => ! empty($o) && $o !== '*'))
    : [
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:3001',
        'http://127.0.0.1:3001',
    ];

return [

    /*
    |--------------------------------------------------------------------------
    | Cross-Origin Resource Sharing (CORS) Configuration
    |--------------------------------------------------------------------------
    */

    'paths' => ['api/*'],

    'allowed_methods' => ['*'],

    'allowed_origins' => $origins,

    'allowed_origins_patterns' => [],

    'allowed_headers' => ['*'],

    'exposed_headers' => [],

    'max_age' => 86400,

    'supports_credentials' => (bool) env('CORS_SUPPORTS_CREDENTIALS', true),

];
