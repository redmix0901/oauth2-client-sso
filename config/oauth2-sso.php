<?php

return [
    'oauthconf' => [
        'clientId' => env('OAUTH2_CLIENT_ID'), // The client ID assigned to you by the provider
        'clientSecret' => env('OAUTH2_CLIENT_SECRET'), // The client password assigned to you by the provider
        'redirectUri' => env('OAUTH2_URL_CALLBACK'), //'https://topdemy.vn/oauth2/callback',
        'urlAuthorize' => env('OAUTH2_URL_AUTHORIZE'), //'https://accounts.topdev.vn/oauth/authorize',
        'urlAccessToken' => env('OAUTH2_URL_ACCESSTOKEN'), //'https://accounts.topdev.vn/oauth/token',
        'urlLogout' => env('OAUTH2_URL_LOGOUT'), //'https://accounts.topdev.vn/logout',
        'urlCheckCookie' => env('OAUTH2_URL_CHECK_COOKIE'), //'https://accounts.topdev.vn/checkCookie',
        'urlResourceOwnerDetails' => env('OAUTH2_URL_RESOURCE_OWNER'), //'https://accounts.topdev.vn/api/v1/user',
    ],
    'prefix_route' => null,
    'session_id' => env('SESSION_ID', 'TDSID'),
    'session_token' => env('SESSION_TOKEN', 'oauth2_session'),
    'mapingUser' => true,
    'mapColumn' => 'email' // email, username
];