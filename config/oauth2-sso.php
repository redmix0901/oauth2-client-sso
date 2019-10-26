<?php

return [
    'oauthconf' => [
        'clientId' => env('OAUTH2_CLIENT_ID'), // The client ID assigned to you by the provider
        'clientSecret' => env('OAUTH2_CLIENT_SECRET'), // The client password assigned to you by the provider
        'redirectUri' => env('OAUTH2_URL_CALLBACK'), //'https://topdemy.vn/oauth2/callback',
        'urlAuthorize' => env('OAUTH2_URL_AUTHORIZE'), //'https://id.topdev.vn/oauth/authorize',
        'urlAccessToken' => env('OAUTH2_URL_ACCESSTOKEN'), //'https://id.topdev.vn/oauth/token',
        'urlLogout' => env('OAUTH2_URL_LOGOUT'), //'https://id.topdev.vn/logout',
        'urlResourceOwnerDetails' => env('OAUTH2_URL_RESOURCE_OWNER'), //'https://id.topdev.vn/api/v1/user',
    ],
    'mapingUser' => true,
    'mapColumn' => 'email' // email, username
];