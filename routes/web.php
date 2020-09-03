<?php

Route::group(['middleware' => ['web'], 'namespace' => 'Redmix0901\Oauth2Sso\Http\Controllers'], function () {
	Route::post(config('oauth2-sso.prefix_route') . '/oauth2/login', 'OAuth2SsoController@loginWithCredentials')->name('sso.login.password_grant');
	Route::get(config('oauth2-sso.prefix_route') . '/oauth2/login', 'OAuth2SsoController@login')->name('sso.login.authorization_code');
	Route::get(config('oauth2-sso.prefix_route') . '/oauth2/logout', 'OAuth2SsoController@logout')->name('sso.logout');
   	Route::get(config('oauth2-sso.prefix_route') . '/oauth2/callback', 'OAuth2SsoController@callback');
   	Route::get(config('oauth2-sso.prefix_route') . '/oauth2/issueToken', 'OAuth2SsoController@issueTokenViaCookie');
});