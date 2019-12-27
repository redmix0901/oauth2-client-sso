<?php

Route::group(['middleware' => ['web'], 'namespace' => 'Redmix0901\Oauth2Sso\Http\Controllers'], function () {
	Route::post('/oauth2/login', 'OAuth2SsoController@loginWithCredentials')->name('sso.login.password_grant');
	Route::get('/oauth2/login', 'OAuth2SsoController@login')->name('sso.login.authorization_code');
	Route::get('/oauth2/logout', 'OAuth2SsoController@logout')->name('sso.logout');
   	Route::get('/oauth2/callback', 'OAuth2SsoController@callback');
   	Route::get('/oauth2/issueToken', 'OAuth2SsoController@issueTokenViaCookie');
});