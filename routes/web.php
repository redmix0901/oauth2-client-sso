<?php

Route::group(['middleware' => ['web'], 'namespace' => 'Redmix0901\Oauth2Sso\Http\Controllers'], function () {
	Route::get('/oauth2/login', 'OAuth2SsoController@login')->name('sso.login');
	Route::get('/oauth2/logout', 'OAuth2SsoController@logout')->name('sso.logout');
   	Route::get('/oauth2/callback', 'OAuth2SsoController@callback');
   	Route::get('/oauth2/issueToken', 'OAuth2SsoController@issueTokenViaCookie');
});