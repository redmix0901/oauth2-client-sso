<?php

namespace Redmix0901\Oauth2Sso;

use League\OAuth2\Client\Provider\GenericProvider;

class OAuth2SsoProvider extends GenericProvider
{
    protected function getDefaultHeaders()
    {
        return array_merge(parent::getDefaultHeaders(), [
            'Accept' => 'application/json',
            'User-Agent' => config('app.name', 'redmix0901/oauth2-client-sso'),
        ]);
    }
}
