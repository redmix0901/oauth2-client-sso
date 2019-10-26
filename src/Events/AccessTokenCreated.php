<?php

namespace Redmix0901\Oauth2Sso\Events;
use League\OAuth2\Client\Token\AccessToken;

class AccessTokenCreated
{
    /**
     * new token.
     *
     * @var AccessToken
     */
    public $token;

    /**
     * Create a new event instance.
     *
     * @param  AccessToken  $token
     * @return void
     */
    public function __construct(AccessToken $token)
    {
        $this->token = $token;
    }
}
