<?php

namespace Redmix0901\Oauth2Sso\Events;
use League\OAuth2\Client\Token\AccessToken;

class UserSsoLogin
{
    /**
     * The newly created user.
     *
     * @var Model
     */
    public $user;

    /**
     * new token.
     *
     * @var AccessToken
     */
    public $token;
    
    /**
     * Create a new event instance.
     *
     * @param  Model  $user
     * @return void
     */
    public function __construct($user, AccessToken $token)
    {
        $this->user = $user;
        $this->token = $token;
    }
}
