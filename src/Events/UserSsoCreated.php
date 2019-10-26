<?php

namespace Redmix0901\Oauth2Sso\Events;

class UserSsoCreated
{
    /**
     * The newly created user.
     *
     * @var Model
     */
    public $user;

    /**
     * Create a new event instance.
     *
     * @param  Model  $user
     * @return void
     */
    public function __construct($user)
    {
        $this->user = $user;
    }
}
