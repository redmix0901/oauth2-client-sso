<?php
namespace Redmix0901\Oauth2Sso\Guards;

use Exception;
use Cookie;
use Crypt;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Redmix0901\Oauth2Sso\SingleSignOn;
use Illuminate\Contracts\Encryption\DecryptException;

class SsoSessionGuard
{
    /** 
     *@var SingleSignOn 
     */
    protected $singleSignOn;

    /**
     * __construct
     *
     */
    public function __construct(SingleSignOn $singleSignOn)
    {
        $this->singleSignOn = $singleSignOn;
    }

    /**
     * Get the user for the incoming request.
     *
     * @param Request $request
     * @return \Illuminate\Contracts\Auth\Authenticatable|null|void
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function user(Request $request)
    {
        $resourceOwner = $request->get('oauth2_user');

        if (! empty($resourceOwner)) {
            return $this->singleSignOn->retrieveUser(
                $resourceOwner->toArray()
            );
        }

        return null;
    }

}
