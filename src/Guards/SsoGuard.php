<?php
namespace Redmix0901\Oauth2Sso\Guards;

use Exception;
use Cookie;
use Crypt;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Illuminate\Contracts\Encryption\Encrypter;
use Redmix0901\Oauth2Sso\SingleSignOn;
use Illuminate\Contracts\Encryption\DecryptException;

class SsoGuard
{
    /** 
     *@var SingleSignOn 
     */
    protected $singleSignOn;

    /**
     * The encrypter implementation.
     *
     * @var \Illuminate\Contracts\Encryption\Encrypter
     */
    protected $encrypter;

    public function __construct(SingleSignOn $singleSignOn, Encrypter $encrypter)
    {
        $this->encrypter = $encrypter;
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
        if ($request->bearerToken()) {
            return $this->authenticateViaOauthServer($request->bearerToken());
        } elseif ($this->getTokenViaCookie($request)) {

            $token = $this->getTokenViaCookie($request);
            return $this->authenticateViaOauthServer($token);
        }
    }

    /**
     * Authenticate via oAuth server
     *
     * @param $token
     * @return mixed, \Illuminate\Contracts\Auth\Authenticatable|null|void
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    protected function authenticateViaOauthServer($token)
    {
        $client = new Client();

        try {
            $res = $client->request('GET', config('oauth2-sso.oauthconf.urlResourceOwnerDetails'), [
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer ' . $token
                ]
            ]);

            // Get the body as json decoded
            $user = json_decode($res->getBody(), true);

            return $this->singleSignOn->retrieveUser($user);

        } catch (Exception $e) {

            return null;
        } 
    }

    /**
     * Get the token cookie via the incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return mixed
     */
    protected function getTokenViaCookie($request)
    {
        try {

            $token = Crypt::decrypt(
                Cookie::get(SingleSignOn::cookie()), 
                SingleSignOn::$unserializesCookies
            );

        } catch (DecryptException $e) {
            return;
        }

        return $token;
    }

}
