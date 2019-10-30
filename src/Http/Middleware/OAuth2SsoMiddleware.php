<?php

namespace Redmix0901\Oauth2Sso\Http\Middleware;

use Closure;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Contracts\Config\Repository as Config;
use Redmix0901\Oauth2Sso\SingleSignOn;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Request;

class OAuth2SsoMiddleware
{
    /** 
     *@var string 
     */
    const ACTION_REDIRECT = 'redirect';

    /** 
     *@var string 
     */
    const ACTION_CREATE_COOKIE = 'cookie';

    /** 
     *@var SingleSignOn 
     */
    protected $singleSignOn;

    /**
     * The API token cookie factory instance.
     *
     * @var \Laravel\Passport\ApiTokenCookieFactory
     */
    protected $config;

    /**
     * OAuth2SsoMiddleware constructor.
     *
     * @param Repository $config
     * @param SingleSignOn $singleSignOn
     */
    public function __construct(SingleSignOn $singleSignOn, Config $config)
    {
        $this->config = $config;
        $this->singleSignOn = $singleSignOn;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string[]  ...$action
     * @return mixed
     *
     * @throws \IdentityProviderException
     */
    public function handle($request, Closure $next, ...$action)
    {
        if (empty($action)) {
            $action = [null];
        }

        /** 
         *
         * @var \League\OAuth2\Client\Token\AccessToken $accessToken 
         */
        $accessToken = $this->singleSignOn->getAccessTokenLocal();

        /**
         * Không có $accessToken tồn tại.
         */
        if (!$accessToken) {
            return $this->redirectTo($request, $next($request), $action);
        }

        try {

            /**
             * Xem $accessToken hết hạn sử dụng chưa.
             * Nếu hết hạn sẽ lấy $accessToken và 
             * refresh token mới bằng refresh token hiện tại.
             */
            $accessToken = $this->singleSignOn->refreshTokenIfExpired($accessToken);

            /**
             * Kiểm tra bằng cách lấy resource owner bằng $accessToken.
             */
            $resourceOwner = $this->singleSignOn->getUserByToken($accessToken);

        } catch (IdentityProviderException $e) {

            /**
             * Xóa $accessToken trên session nếu có lỗi.
             */
            $this->singleSignOn->deleteAccessTokenLocal();

            return $this->redirectTo($request, $next($request), $action);
        }

        $user = $resourceOwner->toArray();

        if (isset($user['message']) && $user['message'] == 'Unauthenticated.') {
            /**
             * Xóa $accessToken trên session nếu có lỗi.
             */
            $this->singleSignOn->deleteAccessTokenLocal();

            return $this->redirectTo($request, $next($request), $action);
        }
        
        $request->attributes->add(['oauth2_user' => $resourceOwner]);

        return $this->sendReponse($request, $next($request), $action);
    }

    /**
     * Trả về reponse sau khi tạo mới token.
     *
     * Token sẽ được gắn trên cookie nếu có yêu cầu và hợp lệ.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Http\Response  $response
     * @param  string[]  ...$action
     * @return \Illuminate\Http\Response
     */
    protected function sendReponse($request, $response, $action)
    {
        if ($this->shouldReceiveFreshAccessToken($request, $response, $action)) {

            $config = $this->config->get('session');

            /** 
             *
             * @var \League\OAuth2\Client\Token\AccessToken $accessToken 
             */
            $accessToken = $this->singleSignOn->getAccessTokenLocal();

            $response->withCookie(
                cookie(
                    SingleSignOn::cookie(),
                    $accessToken->getToken(),
                    $config['lifetime']
                )
            );
        } elseif (Request::hasCookie(SingleSignOn::cookie())) {
            Cookie::queue(Cookie::forget(SingleSignOn::cookie()));
        }

        return $response;
    }

    /**
     * Quyết định xem có được gắn token vào cookie hay không.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Http\Response  $response
     * @param  string[]  ...$action
     * @return bool
     */
    protected function shouldReceiveFreshAccessToken($request, $response, $action)
    {
        /** 
         *
         * @var \League\OAuth2\Client\Token\AccessToken $accessToken 
         */
        $accessToken = $this->singleSignOn->getAccessTokenLocal();

        return in_array(self::ACTION_CREATE_COOKIE, $action) 
                    && $request->isMethod('GET') 
                    && !empty($accessToken) 
                    && !$accessToken->hasExpired();
    }

    /**
     * Kiểm tra token có tồn tại trên cookie chưa.
     *
     * @param  \Illuminate\Http\Response  $response
     * @return bool
     */
    protected function alreadyContainsToken($response)
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === SingleSignOn::cookie()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Redirect về Auth nếu có yêu cầu.
     * 
     * Hoặc tiếp tục request với tạo token trên cookie.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Http\Response  $response
     * @param  string[]  ...$action
     * @return redirect
     */
    protected function redirectTo($request, $response, $action)
    {
        return  in_array(self::ACTION_REDIRECT, $action) 
                ? $this->singleSignOn->getAuthRedirect() 
                    : $this->sendReponse($request, $response, $action) ;
    }
}
