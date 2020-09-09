<?php

namespace Redmix0901\Oauth2Sso\Http\Controllers;

use Illuminate\Http\Request;
use Redmix0901\Oauth2Sso\SingleSignOn;
use App\Http\Controllers\Controller;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Redmix0901\Oauth2Sso\Events\UserSsoLogin;
use Redmix0901\Oauth2Sso\Events\AccessTokenCreated;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Config\Repository as Config;
use GuzzleHttp\Client;
use League\OAuth2\Client\Token\AccessToken;
use Redmix0901\Oauth2Sso\Http\Requests\ApiLoginRequest;

class OAuth2SsoController extends Controller
{
    /**
     * The event dispatcher instance.
     * 
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * @var \Redmix0901\Oauth2Sso\SingleSignOn
     */
    protected $singleSignOn;

    /**
     *
     * @var Illuminate\Contracts\Config\Repository
     */
    protected $config;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct(SingleSignOn $singleSignOn, Dispatcher $events, Config $config)
    {
        $this->config = $config;
        $this->events = $events;
        $this->singleSignOn = $singleSignOn;
    }
    
    /**
     * Redirect qua Auth Server để đăng nhập.
     *
     * @return void
     */
    public function login(Request $request)
    {
        $callbackUrl = url()->previous();

        if ($request->redirect_uri) {
            if (count($request->all()) > 1) {
                $_resquest_all = $request->all();
                unset($_resquest_all['redirect_uri']);
                $callbackUrl = $request->redirect_uri . '&' . http_build_query($_resquest_all);
            }else{
                $callbackUrl = $request->redirect_uri;
            }
        }

        $this->singleSignOn->setCallbackUrl($callbackUrl);

        return $this->singleSignOn->getAuthRedirect();
    }

    /**
     * Đăng nhập bằng email, password.
     *
     * @return void
     */
    public function loginWithCredentials(ApiLoginRequest $request)
    {
        $accessToken = $this->singleSignOn->getProvider()->getAccessToken('password', [
            'username' => $request->get('email'),
            'password' => $request->get('password')
        ]);

        $this->singleSignOn->setAccessTokenLocal($accessToken);

        try {

            $resourceOwner = $this->singleSignOn->getUserByToken($accessToken);

            $this->fireEventUserSsoLogin($accessToken, $resourceOwner);

        } catch (IdentityProviderException $e) { }

        $this->fireEventAccessTokenCreated($accessToken);

        return response()->json([
                'code' => 200,
                'message' => 'Login successfully',
                'access_token' => $accessToken->getToken(),
                'expires_in' => $accessToken->getExpires()
            ]);
    }

    /**
     * Redirect qua Auth Server để logout.
     *
     * @return void
     */
    public function logout()
    {
        $this->singleSignOn->deleteAccessTokenLocal();

        return $this->singleSignOn->getLogoutRedirect();
    }

    /**
     * Lấy token mới qua api, 
     * cho trường hợp token store trên cookie hết hạn 
     * hoặc có vấn đề gì không thể xác thực với Auth Server.
     *
     * @return void
     */
    public function issueTokenViaCookie(Request $request)
    {
        /** 
         * Kiểm tra access token từ session
         *
         * @var \League\OAuth2\Client\Token\AccessToken $accessToken 
         */
        $accessToken = $this->singleSignOn->getAccessTokenLocal();

        /**
         * Không có $accessToken tồn tại.
         */
        if (!$accessToken) {
            return response()
                ->json([
                    'error'   => true,
                    'data'    => null,
                    'message' => 'Unauthenticated.',
                ], 401);
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

            return response()
                ->json([
                    'error'   => true,
                    'data'    => null,
                    'message' => 'Unauthenticated.',
                ], 401);
        }

        $user = $resourceOwner->toArray();

        if (isset($user['message']) && $user['message'] == 'Unauthenticated.') {
            /**
             * Xóa $accessToken trên session nếu có lỗi.
             */
            $this->singleSignOn->deleteAccessTokenLocal();

            return response()
                ->json([
                    'error'   => true,
                    'data'    => null,
                    'message' => 'Unauthenticated.',
                ], 401);
        }
        
        $request->attributes->add(['oauth2_user' => $resourceOwner]);
        $config = $this->config->get('session');

        return response()
                ->json([
                    'error' => false,
                    'token' => $accessToken->getToken(),
                    'message' => 'Succses.',
                ], 200)
                ->withCookie(
                    cookie(
                        SingleSignOn::cookie(),
                        $accessToken->getToken(),
                        $config['lifetime']
                    )
                );
    }

    /**
     * Callback trả về code từ Auth Server. Dùng để lấy AccessToken.
     * và lưu trữ AccessToken trên session
     *
     * @param Illuminate\Http\Request $request
     *
     * @return Redirect
     */
    public function callback(Request $request)
    {
        $callbackUrl = $this->singleSignOn->getCallbackUrl();

        if (!$request->has('state') || $request->get('state') !== session()->get('oauth2_auth_state')) {

            session()->remove('oauth2_auth_state');
            \Log::info('request invalid');

            return redirect()->intended($callbackUrl);
        }

        session()->remove('oauth2_auth_state');

        \Log::info('step 1: getAccessToken via code - ' . $request->get('code'));

        $accessToken = $this->singleSignOn->getProvider()->getAccessToken('authorization_code', [
            'code' => $request->get('code'),
        ]);

        $this->singleSignOn->setAccessTokenLocal($accessToken);

        // try {

        //     $resourceOwner = $this->singleSignOn->getUserByToken($accessToken);

        //     $this->fireEventUserSsoLogin($accessToken, $resourceOwner);

        // } catch (IdentityProviderException $e) { }

        $this->fireEventAccessTokenCreated($accessToken);

        \Log::info('step 2: callback '. session()->pull('url.intended', $callbackUrl));

        return redirect()->intended($callbackUrl);
    }

    /**
     *
     * @param League\OAuth2\Client\Token\AccessToken $accessToken
     *
     * @return mixed
     */
    private function fireEventAccessTokenCreated(AccessToken $accessToken)
    {
        $this->events->dispatch(
            new AccessTokenCreated($accessToken)
        );
    }

    /**
     *
     * @param League\OAuth2\Client\Token\AccessToken $accessToken
     * @param $resourceOwner
     *
     * @return mixed
     */
    private function fireEventUserSsoLogin(AccessToken $accessToken, $resourceOwner)
    {
        $this->events->dispatch(new UserSsoLogin(
            $this->singleSignOn->retrieveUser(
                $resourceOwner->toArray()
            ),
            $accessToken
        ));
    }
}
