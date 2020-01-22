<?php

namespace Redmix0901\Oauth2Sso;

use Crypt;
use Carbon\Carbon;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use League\OAuth2\Client\Token\AccessToken;
use Redmix0901\Oauth2Sso\OAuth2SsoProvider;
use Redmix0901\Oauth2Sso\Entities\User;
use League\OAuth2\Client\Provider\GenericResourceOwner;
use Illuminate\Contracts\Events\Dispatcher;
use Redmix0901\Oauth2Sso\Events\UserSsoCreated;
use Redmix0901\Oauth2Sso\Events\RefreshingAccessToken;
use Illuminate\Contracts\Config\Repository as Config;

class SingleSignOn
{
    /**
     *
     * @var Illuminate\Contracts\Config\Repository
     */
    protected $config;

    /** 
     *@var \League\OAuth2\Client\Provider\AbstractProvider 
     */
    protected $provider;

    /**
     * Tên cho cookie.
     *
     * @var string
     */
    public static $cookie = 'topdev_token';

    /**
     * Cho phép SingleSignOn hủy kích hoạt cookie.
     *
     * @var bool
     */
    public static $unserializesCookies = false;

    /**
     * The event dispatcher instance.
     * 
     * @var \Illuminate\Contracts\Events\Dispatcher
     */
    protected $events;

    /**
     * SingleSignOn constructor.
     *
     * @param \Redmix0901\Oauth2Sso\OAuth2SsoProvider $provider
     * @param \Illuminate\Contracts\Events\Dispatcher $events
     */
    public function __construct(OAuth2SsoProvider $provider, Dispatcher $events, Config $config)
    {
        $this->config = $config;
        $this->provider = $provider;
        $this->events = $events;
    }

    /**
     * @return \League\OAuth2\Client\Provider\AbstractProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Lưu trữ $token trên session
     *
     * @param AccessToken $token
     */
    public function setAccessTokenLocal(AccessToken $token)
    {
        session()->put(config('oauth2-sso.session_token'), $token);
    }

    /**
     * Lấy $token trên session
     *
     */
    public function getAccessTokenLocal()
    {
        return session()->get(config('oauth2-sso.session_token'));
    }

    /**
     * Xóa $token trên session
     *
     */
    public function deleteAccessTokenLocal()
    {
        session()->remove(config('oauth2-sso.session_token'));
    }

    /**
     * Lấy thông tin user bằng $token
     *
     * @param AccessToken $token
     *
     * @return \League\OAuth2\Client\Provider\ResourceOwnerInterface
     *
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function getUserByToken(AccessToken $token)
    {
        return $this->mapUser($this->getProvider()
            ->getResourceOwner($token)
        );
    }

    /**
     * Kiểm tra thời gian hết hạn của $accessToken, 
     * sẽ lấy $accessToken mới nếu hết hạn.
     *
     * @param AccessToken $token
     *
     * @return AccessToken
     *
     * @throws IdentityProviderException
     */
    public function refreshTokenIfExpired(AccessToken $token)
    {
        if ($token->hasExpired() && $token->getRefreshToken()) {

            $token = $this->provider->getAccessToken('refresh_token', [
                'refresh_token' => $token->getRefreshToken(),
            ]);

            $this->setAccessTokenLocal($token);

            $this->events->dispatch(new RefreshingAccessToken(
                $token
            ));
        }

        return $token;
    }

    /**
     * Tạo state và trả về URL chuyển hướng sang Auth Server.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function getAuthRedirect()
    {
        $authorizationUrl = $this->provider->getAuthorizationUrl();

        session()->put('oauth2_auth_state', $this->provider->getState());

        return redirect()->guest($authorizationUrl);
    }

    /**
     * Chuyển hướng sang Auth Server để logout.
     *
     * @return \Illuminate\Http\RedirectResponse
     */
    public function getLogoutRedirect()
    {
        $logoutUrl = config('oauth2-sso.oauthconf.urlLogout');

        return redirect()->guest($logoutUrl);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUser($oauth2User)
    {
        $user = $oauth2User->toArray();

        /**
         * Có lỗi Auth Server không thể xác thực được access token sẽ trả về messsage.
         * Thì không cần map user 
         */
        if ( isset($user['message']) 
            && $user['message'] == 'Unauthenticated.') {
            return $oauth2User;
        }

        $user = $this->retrieveUser($user);

        if (empty($user)) {
            throw new MapUserNotFoundException('User not found/create.');
        }

        return new GenericResourceOwner($user->toArray(), 'id') ;

    }

    /**
     * Lấy user từ Auth Server map với bảng user ở App Server. 
     * Nếu không map, thì sẽ trả về 1 model,
     * với các thông tin user từ Auth Server trả về
     *
     * @param array $user
     *
     * @return App\User
     */
    public function retrieveUser($original)
    {
        $model = config('auth.providers.users.model');
        $model = new $model;

        /**
         * Nếu config mapUser là false 
         * thì sẽ trả về model User với các giá trị Auth Server trả về
         */
        if (!config('oauth2-sso.mapingUser')) {

            foreach ($original as $key => $value) {
               $model->{$key} = $value;
            }

            return $model;
        }

        /**
         * Tìm user trong database  với cột set trong config
         */
        $user = $model->where(
            config('oauth2-sso.mapColumn'), 
            $original[config('oauth2-sso.mapColumn')]
        )->first();

        /**
         * Không có user sẽ tạo 1 user mới với các trường 
         * mặc định trả về từ Auth Server và map với 
         * fillable trong model.
         */
        if (empty($user)) {

            $user = $model->create($original);

            /**
             * dispatch event để có thể update thông tin user sau khi tạo.
             */
            $this->events->dispatch(new UserSsoCreated(
                $user
            ));
        }
        
        return $user;
    }

    /**
     * Get hoặc set tên cho cookie API.
     *
     * @param  string|null  $cookie
     * @return string|static
     */
    public static function cookie($cookie = null)
    {
        if (is_null($cookie)) {
            return static::$cookie;
        }

        static::$cookie = $cookie;

        return new static;
    }

    /**
     * Enable cookie serialization.
     *
     * @return static
     */
    public static function withCookieSerialization()
    {
        static::$unserializesCookies = true;

        return new static;
    }

    /**
     * Disable cookie serialization.
     *
     * @return static
     */
    public static function withoutCookieSerialization()
    {
        static::$unserializesCookies = false;

        return new static;
    }

    /**
     * Disable cookie serialization.
     *
     * @return bool
     */
    public function checkCookie()
    {
        $client = new Client(['cookies' => true]);
        $config = $this->config->get('session');

        $cookies = CookieJar::fromArray([
                    $config['cookie'] => Crypt::encrypt(Cookie::get($config['cookie']), false),
                ], $config['domain']);
    
        try {

            $res = $client->request('GET', config('oauth2-sso.oauthconf.urlCheckCookie'), [
                'cookies' => $cookies
            ]);

            return json_decode($res->getBody(), true);

        } catch (Exception $e) {

            return false;
        } 
    }
}
