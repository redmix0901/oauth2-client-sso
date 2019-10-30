<?php
namespace Redmix0901\Oauth2Sso\Guards;

use Exception;
use Cookie;
use Crypt;
use GuzzleHttp\Client;
use Illuminate\Http\Request;
use Redmix0901\Oauth2Sso\SingleSignOn;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Auth\GuardHelpers;

class SsoSessionGuard
{
    use GuardHelpers;

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

        // Nếu chúng tôi đã truy xuất người dùng cho yêu cầu hiện tại, chúng tôi chỉ có thể
        // trả lại ngay lập tức. Chúng tôi không muốn lấy dữ liệu người dùng trên
        // mọi cuộc gọi đến phương thức này bởi vì điều đó sẽ rất chậm.
        if (! is_null($this->user)) {
            return $this->user;
        }

        if (is_null($this->user) && !empty($resourceOwner)) {
            $this->user = $this->singleSignOn->retrieveUser(
                $resourceOwner->toArray()
            );
        }

        return $this->user;
    }

}
