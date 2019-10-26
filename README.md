
## Cài đặt

Cài đặt qua composer

``` bash
composer require redmix0901/oauth2-client-sso
```
publish file config vào thư mục config

``` bash
$ php artisan vendor:publish --tag=oauth2-sso-config
```

## Sử dụng

middleware này sẽ luôn làm mới access token khi hết hạn.

``` php
Route::middleware('oauth2-sso') 
```

Nếu bạn muốn redirect về trang Auth Server để đăng nhập nếu user chưa đăng thì thêm redirect phía sau.

``` php
Route::middleware('oauth2-sso:redirect') 
```

Nếu muốn token được gắn trên cookie, để gọi xác thực api thì thêm cookie

``` php
Route::middleware('oauth2-sso:cookie') 
```

Hoặc bạn có thể kết hợp cả 2:

``` php
Route::middleware('oauth2-sso:cookie,redirect') 
```

Nếu cần xác thực Token của user từ Resource Server lên (Auth Server) id.todpev.vn thì dùng guard và config trong file config/auth.php như sau

``` php
'api' => [
    'driver' => 'sso',
    'provider' => 'users',
    'hash' => false,
]
```
Việc xác thực API sẽ có 2 trường hợp:
- Nếu không tách Resource Server và App Server ra làm 2 thì bạn có thể kiểm bằng cách thông qua cookie.

``` php
Route::middleware('oauth2-sso:cookie') 
```
middleware này sẽ gắn token vào cookie và server sẽ kiểm tra token đó để xác thực.

- Trường hợp 2 là tách Resource Server và App Server:
Bạn có xác thực bằng cookie với điều kiện là cả 2 cùng là Laravel, chung APP_KEY và setup subdomain có thể share cookie cho nhau, và khai báo middleware như trên.
Hoặc bạn phải gắn token vào header.

``` php
'Authorization' => 'Bearer ' . $token
```

Nếu muốn lấy thông tin user từ request có thể dùng cách sau.

``` php
$request->get('oauth2_user')
```

Nếu muốn lấy thông tin user từ request API có thể dùng cách sau.

``` php
$request->user()
```

Nếu bạn chọn config mapingUser = true.  
User sẽ được tự động map với user trong database cũa App Server.

Nếu Auth Server trả về 1 user mới thì nó sẽ tự động tạo 1 user với các trường mà Auth Server trả về và được map với fillable trong model User.
Việc của bạn là update thông tin cho user đó trong event:

``` php
Redmix0901\Oauth2Sso\Events\UserSsoCreated::class
```