<?php

namespace Redmix0901\Oauth2Sso\Http\Middleware;

use Closure;
use Redmix0901\Oauth2Sso\SingleSignOn;

class AddTokenHeader
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (!$request->bearerToken()) {
            if ($request->hasCookie(SingleSignOn::$cookie)) {
                $token = $request->cookie(SingleSignOn::$cookie);
                $request->headers->add(['Authorization' => 'Bearer ' . $token]);
            }
        }

        return $next($request);
    }
}