<?php
namespace Redmix0901\Oauth2Sso;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

use Redmix0901\Oauth2Sso\Guards\SsoGuard;
use Redmix0901\Oauth2Sso\Http\Middleware\OAuth2SsoMiddleware;
use Redmix0901\Oauth2Sso\SingleSignOn;

class SsoServiceProvider extends ServiceProvider
{

    /**
     * Boot the service provider.
     * @author Tu Tran
     */
    public function boot()
    {
        $this->app['router']->aliasMiddleware('oauth2-sso', OAuth2SsoMiddleware::class);

        $this->app->when(SingleSignOn::class)
            ->needs(OAuth2SsoProvider::class)
            ->give(function () {
                return new OAuth2SsoProvider(
                    config('oauth2-sso.oauthconf')
                );
            });

        $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        if (! $this->app->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__.'/../config/oauth2-sso.php', 'oauth2-sso');
        }

        $this->registerGuard();
        $this->offerPublishing();
        
    }

    /**
     * Register the guard.
     *
     * @return void
     */
    protected function registerGuard()
    {
        Auth::extend('sso', function ($app, $name, array $config) {
            return tap($this->makeGuard($config), function ($guard) {
                $this->app->refresh('request', $guard, 'setRequest');
            });
        });
    }

    /**
     * Make an instance of the guard.
     *
     * @param  array  $config
     * @return \Illuminate\Auth\RequestGuard
     */
    protected function makeGuard(array $config)
    {
        return new RequestGuard(function ($request) use ($config) {
            return (new SsoGuard(
                $this->app->make(SingleSignOn::class),
                $this->app->make('encrypter')
            ))->user($request);
        }, $this->app['request']);
    }

    /**
     * Setup the resource publishing groups for SSO.
     *
     * @return void
     */
    protected function offerPublishing()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/oauth2-sso.php' => config_path('oauth2-sso.php'),
            ], 'oauth2-sso-config');
        }
    }

}
