<?php

namespace AdaTP\Providers;

use Illuminate\Support\ServiceProvider;
use AdaTP\Client;

class AdaTPServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('adatp', function ($app) {
            $config = $app['config']['adatp'] ?? [];
            $host = $config['host'] ?? '127.0.0.1';
            $port = $config['port'] ?? 3000;
            
            return new Client($host, $port);
        });
    }

    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/adatp.php' => config_path('adatp.php'),
            ], 'adatp-config');
        }
    }
}
