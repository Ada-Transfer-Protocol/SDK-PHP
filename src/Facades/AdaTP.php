<?php

namespace AdaTP\Facades;

use Illuminate\Support\Facades\Facade;

class AdaTP extends Facade
{
    protected static function getFacadeAccessor()
    {
        return 'adatp';
    }
}
