<?php

namespace App\Services\Notifier;

interface NotifierInterface
{
    public function send(array $config, string $title, string $content, ?array $proxy = null): array;
}
