<?php

namespace App\Core;

class Crypto
{
    private static function getKey(): string
    {
        $rawKey = App::env('APP_KEY', 'default_secret_key_32_bytes_len!!');
        if (str_starts_with($rawKey, 'base64:')) {
            return base64_decode(substr($rawKey, 7));
        }
        return hash('sha256', $rawKey, true);
    }

    public static function encrypt(string $plainText): string
    {
        $key = self::getKey();
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $encrypted = openssl_encrypt($plainText, 'aes-256-cbc', $key, 0, $iv);
        return base64_encode($iv . '::' . $encrypted);
    }

    public static function decrypt(string $cipherText): ?string
    {
        try {
            $decoded = base64_decode($cipherText);
            if (!str_contains($decoded, '::')) {
                return null;
            }
            [$iv, $encrypted] = explode('::', $decoded, 2);
            $key = self::getKey();
            $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, 0, $iv);
            return $decrypted !== false ? $decrypted : null;
        } catch (\Throwable $e) {
            return null;
        }
    }
}
