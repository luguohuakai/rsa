<?php

namespace Luguohuakai\Rsa;

class Rsa implements base\Rsa
{
    private $privateKey;
    private $privateKeyString;
    private $publicKey;
    private $publicKeyString;

    /**
     * @param string $privateKeyFile 私钥位置
     * @param string $publicKeyFile 公钥位置
     */
    public function __construct(string $privateKeyFile, string $publicKeyFile)
    {
        $this->privateKey = openssl_pkey_get_private("file://$privateKeyFile");
//        openssl_get_privatekey($this->privateKey);

        $this->publicKey = openssl_pkey_get_public("file://$publicKeyFile");
    }

    /**
     * @param $str
     * @param int $algo
     * @return string|null
     */
    public function sign($str, int $algo = OPENSSL_ALGO_SHA1): ?string
    {
        if (!is_string($str)) return null;
        return openssl_sign($str, $sign, $this->privateKey, $algo) ? base64_encode($sign) : null;
    }

    /**
     * @param $str
     * @param $sign
     * @param int $algo
     * @return bool|null
     */
    public function verify($str, $sign, int $algo = OPENSSL_ALGO_SHA1): ?bool
    {
        if (!is_string($str)) return null;
        $rs = openssl_verify($str, base64_decode($sign), $this->publicKey, $algo);
        if ($rs == 1) return true;
        return false;
    }

    /**
     * @param $str
     * @return string
     */
    public function signPss($str): string
    {
        openssl_pkey_export($this->privateKey, $privateKey);
        return base64_encode(\phpseclib3\Crypt\RSA::loadPrivateKey($privateKey)->sign($str));
    }

    /**
     * @param $str
     * @param $sign
     * @return mixed
     */
    public function verifyPss($str, $sign)
    {
        $publicKey = openssl_pkey_get_details($this->publicKey)['key'];
        return \phpseclib3\Crypt\RSA::loadPublicKey($publicKey)->verify($str, base64_decode($sign));
    }

    /**
     * 一般使用公钥加密
     * @param $str
     * @return string|null
     */
    public function encode($str): ?string
    {
        if (!is_string($str)) return null;
        return openssl_public_encrypt($str, $data, $this->publicKey) ? base64_encode($data) : null;
    }

    /**
     * 一般使用私钥解密
     * @param $str
     * @return mixed|null
     */
    public function decode($str)
    {
        if (!is_string($str)) return null;
        return openssl_private_decrypt(base64_decode($str), $data, $this->privateKey) ? $data : null;
    }

    /**
     * 使用私钥加密
     * @param $str
     * @return string|null
     */
    public function privateEncode($str): ?string
    {
        if (!is_string($str)) return null;
        return openssl_private_encrypt($str, $data, $this->privateKey) ? base64_encode($data) : null;
    }

    /**
     *
     * @param $str
     * @return string|null
     */
    public function publicDecode($str): ?string
    {
        if (!is_string($str)) return null;
        return openssl_public_decrypt(base64_decode($str), $data, $this->publicKey) ? $data : null;
    }

    /**
     * 释放资源
     */
    public function __destruct()
    {
        if (!empty($this->privateKey)) openssl_free_key($this->privateKey);
        if (!empty($this->publicKey)) openssl_free_key($this->publicKey);
    }
}