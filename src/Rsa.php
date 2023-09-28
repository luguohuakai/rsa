<?php

namespace luguohuakai\rsa;

class Rsa implements base\Rsa
{
    private $privateKey;
    private $publicKey;

    /**
     * @param string $privateKeyFile 私钥文件位置 /path/to/private.pem
     * @param string $publicKeyFile 公钥文件位置 /path/to/public.pem
     */
    public function __construct(string $privateKeyFile, string $publicKeyFile)
    {
        $this->privateKey = openssl_pkey_get_private("file://$privateKeyFile");
        $this->publicKey = openssl_pkey_get_public("file://$publicKeyFile");
    }

    /**
     * 私钥签名
     * @param $str
     * @param int $algo
     * @return string|null 签名值进行base64_encode
     */
    public function sign($str, int $algo = OPENSSL_ALGO_SHA1): ?string
    {
        if (!is_string($str)) return null;
        return openssl_sign($str, $sign, $this->privateKey, $algo) ? base64_encode($sign) : null;
    }

    /**
     * 公钥验签
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
     * PSS模式 私钥签名
     * @param $str
     * @return string 签名值进行base64_encode
     */
    public function signPss($str): string
    {
        openssl_pkey_export($this->privateKey, $privateKey);
        return base64_encode(\phpseclib3\Crypt\RSA::loadPrivateKey($privateKey)->sign($str));
    }

    /**
     * PSS模式 公钥验签
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
     * @return string|null 返回值进行base64_encode
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
     * @return string|null 返回值进行base64_encode
     */
    public function privateEncode($str): ?string
    {
        if (!is_string($str)) return null;
        return openssl_private_encrypt($str, $data, $this->privateKey) ? base64_encode($data) : null;
    }

    /**
     * 使用公钥解密
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