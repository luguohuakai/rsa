<?php

namespace luguohuakai\rsa\base;

interface Rsa
{
    public function sign($str);

    /**
     * 使用pss填充模式签名更安全
     * @param $str
     * @return mixed
     */
    public function signPss($str);

    public function verify($str, $sign);

    /**
     * 验证使用pss填充模式签名的字符串
     * @param $str
     * @param $sign
     * @return mixed
     */
    public function verifyPss($str, $sign);

    public function encode($str);

    public function decode($str);

    public function privateEncode($str);

    public function publicDecode($str);
}