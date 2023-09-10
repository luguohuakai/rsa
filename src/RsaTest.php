<?php

namespace Luguohuakai\Rsa;

require '../vendor/autoload.php';

$rsa = new Rsa('private.pem', 'public.pem');
$t = new RsaTest;
//$t->testSign();
//$t->testVerify();
//$t->testSignPss();
//$t->testVerifyPss();
//$t->testEncode();
//$t->testDecode();
$t->testPrivateEncode();
$t->testPublicEncode();


class RsaTest /*extends \Codeception\Test\Unit*/
{
    public function testSign()
    {
        global $rsa;
        $s = $rsa->sign('srun.com');
        var_dump($s);
    }

    public function testVerify()
    {
        global $rsa;
        $sign = 'fa3yq2QTHnaHboVju15JqYCInby4YcNPwpV3FbZlKOcZ5rbzj9Q3s/FBMcR2KAxxKwXdeV+26aj8AZNtR0QxD6PxQ+KbJAfcF60FrbMs4ohCu128tT2ixri6LFgYhXjef0evn8OSDcoz3CKPMLOB3YvkwvEDf4g5khu47v5YKQ+K6BH4ZFMFr8yAMFfEDOYNxZiW49xWDBhP7qoBcih+O5B2ug9pJgWqCXZ5xm3c+zB688VYTrMu0LJcJZ1EAivoaAWbwV41cuYLPx/NU5lMaqlRdLfOPHJXJmApjqpvZ80LU0eOAy37dD2Qp7cRlStRoLXiPA+lsuXvG8uR/0WRrA==';
        $s = $rsa->verify('srun.com', $sign);
        var_dump($s);
    }

    public function testSignPss()
    {
        global $rsa;
        $s = $rsa->signPss('srun.com');
        var_dump($s);
    }

    public function testVerifyPss()
    {
        global $rsa;
        $sign = 'Ti+foKxWh+AAzoAkcZRaJDNQOnub5lVG/DBAsPIdpevCHOtY5GkzoCOy3P0MRYMtELllt//7vsPwlwmr0WCsbGQar5njTnOealwckn9AzCoh9NLpVjf8+CovGOdKqP9vBUGSFa/YRgwQD8uZSaeHSZdqYiJff4gTGAHiEy7hWaiKY6rCihjEks0leoV9/hqXJrhIVO8ZldlTjXUa+wsibrOf9VarOEDycYucKyTRMENnOufrXqSUh818u5ep1NtM3znIm6OPeq/iFdpMrlGhQ9Uqd9Ir6gyvxVMVWt7PdCoDYVZVp7wcH/xa3DodpnDh9THhdOwCagbCwE4L2eGysw==';
        $s = $rsa->verifyPss('srun.com', $sign);
        var_dump($s);
    }

    public function testEncode()
    {
        global $rsa;
        $s = $rsa->encode('srun.com');
        var_dump($s);
    }

    public function testDecode()
    {
        global $rsa;
        $str = 'kcJusHkZuBoMbJvXUI88jUjrvDTZzhHEUbq97deSyaG6noLuvwfSk3Do6J1Fy526tEp9JbFzhIZMRwSS5AZ4ivSWjy95nESMH3qr9ZhCZtkmKxenJWTqjMRmvn/Nd7tF+pdgfsQJHgb2H/WX7Dns0/KcRr5fkBZ/xQiGpTn2mor7OokJqr36uYPB2VKHEavkZJespfI5ExmSwvkGosBGC7ErmxgUuwYT0eAKInTmpyfgFv2t/MMeVljYqpSwkFiDTeTaXN1EAR+3fEFC+UEUS5N3TEhvDQeM2+qho2PMNM9a72tJ2UbdNdiai7qJj4LE8HYBbH/ciM13UpeqG0c4tw==';
        $s = $rsa->decode($str);
        var_dump($s);
    }

    public function testPrivateEncode()
    {
        global $rsa;
        $s = $rsa->privateEncode('srun.com');
        var_dump($s);
    }

    public function testPublicEncode()
    {
        global $rsa;
        $str = 'RNAZrdH3UGAIL3GF8N+Bpnr3M7mssUQ533OzpHamLWSsztVMJpmuivhFWwXSTLkMoVOnK15YCBNetR45wfWYIEnBGWHbvBpALa9jW+Rn0DHSz/PnAkleO2tAp2E797rWUb2pX7ggh8J4KCXjU8HWHLX6ZzN5wUEtcGVDzHZ8r8nFgiZPPy5usZEXB77eaui5Ahw+/H8f3c7E4K8OKgC1OubPw5oLvDZCNscM9CbZ+gzd0U+V85WaugggbjzV7lAOUkz2rrhDBZOyq33SKzor8JbNfBDHwG04TGgxNYSuhzOqFKwoYSM4Ntl019E6vTh8O4O+eI9KF7FWAd4fikusRQ==';
        $s = $rsa->publicDecode($str);
        var_dump($s);
    }
}
