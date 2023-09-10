# rsa 非对称加密

simple ssl rsa sign verify

# 使用方法

* 首先生成公钥/私钥对 如: private.pem public.pem

> 生成方式: 自己想办法用什么工具生成

```php

```

```shell
# Linux

# Windows

```

* 公钥加密

```php
(new \Luguohuakai\Rsa\Rsa('private.pem','public.pem'))->encode('xxx');
```

* 私钥解密

```php
(new \Luguohuakai\Rsa\Rsa('private.pem','public.pem'))->decode('xxx');
```

* 私钥签名
* PSS签名

```php
(new \Luguohuakai\Rsa\Rsa('private.pem','public.pem'))->sign('xxx');
(new \Luguohuakai\Rsa\Rsa('private.pem','public.pem'))->signPss('xxx');
```

* 公钥验签
* PSS验签

```php
(new \Luguohuakai\Rsa\Rsa('private.pem','public.pem'))->verify('xxx');
(new \Luguohuakai\Rsa\Rsa('private.pem','public.pem'))->verifyPss('xxx');
```

## 场景解读
