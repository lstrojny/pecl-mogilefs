# PECL MogileFs

MogileFs is a open source distribued filesystem (www.danga.com/mogilefs/). The PECL MogileFs extension allows to communicate with a MogileFs tracker from within PHP.

## Install MogileFs extension

```bash
phpize
./configure
make install
```

## Method overview

 - ``MogileFs MogileFs::__construct()``
 - ``bool MogileFs::connect(string $host, int $port, string $domain[, float $timeout])``
 - ``bool MogileFs::isConnection()``
 - ``bool MogileFs::close()``
 - ``bool MogileFs::put(file, string $key, string $class[, bool $use_file])``
 - ``array MogileFs::file(string $key)``
 - ``array MogileFs::get (string $key)``
 - ``bool MogileFs::delete (string $key)``
 - ``bool MogileFs::rename (string $from_key, string $to_key)``
 - ``array MogileFs::listKeys (string $prefix, string $after, integer $limit)``
 - ``bool MogileFs::listFids (integer $from, integer $to)``
 - ``array MogileFs::getDomains()``
 - ``array MogileFs::getHosts()``
 - ``array MogileFs::getDevices()``
 - ``bool MogileFs::sleep(integer $duration)``
 - ``array MogileFs::stats(integer $all)``
 - ``bool MogileFs::replicate()``
 - ``array MogileFs::createDevice(string $devid, string $status)``
 - ``array MogileFs::createDomain(string $domain)``
 - ``array MogileFs::deleteDomain(string $domain)``
 - ``array MogileFs::createClass(string $domain, string $class, string $mindevcount)``
 - ``array MogileFs::updateClass(string $domain, string $class, string $mindevcount)``
 - ``array MogileFs::createHost(string $hostname)``
 - ``array MogileFs::updateHost(string $hostname, string $ip, int $port[, string $state = "alive"])``
 - ``bool MogileFs::deleteHost(string $hostname)``
 - ``bool MogileFs::setWeight(string $hostname, string $device, string $weight)``
 - ``bool MogileFs::setState(string $hostname, string $device[, string $state = "alive"])``
 - ``bool MogileFs::checker(string $status ("on" or "off"), string $level)``
 - ``void Mogilefs::setReadTimeout(float $readTimeout)``
 - ``float MogileFs::getReadTimeout()``

## Example usage
```php
<?php
$mg = new MogileFs();
$mg->connect('192.168.101.1', 6001, 'myDomain');
$mg->put('/example/file.jpg', 'my_key', 'my_class');
$paths = $mg->get('my_key');
$mg->close();
```

## Licensing
 - Maintainer: Lars Strojny <lstrojny@php.net>
 - License: BSD License
