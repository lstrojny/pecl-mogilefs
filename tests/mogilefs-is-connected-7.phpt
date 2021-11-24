--TEST--
MogileFs::isConnected()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID >= 80000) die("skip PHP 7 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = new MogileFs();
var_dump($client->isConnected());
$client = mogilefs_test_factory();
var_dump($client->isConnected());
$client->close();
var_dump($client->isConnected());


var_dump($client->isConnected('invalid param'));
--EXPECTF--
bool(false)
bool(true)
bool(false)

Warning: MogileFs::isConnected() expects exactly 0 parameters, 1 given in %s on line %d
NULL