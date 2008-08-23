--TEST--
MogileFs::isConnected()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
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


$client = mogilefs_test_factory(true);
var_dump(mogilefs_is_connected($client));
mogilefs_close($client);
var_dump(mogilefs_is_connected($client));


var_dump($client->isConnected('invalid param'));
--EXPECTF--
bool(false)
bool(true)
bool(false)
bool(true)
bool(false)

Invalid parameters for MogileFs::isConnected()
NULL
