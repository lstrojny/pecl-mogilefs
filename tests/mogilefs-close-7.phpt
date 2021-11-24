--TEST--
MogileFs::close()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID >= 80000) die("skip PHP 7 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';

$client = mogilefs_test_factory();
var_dump($client->close());
var_dump($client->close());
var_dump($client->close("param"));

$client = mogilefs_test_factory();
var_dump($client->disconnect());
var_dump($client->disconnect());
?>
==DONE==
--EXPECTF--
bool(true)
bool(false)

Warning: MogileFs::close() expects exactly 0 parameters, 1 given in %s on line %d
NULL
bool(true)
bool(false)
==DONE==