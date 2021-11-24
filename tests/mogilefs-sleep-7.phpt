--TEST--
MogileFs::sleep(int time)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID >= 80000) die("skip PHP 7 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';

$client = mogilefs_test_factory();
$start = microtime(true);
var_dump($client->sleep(1));
$end = (microtime(true) - $start);
var_dump($end >= 1);

var_dump($client->sleep("wrong"));
?>
==DONE==
--EXPECTF--
bool(true)
bool(true)

Warning: MogileFs::sleep() expects parameter 1 to be int, string given in %s on line %d
NULL
==DONE==