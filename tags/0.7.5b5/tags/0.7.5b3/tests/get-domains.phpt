--TEST--
MogileFS::getDomains()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';

$client = mogilefs_test_factory();
$domains = $client->getDomains();
var_dump(is_array($domains));
var_dump(count($domains) > 0);
?>
==DONE==
--EXPECTF--
bool(true)
bool(true)
==DONE==
