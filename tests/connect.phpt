--TEST--
Test MogileFS connection method
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = new MogileFs();
var_dump($client->connect(MOGILEFS_HOST, MOGILEFS_PORT, MOGILEFS_DOMAIN));
?>
==DONE==
--EXPECT--
bool(true)
==DONE==
