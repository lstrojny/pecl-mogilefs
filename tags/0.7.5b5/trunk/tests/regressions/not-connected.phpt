--TEST--
REGRESSION: MogileFs::put() segfaults if not connected
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/../test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/../test-helper.php';
$client = new MogileFs();
var_dump($client->put(__FILE__, 'test', MOGILEFS_DOMAIN));
?>
==DONE==
--EXPECTF--
bool(false)
==DONE==
