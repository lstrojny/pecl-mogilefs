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
try {
	$client->put(__FILE__, 'test', MOGILEFS_DOMAIN);
} catch (MogileFsException $e) {
	var_dump(get_class($e));
	var_dump($e->getMessage());
}
?>
==DONE==
--EXPECTF--
string(%d) "MogileFsException"
string(%d) "Could not connect to MogileFS tracker"
==DONE==
