--TEST--
MogileFs::close()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';

// Successfull connect
$client = new MogileFs();
var_dump($client->connect(MOGILEFS_HOST, MOGILEFS_PORT, MOGILEFS_DOMAIN));
var_dump($client->close());
var_dump($client->close());
var_dump($client->close("param"));
?>
==DONE==
--EXPECTF--
bool(true)
bool(true)
bool(false)

Warning: MogileFs::close() expects exactly 0 parameters, 1 given in %s on line %d
bool(false)
==DONE==
