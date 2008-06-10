--TEST--
Test MogileFS connection method
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

// Invalid host
$client = new MogileFs();
try {
	$client->connect("foobarbaz", 100000, "foodomain");
} catch (MogileFsException $e) {
	var_dump($e->getMessage(), $e->getCode());
}

// Timeout more than MAX INT
$client = new MogileFs();
try {
	$client->connect('testhost', 1234, 'domain', PHP_INT_MAX + 1);
} catch (MogileFsException $e) {
	var_dump($e->getMessage(), $e->getCode());
}

// Unsigned integer as timeout
$client = new MogileFs();
try {
	$client->connect('testhost', 1234, 'domain', -1);
} catch (MogileFsException $e) {
	var_dump($e->getMessage(), $e->getCode());
}
?>
==DONE==
--EXPECTF--
bool(true)

Warning: %s on line %d
string(%d) "Can't connect to %s:%d"
int(0)
string(%d) "Invalid timeout"
int(0)
string(%d) "Invalid timeout"
int(0)
==DONE==
