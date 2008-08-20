--TEST--
MogileFs::listKeys(string prefix, string after, int limit)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();

var_dump($client->listKeys());

var_dump($client->listKeys('pref'));

try {
	var_dump($client->listKeys('pref', 'after'));
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}
try {
	var_dump($client->listKeys('pref', 'prefix'));
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}

?>
==DONE==
--EXPECTF--

Warning: MogileFs::listKeys() expects at least 2 parameters, 0 given in %s on line %d
NULL

Warning: MogileFs::listKeys() expects at least 2 parameters, 1 given in %s on line %d
NULL
string(39) "Pattern does not match the after-value?"
string(52) "No keys match that pattern and after-value (if any)."
==DONE==
