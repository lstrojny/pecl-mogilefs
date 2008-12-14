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


var_dump($client->put(__FILE__, 'test1', MOGILEFS_CLASS));
var_dump($client->put(__FILE__, 'test2', MOGILEFS_CLASS));
var_dump($client->put(__FILE__, 'test3', MOGILEFS_CLASS));

$result = $client->listKeys('test', 'test', 10);
var_dump($result['key_1']);
var_dump($result['key_2']);
var_dump($result['key_3']);
var_dump($result['key_count']);
var_dump($result['next_after']);

var_dump($client->delete('test1'));
var_dump($client->delete('test2'));
var_dump($client->delete('test3'));
?>
==DONE==
--EXPECTF--

Warning: MogileFs::listKeys() expects at least 2 parameters, 0 given in %s on line %d
NULL

Warning: MogileFs::listKeys() expects at least 2 parameters, 1 given in %s on line %d
NULL
string(39) "Pattern does not match the after-value?"
string(52) "No keys match that pattern and after-value (if any)."
bool(true)
bool(true)
bool(true)
string(5) "test1"
string(5) "test2"
string(5) "test3"
string(1) "3"
string(5) "test3"
bool(true)
bool(true)
bool(true)
==DONE==
