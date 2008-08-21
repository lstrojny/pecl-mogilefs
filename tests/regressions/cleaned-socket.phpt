--TEST--
Socket is cleaned after operation
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/../test-helper.php';
if (mogilefs_skipped()) {
	print "skip";
} else {
	$client = mogilefs_test_factory();
	$client->put(__FILE__, 'test1', MOGILEFS_CLASS);
}
--FILE--
<?php
require_once dirname(__FILE__) . '/../test-helper.php';
$client = mogilefs_test_factory();
var_dump(is_array($client->listKeys('te', 'test')));
var_dump($client->put(__FILE__, 'test2', MOGILEFS_CLASS));
?>
==DONE==
--CLEAN--
require_once dirname(__FILE__) . '/../test-helper.php';
$client = mogilefs_test_factory();
$client->delete('test1');
$client->delete('test2');
--EXPECTF--
bool(true)
bool(true)
==DONE==
