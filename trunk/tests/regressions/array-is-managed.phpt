--TEST--
Array is managed by ZE and must not free the token
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/../test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/../test-helper.php';
$client = mogilefs_test_factory();
var_dump($client->put(__FILE__, 'foo', MOGILEFS_CLASS));
var_dump(is_array($client->get('foo')));
var_dump(is_array($client->get('foo')));
$result = $client->get('foo');
var_dump(is_array($result));
?>
==DONE==
--EXPECTF--
bool(true)
bool(true)
bool(true)
bool(true)
==DONE==
