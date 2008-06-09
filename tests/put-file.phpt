--TEST--
Test putting a file on the server
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();
var_dump($client->put(__FILE__, 'foo', MOGILEFS_CLASS));
var_dump($result = $client->get('foo'));
var_dump(file_get_contents(__FILE__) === file_get_contents($result['path1']));


var_dump($client->put('foobarbaz', 'bar', MOGILEFS_CLASS));
var_dump($result = $client->get('bar'));
var_dump('foobarbaz' === file_get_contents($result['path1']));
?>
==DONE==
--EXPECTF--
bool(true)
array(%d) {
  ["path1"]=>
  string(%d) "http://%s.fid"
  ["paths"]=>
  string(%d) "1"
}
bool(true)
bool(true)
array(%d) {
  ["path1"]=>
  string(%d) "http://%s.fid"
  ["paths"]=>
  string(%d) "1"
}
bool(true)
==DONE==
