--TEST--
MogileFS::getDomains()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';

$client = mogilefs_test_factory();

$k = 'mogilefs-fileinfo-testkey';
var_dump($client->put("foo", $k, MOGILEFS_CLASS, false));
var_dump($client->fileInfo($k));
var_dump($client->delete($k));
?>
==DONE==
--EXPECTF--
bool(true)
array(6) {
  ["length"]=>
  string(%d) "3"
  ["domain"]=>
  string(%d) "%s"
  ["fid"]=>
  string(%d) "%d"
  ["devcount"]=>
  string(%d) "%d"
  ["class"]=>
  string(%d) "%s"
  ["key"]=>
  string(%d) "mogilefs-fileinfo-testkey"
}
bool(true)
==DONE==
