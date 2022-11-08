--TEST--
MogileFS::fileInfo()
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
$file_info = $client->fileInfo($k);
ksort($file_info); // Ensure key ordering, It seems like the implementation of var_dump has changed in PHP 7.
var_dump($file_info);
var_dump($client->delete($k));
?>
==DONE==
--EXPECTF--
bool(true)
array(6) {
  ["class"]=>
  string(%d) "%s"
  ["devcount"]=>
  string(%d) "%d"
  ["domain"]=>
  string(%d) "%s"
  ["fid"]=>
  string(%d) "%d"
  ["key"]=>
  string(%d) "mogilefs-fileinfo-testkey"
  ["length"]=>
  string(%d) "3"
}
bool(true)
==DONE==