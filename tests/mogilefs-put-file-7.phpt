--TEST--
MogileFs::put(string path/content, string key, string class, bool file_only = true)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID >= 80000) die("skip PHP 7 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();
var_dump($client->put(__FILE__, 'foo', MOGILEFS_CLASS));
$result = $client->get('foo');
var_dump($result['path1']);
var_dump($result['paths']);
var_dump(file_get_contents(__FILE__) === file_get_contents($result['path1']));
var_dump($client->delete('foo'));

var_dump($client->put('foobarbaz', 'bar', MOGILEFS_CLASS, false));
$result = $client->get('bar');
var_dump($result['path1']);
var_dump($result['paths']);
var_dump('foobarbaz' === file_get_contents($result['path1']));
var_dump($client->delete('bar'));


try {
	$client->put('foobarbaz', 'bar', MOGILEFS_CLASS, true);
} catch (MogileFsException $e) {
	var_dump(get_class($e));
	var_dump($e->getMessage());
}
var_dump($client->put());

?>
==DONE==
--EXPECTF--
bool(true)
string(%d) "http://%s.fid"
string(%d) "%d"
bool(true)
bool(true)
bool(true)
string(%d) "http://%s.fid"
string(%d) "%d"
bool(true)
bool(true)
string(%d) "MogileFsException"
string(%d) "Could not open file"

Warning: MogileFs::put() expects at least 3 parameters, 0 given in %s on line %d
NULL
==DONE==