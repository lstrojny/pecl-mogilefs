--TEST--
MogileFs::put(string path/content, string key, string class, bool file_only = true)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
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


var_dump($client->put('foobarbaz', 'bar', MOGILEFS_CLASS, true));
var_dump($client->put());


$obj = mogilefs_test_factory(true);
var_dump(mogilefs_put($obj, __FILE__, 'foobar', MOGILEFS_CLASS));
$result = mogilefs_get($obj, 'foobar');
var_dump($result['path1']);
var_dump($result['paths']);
var_dump(file_get_contents(__FILE__) === file_get_contents($result['path1']));

var_dump(mogilefs_put($obj, 'foobarbar', 'barfoo', MOGILEFS_CLASS, false));
$result = mogilefs_get($obj, 'barfoo');
var_dump($result['path1']);
var_dump($result['paths']);
var_dump('foobarbar' === file_get_contents($result['path1']));
var_dump(mogilefs_delete($obj, 'barfoo'));

var_dump(mogilefs_put($obj, 'foobarbar', 'bazbarfoo', MOGILEFS_CLASS, true));

var_dump(mogilefs_put());
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
bool(false)

Warning: MogileFs::put() expects at least 3 parameters, 0 given in %s on line %d
bool(false)
bool(true)
string(%d) "http://%s.fid"
string(%d) "%d"
bool(true)
bool(true)
string(%d) "http://%s.fid"
string(%d) "%d"
bool(true)
bool(true)
bool(false)

Warning: mogilefs_put() expects at least 4 parameters, 0 given in %s on line %d
bool(false)
==DONE==
