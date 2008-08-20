--TEST--
MogileFs::rename(string key, string new_key)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';

$client = mogilefs_test_factory();
$client->put(__FILE__, 'test', MOGILEFS_CLASS);
$result1 = $client->get('test');
$content1 = file_get_contents($result1['path1']);
$client->rename('test', 'test2');
$result2 = $client->get('test2');
$content2 = file_get_contents($result2['path1']);
var_dump($content1 === $content2);
try {
	$client->get('test');
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}
$client->put(__FILE__, 'test', MOGILEFS_CLASS);
try {
	$client->rename('test', 'test2');
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}
var_dump($client->delete('test'));
var_dump($client->delete('test2'));
?>
==DONE==
--EXPECTF--
bool(true)
string(%d) "unknown_key"
string(%d) "Target key name already exists; can't overwrite."
bool(true)
bool(true)
==DONE==
