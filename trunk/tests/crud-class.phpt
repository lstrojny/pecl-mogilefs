--TEST--
Test for createClass()/updateClass()/deleteClass()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();


$classname = uniqid(uniqid(), true);
$data = $client->createClass(MOGILEFS_DOMAIN, $classname, MOGILEFS_DEVICE_COUNT);
var_dump($data['domain'] === MOGILEFS_DOMAIN);
var_dump($data['class'] === $classname);
var_dump($data['mindevcount'] == MOGILEFS_DEVICE_COUNT);
var_dump(count($data));

try {
	$client->createClass(MOGILEFS_DOMAIN, $classname, MOGILEFS_DEVICE_COUNT);
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}

$data = $client->deleteClass(MOGILEFS_DOMAIN, $classname);
var_dump($data['domain'] === MOGILEFS_DOMAIN);
var_dump($data['class'] === $classname);
var_dump(count($data));
?>
==DONE==
--EXPECTF--
bool(true)
bool(true)
bool(true)
int(3)
string(%d) "That class already exists in that domain"
bool(true)
bool(true)
int(2)
==DONE==
