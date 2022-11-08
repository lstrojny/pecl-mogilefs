--TEST--
Mogilefs::createClass(string domain, string class, int device_count) / MogileFs::updateClass(string domain, string class, int device_count) / MogileFs::deleteClass(string domain, string class)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID < 80000) die("skip PHP 8 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();

// Params
try {
	$client->createClass();
} catch (\ArgumentCountError $e) {
	var_dump($e->getMessage(), $e->getCode());
}

$classname = 'crud-test-class';

$data = $client->createClass(MOGILEFS_DOMAIN, $classname, MOGILEFS_DEVICE_COUNT);
var_dump($data['domain'] == MOGILEFS_DOMAIN);
var_dump($data['class'] == $classname);
var_dump($data['mindevcount'] == MOGILEFS_DEVICE_COUNT);
var_dump(count($data));

try {
	$client->createClass(MOGILEFS_DOMAIN, $classname, MOGILEFS_DEVICE_COUNT);
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}

// Might take a few seconds to create the class
$c = 0;
do {
	try {
		$data = $client->updateClass(MOGILEFS_DOMAIN, $classname, 1);
		break;
	} catch (MogileFsException $e) {
		usleep(500);
		++$c;
	}
} while ($c < 10);
var_dump($data['domain'] == MOGILEFS_DOMAIN);
var_dump($data['class'] == $classname);
var_dump($data['mindevcount'] == 1);
var_dump(count($data));

$data = $client->deleteClass(MOGILEFS_DOMAIN, $classname);
var_dump($data['domain'] == MOGILEFS_DOMAIN);
var_dump($data['class'] == $classname);
var_dump(count($data));
?>
==DONE==
--EXPECTF--
string(%d) "MogileFs::createClass() expects exactly 3 %s, 0 given"
int(0)
bool(true)
bool(true)
bool(true)
int(3)
string(%d) "That class already exists in that domain"
bool(true)
bool(true)
bool(true)
int(3)
bool(true)
bool(true)
int(2)
==DONE==
