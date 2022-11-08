--TEST--
MogileFs::createDomain(string domain) / MogileFs::deleteDomain(string domain)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID < 80000) die("skip PHP 8 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();

$domainname = "simple-test-domain";
var_dump($client->createDomain($domainname));
var_dump($client->deleteDomain($domainname));

try {
	$client->createDomain();
} catch (\ArgumentCountError $e) {
	var_dump($e->getMessage(), $e->getCode());
}

try {
	$client->createDomain(new stdClass());
} catch (\TypeError $e) {
	var_dump($e->getMessage(), $e->getCode());
}

try {
	$client->deleteDomain();
} catch (\ArgumentCountError $e) {
	var_dump($e->getMessage(), $e->getCode());
}

try {
	$client->deleteDomain(new stdClass());
} catch (\TypeError $e) {
	var_dump($e->getMessage(), $e->getCode());
}

try {
	$client->deleteDomain('unknown-domain');
} catch (MogileFsException $e) {
	var_dump($e->getMessage());
}
?>
==DONE==
--EXPECTF--
array(1) {
  ["domain"]=>
  string(18) "simple-test-domain"
}
array(1) {
  ["domain"]=>
  string(18) "simple-test-domain"
}
string(%d) "MogileFs::createDomain() expects exactly 1 %s, 0 given"
int(0)
string(%d) "MogileFs::createDomain(): Argument #1 ($domain) must be of type string, stdClass given"
int(0)
string(%d) "MogileFs::deleteDomain() expects exactly 1 %s, 0 given"
int(0)
string(%d) "MogileFs::deleteDomain(): Argument #1 ($domain) must be of type string, stdClass given"
int(0)
string(%d) "Domain not found"
==DONE==
