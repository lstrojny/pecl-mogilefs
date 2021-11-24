--TEST--
MogileFs::createDomain(string domain) / MogileFs::deleteDomain(string domain)
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID >= 80000) die("skip PHP 7 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();

$domainname = "simple-test-domain";
var_dump($client->createDomain($domainname));
var_dump($client->deleteDomain($domainname));


var_dump($client->createDomain());
var_dump($client->createDomain(new stdClass()));


var_dump($client->deleteDomain());
var_dump($client->deleteDomain(new stdClass()));


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

Warning: MogileFs::createDomain() expects exactly 1 parameter, 0 given in %s on line %d
NULL

Warning: MogileFs::createDomain() expects parameter 1 to be string, object given in %s on line %d
NULL

Warning: MogileFs::deleteDomain() expects exactly 1 parameter, 0 given in %s on line %d
NULL

Warning: MogileFs::deleteDomain() expects parameter 1 to be string, object given in %s on line %d
NULL
string(%d) "Domain not found"
==DONE==