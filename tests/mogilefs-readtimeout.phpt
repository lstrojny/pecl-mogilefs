--TEST--
MogileFs::setReadTimeout() / MogileFs::getReadTimeout()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
$client = new MogileFs();
var_dump($client->getReadTimeout());
try {
    $client->setReadTimeout(10.2);
} catch (MogileFsException $e) {
    var_dump($e->getMessage());
}
require_once dirname(__FILE__) . '/test-helper.php';
$client = mogilefs_test_factory();
var_dump($client->getReadTimeout());
var_dump($client->setReadTimeout(10.2));
var_dump($client->getReadTimeout());
?>
==DONE==
--EXPECTF--
float(10)
string(%d) "No connection established. Call connect() first"
float(10)
NULL
float(10.2)
==DONE==
