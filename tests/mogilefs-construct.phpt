--TEST--
MogileFs::__construct()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID < 80000) die("skip PHP 8 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
var_dump(new MogileFs());

try {
    new MogileFs('invalidParam');
} catch (\ArgumentCountError $e) {
    var_dump($e->getMessage(), $e->getCode());
}
?>
=DONE=
--EXPECTF--
object(MogileFs)#%d (%d) {
}
string(%d) "MogileFs::__construct() expects exactly 0 %s, 1 given"
int(0)
=DONE=
