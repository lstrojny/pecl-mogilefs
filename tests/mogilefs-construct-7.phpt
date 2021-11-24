--TEST--
MogileFs::__construct()
--SKIPIF--
<?php
require_once dirname(__FILE__) . '/test-helper.php';
if (PHP_VERSION_ID >= 80000) die("skip PHP 7 only");
if (mogilefs_skipped()) print "skip";
--FILE--
<?php
var_dump(new MogileFs());
var_dump(new MogileFs('invalidParam'));
?>
=DONE=
--EXPECTF--
object(MogileFs)#%d (%d) {
}

Warning: MogileFs::__construct() expects exactly 0 parameters, 1 given in %s on line %d
object(MogileFs)#%d (%d) {
}
=DONE=