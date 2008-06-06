--TEST--
Check for mogilefs presence
--SKIPIF--
<?php if (!extension_loaded("mogilefs")) print "skip"; ?>
--FILE--
<?php
echo "mogilefs extension is available";
--EXPECT--
mogilefs extension is available
