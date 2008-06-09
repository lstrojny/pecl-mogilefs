--TEST--
Check for mogilefs presence
--SKIPIF--
<?php if (!extension_loaded("mogilefs")) print "skip"; ?>
--FILE--
<?php
echo "mogilefs extension is available\n";
?>
==DONE==
--EXPECT--
mogilefs extension is available
==DONE==
