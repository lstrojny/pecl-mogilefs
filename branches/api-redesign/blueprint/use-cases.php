Writing a file to MogileFs:
<?php
$tracker = new MogileFsTracker();
$tracker->connect('host', 1234);
$domain = $tracker->getDomain('testdomain');
$class = $tracker->getClass($domain, 'myclass');

$fs = new MogileFs($tracker, $domain, $class);
$fs->put('file', 'this is the file content');
