<?php
echo "==START==\n\n\n";
require_once __DIR__ . '/../test-helper.php';
if (!defined('MOGILEFS_BENCHMARK_ITERATIONS')) {
	define('MOGILEFS_BENCHMARK_ITERATIONS', 100);
}

require_once __DIR__ . '/timer.php';

/**
 * Connecting/disconnecting
 */
$timer = new MogileFsBenchmarkTimer(
	'Connecting/disconnecting %d times to the MogileFsServer: %fs (%fs per connect)'
);
for ($a = 0; $a < MOGILEFS_BENCHMARK_ITERATIONS; ++$a) {
	$client = new MogileFs();
	$client->connect(MOGILEFS_HOST, MOGILEFS_PORT, MOGILEFS_CLASS, 10000);
	unset($client);
	$timer->tick();
}
echo $timer;


//
// CREATING FILES
//
$files = array();

$dir = tempnam(sys_get_temp_dir(), 'mfsb');
unlink($dir);
mkdir ($dir);
$timer = new MogileFsBenchmarkTimer('Creating %d temp files: %fs (%fs per tick)');
for ($a = 0; $a < MOGILEFS_BENCHMARK_ITERATIONS; ++$a) {
	$file = $dir . '/' . $a;
	file_put_contents($file, str_repeat("0", rand(1024, 1024*1024)));
	$files[] = $file;
	$timer->tick();
}
echo $timer;


$client = mogilefs_test_factory();
$timer = new MogileFsBenchmarkTimer(
	'Writing %d files between 1KB and 1MB to MogileFS: %fs (%fs per write)'
);
for ($a = 0; $a < MOGILEFS_BENCHMARK_ITERATIONS; ++$a) {
	assert($client->put($dir . '/' . $a, 'tf' . $a, MOGILEFS_CLASS));
	$timer->tick();
}
echo $timer;

$client = mogilefs_test_factory();
$timer = new MogileFsBenchmarkTimer(
	'Reading %d files between 1KB and 1MB from MogileFS tracker: %fs (%fs per read)'
);
for ($a = 0; $a < MOGILEFS_BENCHMARK_ITERATIONS; ++$a) {
	$result = $client->get('tf' . $a);
	assert(is_array($result));
	assert(strlen(file_get_contents($result['path1'])) >= 1024);
	$timer->tick();
}
echo $timer;

echo "\n\n\n==END==\n";
