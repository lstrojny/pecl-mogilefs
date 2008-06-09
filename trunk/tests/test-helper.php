<?php
$config = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'config.inc.php';
if (file_exists($config)) {
	require_once $config;
}

/**
 * Returns true if a certain pre-condition for MogileFS tests are not valid
 */
function mogilefs_skipped() {
	return extension_loaded('mogilefs')
		and defined(MOGILEFS_ENABLED)
		and MOGILEFS_ENABLED;
}

function mogilefs_test_factory()
{
	if (mogilefs_skipped()) {
		die('SKIP');
	}
	$client = new MogileFsClient();
	assert($client->connect(MOGILEFS_HOST, MOGILEFS_PORT, MOGILEFS_DOMAIN));
	try {
		$client->createClass(MOGILEFS_DOMAIN, MOGILEFS_CLASS, MOGILEFS_DEVICE_COUNT);
	} catch (Exception $e) {}
	return $client;
}
