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
		and !MogileFs::isInDebuggingMode()
		and defined(MOGILEFS_ENABLED)
		and MOGILEFS_ENABLED;
}

function mogilefs_test_factory()
{
	if (mogilefs_skipped()) {
		die('SKIP');
	}

	$client = new MogileFs();
	$connected = $client->connect(MOGILEFS_HOST, MOGILEFS_PORT, MOGILEFS_DOMAIN);
	assert($connected);
	try {
		$client->createClass(MOGILEFS_DOMAIN, MOGILEFS_CLASS, MOGILEFS_DEVICE_COUNT);
	} catch (MogileFsException $e) {
        if ($e->getMessage() === 'Domain not found') {
            $client->createDomain(MOGILEFS_DOMAIN);
        } else {
			$assertion = $e->getMessage() == "That class already exists in that domain";
		    assert($assertion);
        }
	}
	return $client;
}
