<?php
$config = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'config.inc.php';
if (file_exists($config)) {
	require_once $config;
}

/**
 * Returns true if a certain pre-condition for MogileFS tests are not valid
 */
function mogilfs_skipped() {
	return extension_loaded('mogilefs')
		and defined(MOGILEFS_ENABLED)
		and MOGILEFS_ENABLED;
}
