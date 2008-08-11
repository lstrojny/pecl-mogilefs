<?php
class MogileFsDomain
{
	public function __construct($domain, $host, $port = 6001);
	public function getName();
	public function getHost();
	public function getPort();
}

class MogileFsFile
{
	public function __construct($name, $class = null);
	public function getName();
	public function getDomain();
	public function getContent();
	public function setContent($string);
}

class MogileFsClass
{
	public function __construct($name, $file_count = 1);
	public function setFileCount($count);
	public function getFileCount();
	public function getName();
}

class MogileFsTracker
{
	public function connect($host, $port, $timeout = 30);
	public function close();

	public function createDomain(MogileFsDomain $domain); // bool
	public function removeDomain(MogileFsDomain $domain); // bool
	public function getDomain($name); // MogileFsDomain
	public function getDomains();  // MogileFsDomain[]

	public function createClass(MogileFsDomain $domain, MogileFsClass $class); // bool
	public function modifyClass(MogileFsDomain $domain, MogileFsClass $class); // bool
	public function getClass(MogileFsDomain $domain, $name); // MogileFsClass
	public function getClasses(MogileFsDomain $domain); // MogileFsClass[]
}

class MogileFs
{
	public function __construct(
		MogileFsTracker $tracker,
		MogileFsDomain $domain,
		MogileFsClass $class
	);
	public function put(MogileFsFile $file); // bool
	public function get($name); // MogileFsFile
	public function drop($name); // bool
}
