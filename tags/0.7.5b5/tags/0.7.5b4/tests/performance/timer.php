<?php
class MogileFsBenchmarkTimer
{
	protected $_description;
	protected $_start;
	protected $_time;
	protected $_ticks = 0;

	public function __construct($description)
	{
		$this->_description = (string)$description;
		$this->_start = microtime(true);
	}

	public function getDescription()
	{
		return $this->_description;
	}

	public function tick()
	{
		++$this->_ticks;
	}

	public function getTicks()
	{
		return $this->_ticks;
	}

	public function isRunning()
	{
		return $this->_time === null;
	}

	public function stop()
	{
		$this->_time = microtime(true) - $this->_start;
	}

	public function getTime()
	{
		if ($this->isRunning()) {
			$this->stop();
		}
		return $this->_time;
	}

	public function __toString()
	{
		if ($this->isRunning()) {
			$this->stop();
		}
		return sprintf($this->getDescription() . "\n", $this->getTicks(),
		$this->getTime(), ($this->getTime() / $this->getTicks()));
	}
}
