<?php
/**  @generate-function-entries */
class MogileFs {
    public function __construct(){}
    public function isConnected(): bool {}
    public function connect(string $host, int $port, string $domain, float $timeout): bool {}
    public function get(string $key, int $pathcount = 2): array {}
    public function getDomains(): array {}
    public function fileInfo(string $key): array {}
    public function listKeys(string $prefix, string $after, int $limit): array {}
    public function listFids(int $from, int $to): bool {}
    public function getHosts(): array {}
    public function getDevices(): array {}
    public function sleep(int $duration): bool {}
    public function stats(int $all): array {}
    public function replicate(): bool {}
    public function createDevice(string $devid, string $status): array {}
    public function createDomain(string $domain): array {}
    public function deleteDomain(string $domain): array {}
    public function createClass(string $domain, string $class, string $mindevcount): array {}
    public function updateClass(string $domain, string $class, string $mindevcount): array {}
    public function deleteClass(string $domain, string $class): bool {}
    public function createHost(string $hostname): array {}
    public function updateHost(string $hostname, string $ip, int $port, string $state = "alive"): array {}
    public function deleteHost(string $hostname): bool {}
    public function setWeight(string $hostname, string $device, string $weight): bool {}
    public function setState(string $hostname, string $device, string $state = "alive"): bool {}
    public function checker(string $status, string $level): bool {}
    public function monitorRound(): array {}
    public function put(string $pathvalidfile, string $key, string $class, bool $use_file = true): bool {}
    public function close(): bool {}
    public function delete(string $key): bool {}
    public function rename(string $from_key, string $to_key): bool {}
    public function setReadTimeout(float $readTimeout): void {}
    public function getReadTimeout(): float {}
    public static function isInDebuggingMode(): bool {}
    /** @alias MogileFs::close */
    public function disconnect(): bool {}
}

