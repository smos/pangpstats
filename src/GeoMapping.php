<?php

namespace App;

class GeoMapping
{
    private $baseUrl;
    private $cacheDir;
    private $ipv4Map = [];
    private $ipv6Map = [];

    public function __construct(string $baseUrl, string $cacheDir)
    {
        $this->baseUrl = rtrim($baseUrl, '/') . '/';
        $this->cacheDir = rtrim($cacheDir, '/') . '/';
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }

    public function updateAllCountries(): void
    {
        $html = @file_get_contents($this->baseUrl);
        if ($html === false) return;

        preg_match_all('/href="([A-Z]{2})\.txt"/', $html, $matches);
        if (empty($matches[1])) return;

        foreach ($matches[1] as $country) {
            echo "Fetching $country...\n";
            $this->fetchCountry($country);
        }
    }

    private function fetchCountry(string $country): void
    {
        $country = strtoupper($country);
        $cacheFile = $this->cacheDir . "{$country}.txt";

        // Refresh cache if older than 24h
        if (!file_exists($cacheFile) || (time() - filemtime($cacheFile) > 86400)) {
            $url = $this->baseUrl . "{$country}.txt";
            $content = @file_get_contents($url);
            if ($content !== false) {
                file_put_contents($cacheFile, $content);
            }
        }
    }

    public function loadAll(): void
    {
        // Load custom overrides first if they exist
        $customFile = $this->cacheDir . "custom.txt";
        if (file_exists($customFile)) {
            $this->loadFromFile($customFile, true);
        }

        $files = glob($this->cacheDir . "*.txt");
        foreach ($files as $file) {
            if (basename($file) === 'custom.txt') continue;
            $this->loadFromFile($file);
        }
    }

    private function loadFromFile(string $file, bool $isCustom = false): void
    {
        $country = basename($file, '.txt');
        $lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($lines as $line) {
            // Handle lines like "1.2.3.4 NL" in custom file, or standard CIDR
            $parts = preg_split('/\s+/', $line);
            $prefix = $parts[0];
            $entryCountry = $isCustom && isset($parts[1]) ? strtoupper($parts[1]) : $country;

            if (strpos($prefix, ':') !== false) {
                $this->ipv6Map[] = ['prefix' => $prefix, 'country' => $entryCountry];
            } else {
                $this->ipv4Map[] = ['prefix' => $prefix, 'country' => $entryCountry];
            }
        }
    }

    public function getCountryForIP(string $ip): string
    {
        if ($this->isLocalIP($ip)) {
            return 'Local';
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->matchIPv4($ip);
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->matchIPv6($ip);
        }
        return 'Unknown';
    }

    private function isLocalIP(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            // RFC1918 check
            $ipLong = ip2long($ip);
            $ranges = [
                ['10.0.0.0', '10.255.255.255'],
                ['172.16.0.0', '172.31.255.255'],
                ['192.168.0.0', '192.168.255.255'],
            ];
            foreach ($ranges as $range) {
                if ($ipLong >= ip2long($range[0]) && $ipLong <= ip2long($range[1])) {
                    return true;
                }
            }
            // Loopback and Link-local
            if ($ipLong >= ip2long('127.0.0.0') && $ipLong <= ip2long('127.255.255.255')) return true;
            if ($ipLong >= ip2long('169.254.0.0') && $ipLong <= ip2long('169.254.255.255')) return true;
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            // ULA: fc00::/7, Loopback: ::1, Link-local: fe80::/10
            if (strpos($ip, 'fc') === 0 || strpos($ip, 'fd') === 0 || $ip === '::1' || strpos($ip, 'fe80') === 0) {
                return true;
            }
        }
        return false;
    }

    private function matchIPv4(string $ip): string
    {
        $ipLong = ip2long($ip);
        foreach ($this->ipv4Map as $entry) {
            if ($this->cidrmatch($ip, $entry['prefix'])) {
                return $entry['country'];
            }
        }
        return 'Unknown';
    }

    private function matchIPv6(string $ip): string
    {
        foreach ($this->ipv6Map as $entry) {
            if ($this->cidrmatch($ip, $entry['prefix'])) {
                return $entry['country'];
            }
        }
        return 'Unknown';
    }

    private function cidrmatch($ip, $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return $ip === $cidr;
        }
        list($subnet, $mask) = explode('/', $cidr);
        if (strpos($ip, ':') !== false) {
            // IPv6 matching
            $ipBinary = inet_pton($ip);
            $subnetBinary = inet_pton($subnet);
            $maskBinary = str_repeat("\xff", $mask >> 3);
            if ($mask % 8 !== 0) {
                $maskBinary .= chr(0xff << (8 - ($mask % 8)));
            }
            $maskBinary = str_pad($maskBinary, 16, "\x00");
            return ($ipBinary & $maskBinary) === ($subnetBinary & $maskBinary);
        } else {
            // IPv4 matching
            $ipLong = ip2long($ip);
            $subnetLong = ip2long($subnet);
            $maskLong = -1 << (32 - $mask);
            return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
        }
    }
}
