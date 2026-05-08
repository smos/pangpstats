<?php

namespace App;

class GeoMapping
{
    private $sourceUrl;
    private $cacheDir;
    private $cacheFile;
    private $ipv4Map = [];
    private $ipv6Map = [];
    private $loaded = false;

    public function __construct(string $sourceUrl, string $cacheDir)
    {
        $this->sourceUrl = $sourceUrl;
        $this->cacheDir = rtrim($cacheDir, '/') . '/';
        $this->cacheFile = $this->cacheDir . 'geo_cache.php';
        if (!is_dir($this->cacheDir)) {
            mkdir($this->cacheDir, 0755, true);
        }
    }

    /**
     * Updates the local geo cache by downloading and parsing the source CSV.
     */
    public function updateData(): void
    {
        echo "Downloading geolocation data from {$this->sourceUrl}...\n";
        
        $zipFile = $this->cacheDir . 'ip-to-asn.csv.zip';
        $content = @file_get_contents($this->sourceUrl);
        
        if ($content === false) {
            throw new \Exception("Failed to download geolocation data from {$this->sourceUrl}");
        }
        
        file_put_contents($zipFile, $content);
        
        echo "Extracting data...\n";
        $zip = new \ZipArchive();
        if ($zip->open($zipFile) === TRUE) {
            $zip->extractTo($this->cacheDir);
            $zip->close();
        } else {
            throw new \Exception("Failed to unzip geolocation data");
        }

        $csvFile = $this->cacheDir . 'ip-to-asn.csv';
        if (!file_exists($csvFile)) {
            // Check if it's named differently inside the zip
            $files = glob($this->cacheDir . "ip-to-asn*.csv");
            if (empty($files)) {
                throw new \Exception("CSV file not found after extraction");
            }
            $csvFile = $files[0];
        }

        echo "Parsing CSV and building cache (this may take a minute)...\n";
        $this->ipv4Map = [];
        $this->ipv6Map = [];
        
        if (($handle = fopen($csvFile, "r")) !== FALSE) {
            // Skip header if it exists
            $firstLine = fgets($handle);
            if (strpos($firstLine, 'network') === false) {
                rewind($handle);
            }

            while (($data = fgetcsv($handle, 1000, ",")) !== FALSE) {
                // network,asn,country_code,name,org,domain
                if (count($data) < 5) continue;
                
                $network = $data[0];
                $country = $data[2];
                $isp = $data[4]; // Use 'org' field for ISP name
                
                if (strpos($network, ':') !== false) {
                    $range = $this->cidrToRange($network);
                    if ($range) {
                        $this->ipv6Map[] = [
                            's' => $range['start'],
                            'e' => $range['end'],
                            'c' => $country,
                            'i' => $isp
                        ];
                    }
                } else {
                    $range = $this->cidrToRange($network);
                    if ($range) {
                        $this->ipv4Map[] = [
                            's' => $range['start'],
                            'e' => $range['end'],
                            'c' => $country,
                            'i' => $isp
                        ];
                    }
                }
            }
            fclose($handle);
        }

        echo "Sorting ranges...\n";
        usort($this->ipv4Map, fn($a, $b) => $a['s'] <=> $b['s']);
        usort($this->ipv6Map, fn($a, $b) => $a['s'] <=> $b['s']);

        echo "Saving serialized cache...\n";
        $cacheContent = "<?php\nreturn " . var_export([
            'ipv4' => $this->ipv4Map,
            'ipv6' => $this->ipv6Map,
            'updated_at' => time()
        ], true) . ";\n";
        
        file_put_contents($this->cacheFile, $cacheContent);
        
        // Clean up temporary files
        @unlink($zipFile);
        @unlink($csvFile);
        
        $this->loaded = true;
    }

    public function loadAll(): void
    {
        if (file_exists($this->cacheFile)) {
            $data = include $this->cacheFile;
            $this->ipv4Map = $data['ipv4'] ?? [];
            $this->ipv6Map = $data['ipv6'] ?? [];
            $this->loaded = true;
        }
    }

    public function isLoaded(): bool
    {
        return $this->loaded;
    }

    public function getLocation(string $ip): array
    {
        if ($this->isLocalIP($ip)) {
            return ['country' => 'Local', 'isp' => 'Internal Network'];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->searchIPv4($ip);
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->searchIPv6($ip);
        }
        
        return ['country' => 'Unknown', 'isp' => 'Unknown'];
    }

    public function getCountryForIP(string $ip): string
    {
        $loc = $this->getLocation($ip);
        return $loc['country'];
    }

    private function searchIPv4(string $ip): array
    {
        $ipLong = ip2long($ip);
        if ($ipLong === false) return ['country' => 'Unknown', 'isp' => 'Unknown'];
        
        // Unsigned comparison
        $ipLong = sprintf('%u', $ipLong);

        $low = 0;
        $high = count($this->ipv4Map) - 1;
        $candidate = -1;

        // Find the index of the largest 's' (start) such that 's' <= $ipLong
        while ($low <= $high) {
            $mid = floor(($low + $high) / 2);
            $start = sprintf('%u', $this->ipv4Map[$mid]['s']);

            if ($start <= $ipLong) {
                $candidate = $mid;
                $low = $mid + 1;
            } else {
                $high = $mid - 1;
            }
        }

        if ($candidate !== -1) {
            // Check the candidate and potentially its neighbors (in case of overlapping start IPs)
            // The database is sorted by 's'. Multiple entries might have the same 's'.
            // We want the most specific one, but usually the first one that matches 'e' is fine.
            for ($i = $candidate; $i >= 0; $i--) {
                $entry = $this->ipv4Map[$i];
                $start = sprintf('%u', $entry['s']);
                $end = sprintf('%u', $entry['e']);

                if ($ipLong >= $start && $ipLong <= $end) {
                    return ['country' => $entry['c'], 'isp' => $entry['i']];
                }
                
                // Optimization: if we move to a different start IP, we might still find a match
                // if ranges are nested. However, iplocate usually puts more specific ranges after.
                // Let's check a few previous entries just in case.
                if ($i < $candidate - 10) break; 
            }
        }

        return ['country' => 'Unknown', 'isp' => 'Unknown'];
    }

    private function searchIPv6(string $ip): array
    {
        $ipBin = inet_pton($ip);
        if ($ipBin === false) return ['country' => 'Unknown', 'isp' => 'Unknown'];

        $low = 0;
        $high = count($this->ipv6Map) - 1;
        $candidate = -1;

        while ($low <= $high) {
            $mid = floor(($low + $high) / 2);
            $start = $this->ipv6Map[$mid]['s'];

            if ($start <= $ipBin) {
                $candidate = $mid;
                $low = $mid + 1;
            } else {
                $high = $mid - 1;
            }
        }

        if ($candidate !== -1) {
            for ($i = $candidate; $i >= 0; $i--) {
                $entry = $this->ipv6Map[$i];
                if ($ipBin >= $entry['s'] && $ipBin <= $entry['e']) {
                    return ['country' => $entry['c'], 'isp' => $entry['i']];
                }
                if ($i < $candidate - 10) break;
            }
        }

        return ['country' => 'Unknown', 'isp' => 'Unknown'];
    }

    private function cidrToRange(string $cidr): ?array
    {
        if (strpos($cidr, '/') === false) {
            $ip = $cidr;
            $mask = strpos($ip, ':') !== false ? 128 : 32;
        } else {
            list($ip, $mask) = explode('/', $cidr);
        }

        if (strpos($ip, ':') !== false) {
            // IPv6
            $bin = inet_pton($ip);
            if (!$bin) return null;
            
            $maskBin = $this->getIPv6Mask((int)$mask);
            $start = $bin & $maskBin;
            $end = $start | ~$maskBin;
            
            return ['start' => $start, 'end' => $end];
        } else {
            // IPv4
            $long = ip2long($ip);
            if ($long === false) return null;
            
            $maskLong = -1 << (32 - (int)$mask);
            $start = $long & $maskLong;
            $end = $start | ~$maskLong;
            
            return ['start' => $start, 'end' => $end];
        }
    }

    private function getIPv6Mask(int $mask): string
    {
        $maskBin = str_repeat("\xff", $mask >> 3);
        if ($mask % 8 !== 0) {
            $maskBin .= chr(0xff << (8 - ($mask % 8)));
        }
        return str_pad($maskBin, 16, "\x00");
    }

    private function isLocalIP(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipLong = ip2long($ip);
            $ranges = [
                ['10.0.0.0', '10.255.255.255'],
                ['172.16.0.0', '172.31.255.255'],
                ['192.168.0.0', '192.168.255.255'],
                ['127.0.0.0', '127.255.255.255'],
                ['169.254.0.0', '169.254.255.255'],
            ];
            foreach ($ranges as $range) {
                if ($ipLong >= ip2long($range[0]) && $ipLong <= ip2long($range[1])) {
                    return true;
                }
            }
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            if (strpos($ip, 'fc') === 0 || strpos($ip, 'fd') === 0 || $ip === '::1' || strpos($ip, 'fe80') === 0) {
                return true;
            }
        }
        return false;
    }
}
