<?php

namespace App;

class StatsProcessor
{
    private $geoMapping;
    private $dataDir;
    private $logsDir;

    public function __construct(GeoMapping $geoMapping, string $dataDir)
    {
        $this->geoMapping = $geoMapping;
        $this->dataDir = rtrim($dataDir, '/') . '/';
        $this->logsDir = $this->dataDir . 'logs/';
        if (!is_dir($this->dataDir)) {
            mkdir($this->dataDir, 0755, true);
        }
        if (!is_dir($this->logsDir)) {
            mkdir($this->logsDir, 0755, true);
        }
    }

    /**
     * Processes an array of log entries and groups them by date.
     * Also handles deduplication against already saved logs.
     */
    public function process(array $logs): array
    {
        $statsByDay = [];
        $unknownIps = [];
        $newLogsByDay = [];

        // Load existing logs for the days we are touching to deduplicate
        $loadedLogs = [];

        foreach ($logs as $entry) {
            $timeStr = (string)$entry->time_generated;
            if (!$timeStr) continue;
            
            $date = date('Y-m-d', strtotime($timeStr));
            // Use seqno as a unique identifier for deduplication
            $logId = (string)($entry->attributes()->seqno ?? $entry['name'] ?? ''); 

            if (!isset($loadedLogs[$date])) {
                $loadedLogs[$date] = $this->loadRawLogs($date);
            }

            if ($logId && isset($loadedLogs[$date][$logId])) {
                continue; // Skip already processed log
            }

            if (!isset($statsByDay[$date])) {
                $statsByDay[$date] = [
                    'by_country' => [],
                    'client_versions' => [],
                    'failure_types' => []
                ];
            }

            if (!isset($newLogsByDay[$date])) {
                $newLogsByDay[$date] = [];
            }
            $newLogsByDay[$date][$logId ?: count($newLogsByDay[$date])] = $entry;

            $ip = (string)$entry->public_ip;
            $ipv6 = (string)$entry->public_ipv6;
            $user = (string)$entry->srcuser;
            $version = (string)$entry->client_ver ?: 'Unknown';
            $status = strtolower((string)$entry->status);
            $description = strtolower((string)($entry->description ?? $entry->error ?? ''));

            // Do not consider 'cookie expired' or IP changes as a failure or success; just ignore them.
            if ($status === 'cookie expired' || 
                strpos($description, 'cookie expired') !== false ||
                strpos($description, 'ip address change') !== false ||
                strpos($description, 'client ip changed') !== false ||
                strpos($description, 'authentication cookie usage is restricted to specified ip addresses') !== false
            ) {
                continue;
            }
            
            $activeIp = ($ip && $ip !== '0.0.0.0') ? $ip : $ipv6;
            
            if ($activeIp && filter_var($activeIp, FILTER_VALIDATE_IP)) {
                $country = $this->geoMapping->getCountryForIP($activeIp);
                if ($country === 'Unknown') {
                    $unknownIps[$activeIp] = true;
                }

                if (!isset($statsByDay[$date]['by_country'][$country])) {
                    $statsByDay[$date]['by_country'][$country] = [
                        'success' => 0, 
                        'failure' => 0, 
                        'unique_users' => []
                    ];
                }

                if ($status === 'success') {
                    $statsByDay[$date]['by_country'][$country]['success']++;
                    if ($user) {
                        $statsByDay[$date]['by_country'][$country]['unique_users'][$user] = true;
                    }
                } else {
                    $statsByDay[$date]['by_country'][$country]['failure']++;
                    // Track failure types
                    $failureType = (string)($entry->error ?: $entry->description ?: 'Unknown');
                    if (!isset($statsByDay[$date]['failure_types'][$failureType])) {
                        $statsByDay[$date]['failure_types'][$failureType] = 0;
                    }
                    $statsByDay[$date]['failure_types'][$failureType]++;
                }

                if (!isset($statsByDay[$date]['client_versions'][$version])) {
                    $statsByDay[$date]['client_versions'][$version] = 0;
                }
                $statsByDay[$date]['client_versions'][$version]++;
            }
        }

        return [
            'days' => $statsByDay,
            'unknown_ips' => $unknownIps,
            'new_logs' => $newLogsByDay
        ];
    }

    /**
     * Saves stats and raw logs.
     */
    public function saveDailySummaries(array $results): void
    {
        $lastTimestamp = $this->getLastTimestamp();

        foreach ($results['days'] as $date => $stats) {
            $file = $this->dataDir . "{$date}.json";
            
            $currentData = [
                'countries' => [],
                'client_versions' => [],
                'failure_types' => []
            ];

            if (file_exists($file)) {
                $currentData = json_decode(file_get_contents($file), true) ?: $currentData;
            }

            // Merge country data
            foreach ($stats['by_country'] as $country => $data) {
                if (!isset($currentData['countries'][$country])) {
                    $currentData['countries'][$country] = [
                        'success' => 0, 
                        'failure' => 0, 
                        'users' => []
                    ];
                }
                $currentData['countries'][$country]['success'] += $data['success'];
                $currentData['countries'][$country]['failure'] += $data['failure'];
                
                foreach ($data['unique_users'] as $user => $val) {
                    $currentData['countries'][$country]['users'][$user] = true;
                }
            }

            // Merge version data
            foreach ($stats['client_versions'] as $version => $count) {
                if (!isset($currentData['client_versions'][$version])) {
                    $currentData['client_versions'][$version] = 0;
                }
                $currentData['client_versions'][$version] += $count;
            }

            // Merge failure types
            foreach ($stats['failure_types'] as $type => $count) {
                if (!isset($currentData['failure_types'][$type])) {
                    $currentData['failure_types'][$type] = 0;
                }
                $currentData['failure_types'][$type] += $count;
            }

            file_put_contents($file, json_encode($currentData, JSON_PRETTY_PRINT));
        }

        // Save raw logs and update last timestamp
        foreach ($results['new_logs'] as $date => $logs) {
            $this->saveRawLogs($date, $logs);
            foreach ($logs as $entry) {
                $ts = strtotime((string)$entry->time_generated);
                if ($ts > $lastTimestamp) {
                    $lastTimestamp = $ts;
                }
            }
        }

        if ($lastTimestamp > $this->getLastTimestamp()) {
            $this->saveLastTimestamp($lastTimestamp);
        }

        // Save unknown IPs
        if (!empty($results['unknown_ips'])) {
            $unknownFile = $this->dataDir . "unknown_ips.txt";
            $existing = file_exists($unknownFile) ? file($unknownFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : [];
            $allUnknown = array_unique(array_merge($existing, array_keys($results['unknown_ips'])));
            file_put_contents($unknownFile, implode("\n", $allUnknown));
        }
    }

    public function getLastTimestamp(): int
    {
        $file = $this->dataDir . 'last_fetch.json';
        if (file_exists($file)) {
            $data = json_decode(file_get_contents($file), true);
            return $data['timestamp'] ?? 0;
        }
        return 0;
    }

    private function saveLastTimestamp(int $timestamp): void
    {
        $file = $this->dataDir . 'last_fetch.json';
        file_put_contents($file, json_encode([
            'timestamp' => $timestamp,
            'date' => date('Y-m-d H:i:s', $timestamp)
        ], JSON_PRETTY_PRINT));
    }

    private function loadRawLogs(string $date): array
    {
        $file = $this->logsDir . "{$date}.json";
        if (file_exists($file)) {
            return json_decode(file_get_contents($file), true) ?: [];
        }
        return [];
    }

    private function saveRawLogs(string $date, array $newLogs): void
    {
        $existing = $this->loadRawLogs($date);
        foreach ($newLogs as $id => $entry) {
            $existing[$id] = $entry;
        }
        $file = $this->logsDir . "{$date}.json";
        file_put_contents($file, json_encode($existing));
    }
}
