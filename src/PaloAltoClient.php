<?php

namespace App;

class PaloAltoClient
{
    private $host;
    private $apiKey;

    public function __construct(string $host, string $apiKey)
    {
        $this->host = $host;
        $this->apiKey = $apiKey;
    }

    /**
     * Fetches all logs for the given period by iterating through 5000-log batches.
     */
    public function getAllGlobalProtectLogs(int $days = 1, ?int $startTime = null): array
    {
        $allEntries = [];
        $targetStartTime = $startTime ? date('Y/m/d H:i:s', $startTime) : date('Y/m/d H:i:s', strtotime("-$days days"));
        $fetchUntil = date('Y/m/d H:i:s'); // Start from now

        echo "Starting recursive log fetch back to $targetStartTime...\n";

        while (true) {
            $query = "((eventid eq portal-auth) or (eventid eq gateway-auth)) and (time_generated geq '$targetStartTime') and (time_generated leq '$fetchUntil')";
            $url = "https://{$this->host}/api/?type=log&log-type=globalprotect&nlogs=5000&query=" . urlencode($query);
            
            $response = $this->makeRequest($url);
            $xml = simplexml_load_string($response);

            if (!$xml || (string)$xml['status'] !== 'success') {
                throw new \Exception("Failed to submit log query: " . ($xml->result->msg ?? 'Unknown error'));
            }

            $jobId = (string)$xml->result->job;
            $batchXml = $this->pollJob($jobId);
            
            $logs = $batchXml->result->log->logs->entry ?? [];
            $count = count($logs);
            
            if ($count === 0) break;

            $oldestTime = (string)$logs[$count - 1]->time_generated;
            $newestTime = (string)$logs[0]->time_generated;
            echo "Fetched $count logs (Window: $newestTime to $oldestTime). Total: " . (count($allEntries) + $count) . ".\n";

            foreach ($logs as $entry) {
                $allEntries[] = $entry;
            }

            if ($count < 5000) {
                // We reached the end of the available logs
                break;
            }

            // Move the window: the last entry in the batch is the oldest
            $fetchUntil = date('Y/m/d H:i:s', strtotime($oldestTime) - 1);
            
            if (strtotime($fetchUntil) <= strtotime($targetStartTime)) {
                break;
            }
        }

        return $allEntries;
    }

    private function pollJob(string $jobId): \SimpleXMLElement
    {
        $pollUrl = "https://{$this->host}/api/?type=log&action=get&job-id=$jobId";
        $maxRetries = 30;
        $retryCount = 0;
        
        while ($retryCount < $maxRetries) {
            sleep(2);
            $response = $this->makeRequest($pollUrl);
            $pollXml = simplexml_load_string($response);

            if (!$pollXml || (string)$pollXml['status'] !== 'success') {
                throw new \Exception("Error polling job $jobId");
            }

            if ((string)$pollXml->result->job->status === 'FIN') {
                return $pollXml;
            }
            $retryCount++;
        }
        throw new \Exception("Timed out waiting for job $jobId");
    }

    private function makeRequest(string $url): string
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["X-PAN-KEY: {$this->apiKey}"]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        $response = curl_exec($ch);
        curl_close($ch);
        return $response ?: '';
    }
}
