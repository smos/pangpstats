<?php

namespace App;

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

class EmailReporter
{
    private $dataDir;
    private $recipient;
    private $from;

    public function __construct(string $dataDir)
    {
        $this->dataDir = rtrim($dataDir, '/') . '/';
        $this->recipient = getenv('REPORT_RECIPIENT');
        $this->from = getenv('SMTP_FROM') ?: 'stats@pangpstats.local';
    }

    public function sendReport(int $days = 7): void
    {
        if (!$this->recipient) {
            echo "Warning: REPORT_RECIPIENT not set in .env. Skipping email report.\n";
            return;
        }

        $dates = [];
        for ($i = $days - 1; $i >= 0; $i--) {
            $dates[] = date('Y-m-d', strtotime("-$i days"));
        }

        $trendData = [
            'labels' => [],
            'success_events' => [],
            'failures' => [],
            'unique_users' => []
        ];

        $periodDailyStats = []; // Date -> [ 'countries' => Stats, 'failures' => FailureTypes ]
        $latestDate = end($dates);
        $firstDate = reset($dates);

        foreach ($dates as $date) {
            $file = $this->dataDir . "{$date}.json";
            $dayTotalSuccess = 0;
            $dayTotalFailure = 0;
            $dayUniqueUsers = [];

            if (file_exists($file)) {
                $data = json_decode(file_get_contents($file), true);
                $periodDailyStats[$date] = [
                    'countries' => $data['countries'] ?? [],
                    'failures' => $data['failure_types'] ?? []
                ];
                
                if (isset($data['countries'])) {
                    foreach ($data['countries'] as $country => $stats) {
                        $dayTotalSuccess += $stats['success'];
                        $dayTotalFailure += $stats['failure'];
                        foreach (($stats['users'] ?? []) as $user => $val) {
                            $dayUniqueUsers[$user] = true;
                        }
                    }
                }
            }

            $trendData['labels'][] = date('M d', strtotime($date));
            $trendData['success_events'][] = $dayTotalSuccess;
            $trendData['failures'][] = $dayTotalFailure;
            $trendData['unique_users'][] = count($dayUniqueUsers);
        }

        $chartUrl = $this->generateChartUrl($trendData);
        $html = $this->buildHtml($firstDate, $latestDate, $periodDailyStats, $chartUrl);

        $subject = "GlobalProtect Stats Report - $latestDate";
        
        $mail = new PHPMailer(true);

        try {
            // SMTP Settings
            $mail->isSMTP();
            $mail->Host       = getenv('SMTP_HOST') ?: 'localhost';
            $mail->Port       = (int)getenv('SMTP_PORT') ?: 587;
            
            $user = getenv('SMTP_USER');
            $pass = getenv('SMTP_PASS');
            if ($user) {
                $mail->SMTPAuth   = true;
                $mail->Username   = $user;
                $mail->Password   = $pass ?: '';
            } else {
                $mail->SMTPAuth   = false;
            }
            
            $secure = strtolower(getenv('SMTP_SECURE') ?: '');
            if ($secure === 'ssl' || ($mail->Port === 465 && $secure !== 'none')) {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            } elseif ($secure === 'tls' || ($mail->Port === 587 && $secure !== 'none')) {
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            } else {
                $mail->SMTPSecure = '';
                $mail->SMTPAutoTLS = false; // Disable auto TLS for internal relays that don't support it
            }

            if (strtolower(getenv('SMTP_ALLOW_INSECURE') ?: '') === 'true') {
                $mail->SMTPOptions = [
                    'ssl' => [
                        'verify_peer' => false,
                        'verify_peer_name' => false,
                        'allow_self_signed' => true
                    ]
                ];
            }

            // Recipients
            $mail->setFrom($this->from, 'PangPstats');
            $mail->addAddress($this->recipient);

            // Content
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $html;

            $mail->send();
            echo "Email report sent to {$this->recipient} via SMTP.\n";
        } catch (Exception $e) {
            echo "Error: Failed to send email report. PHPMailer Error: {$mail->ErrorInfo}\n";
        }
    }

    private function generateChartUrl(array $trendData): string
    {
        $config = [
            'type' => 'line',
            'data' => [
                'labels' => $trendData['labels'],
                'datasets' => [
                    [
                        'label' => 'Auth Failures',
                        'data' => $trendData['failures'],
                        'borderColor' => 'rgb(220, 53, 69)', // Red
                        'backgroundColor' => 'rgba(220, 53, 69, 0.1)',
                        'fill' => false,
                    ],
                    [
                        'label' => 'Unique Users',
                        'data' => $trendData['unique_users'],
                        'borderColor' => 'rgb(0, 123, 255)', // Blue
                        'backgroundColor' => 'rgba(0, 123, 255, 0.1)',
                        'fill' => false,
                    ]
                ]
            ],
            'options' => [
                'title' => [
                    'display' => true,
                    'text' => 'GlobalProtect Auth Trend (Last 7 Days)'
                ]
            ]
        ];

        return "https://quickchart.io/chart?c=" . urlencode(json_encode($config));
    }

    private function buildHtml(string $startDate, string $endDate, array $periodDailyStats, string $chartUrl): string
    {
        ob_start();
        ?>
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2>GlobalProtect Authentication Report: <?php echo "$startDate to $endDate"; ?></h2>
            
            <div style="margin-bottom: 30px;">
                <img src="<?php echo $chartUrl; ?>" alt="Auth Trend Chart" style="max-width: 100%; border: 1px solid #ddd;">
                <p style="font-size: 0.9em; color: #666;">
                    * <strong>Unique Users:</strong> Total count of unique usernames with successful auth per day.<br>
                    * <strong>Auth Failures:</strong> Total count of failed auth events per day.
                </p>
            </div>

            <h3>Daily Breakdown</h3>
            <?php 
            krsort($periodDailyStats); // Show most recent days first
            foreach ($periodDailyStats as $date => $dayData): 
                $countryStats = $dayData['countries'] ?? [];
                $failureStats = $dayData['failures'] ?? [];
                if (empty($countryStats) && empty($failureStats)) continue;
                ?>
                <h4 style="margin-bottom: 5px; color: #555; background-color: #f9f9f9; padding: 5px;"><?php echo date('l, M d, Y', strtotime($date)); ?></h4>
                
                <div style="display: flex; flex-wrap: wrap; gap: 20px;">
                    <div style="flex: 1; min-width: 300px; margin-bottom: 20px;">
                        <h5 style="margin: 10px 0;">Summary by Country</h5>
                        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 0.9em;">
                            <thead>
                                <tr style="background-color: #f2f2f2;">
                                    <th>Country</th>
                                    <th>Success</th>
                                    <th>Failure</th>
                                    <th>Unique Users</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php 
                                uasort($countryStats, function($a, $b) {
                                    return ($b['success'] + $b['failure']) <=> ($a['success'] + $a['failure']);
                                });
                                foreach ($countryStats as $country => $stats): ?>
                                    <tr>
                                        <td><strong><?php echo $country; ?></strong></td>
                                        <td align="right"><?php echo number_format($stats['success']); ?></td>
                                        <td align="right"><?php echo number_format($stats['failure']); ?></td>
                                        <td align="right"><?php echo count($stats['users'] ?? []); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <?php if (!empty($failureStats)): ?>
                    <div style="flex: 1; min-width: 300px; margin-bottom: 20px;">
                        <h5 style="margin: 10px 0;">Auth Failure Breakdown</h5>
                        <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 0.9em;">
                            <thead>
                                <tr style="background-color: #f2f2f2;">
                                    <th>Failure Reason</th>
                                    <th width="80">Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php 
                                arsort($failureStats);
                                foreach ($failureStats as $reason => $count): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($reason); ?></td>
                                        <td align="right"><?php echo number_format($count); ?></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php endif; ?>
                </div>
                <hr style="border: 0; border-top: 1px solid #eee; margin: 10px 0 20px 0;">
            <?php endforeach; ?>

            <p style="font-size: 0.8em; color: #777; margin-top: 40px;">
                This report was automatically generated by pangpstats.
            </p>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }
}
