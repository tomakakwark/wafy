<?php

namespace Bdsa\Wafy\Mail;

use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class IpBannedEmail extends Mailable
{
    use Queueable, SerializesModels;

    public $ip;
    public $reason;
    public $request_data;

    public function __construct($data)
    {
        $this->ip = $data['ip_address'] ?? 'Unknown';
        $this->reason = $data['reason'] ?? 'N/A';
        $this->request_data = $data['request_data'] ?? [];
    }

    public function build()
    {
        return $this->subject('Wafy Alert: IP Banned')
            ->view('wafy::emails.ip_banned');
    }
}