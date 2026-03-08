<?php

namespace Bdsa\Wafy\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Messages\SlackMessage;
use Bdsa\Wafy\Models\BannedIp;

class IpBannedNotification extends Notification
{
    use Queueable;

    public $bannedIp;

    public function __construct(BannedIp $bannedIp)
    {
        $this->bannedIp = $bannedIp;
    }

    public function via($notifiable)
    {
        return config('wafy.notifications.channels', ['mail']);
    }

    public function toMail($notifiable)
    {
        return (new MailMessage)
            ->subject('🚨 Wafy Alert: IP Banned')
            ->error()
            ->greeting('Hello Admin,')
            ->line('Wafy has detected malicious activity and banned an IP address.')
            ->line('**IP Address:** ' . $this->bannedIp->ip_address)
            ->line('**Reason:** ' . $this->bannedIp->reason)
            ->line('**Method:** ' . ($this->bannedIp->request_data['method'] ?? 'N/A'))
            ->line('**URL:** ' . ($this->bannedIp->request_data['url'] ?? 'N/A'));
    }

    public function toSlack($notifiable)
    {
        return (new SlackMessage)
            ->error()
            ->content('🚨 *Wafy Alert: IP Banned*')
            ->attachment(function ($attachment) {
            $attachment->title('Banned IP: ' . $this->bannedIp->ip_address)
                ->fields([
                'Reason' => $this->bannedIp->reason,
                'Method' => $this->bannedIp->request_data['method'] ?? 'N/A',
                'URL' => $this->bannedIp->request_data['url'] ?? 'N/A',
            ]);
        });
    }
}