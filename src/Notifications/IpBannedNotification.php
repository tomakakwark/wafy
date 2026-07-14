<?php

namespace Bdsa\Wafy\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Notification;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Messages\SlackMessage;
use Bdsa\Wafy\Models\BannedIp;
use Bdsa\Wafy\Notifications\Channels\DiscordWebhookChannel;
use Bdsa\Wafy\Notifications\Channels\TeamsWebhookChannel;

class IpBannedNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public $bannedIp;

    /** @var array|null Restrict delivery to these channels (used by wafy:test-notification). */
    protected $onlyChannels = null;

    public function __construct(BannedIp $bannedIp)
    {
        $this->bannedIp = $bannedIp;
    }

    /**
     * Restrict this notification to a subset of the configured channels.
     */
    public function only(array $channels): self
    {
        $this->onlyChannels = $channels;

        return $this;
    }

    public function via($notifiable)
    {
        $channels = $this->onlyChannels ?? config('wafy.notifications.channels', ['mail']);

        // Map the friendly channel names to our custom webhook channel classes;
        // 'mail' and 'slack' resolve through Laravel's own channel manager.
        $map = [
            'discord' => DiscordWebhookChannel::class,
            'teams' => TeamsWebhookChannel::class,
        ];

        return array_map(function ($channel) use ($map) {
            return $map[$channel] ?? $channel;
        }, (array) $channels);
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

    /**
     * Payload for a Discord incoming webhook (rich embed).
     */
    public function toDiscord($notifiable): array
    {
        return [
            'username' => 'Wafy',
            'embeds' => [[
                'title' => '🚨 IP Banned',
                'description' => 'Wafy detected malicious activity and banned an IP address.',
                'color' => 15158332, // #E74C3C
                'fields' => [
                    ['name' => 'IP Address', 'value' => (string) $this->bannedIp->ip_address, 'inline' => true],
                    ['name' => 'Method', 'value' => (string) ($this->bannedIp->request_data['method'] ?? 'N/A'), 'inline' => true],
                    ['name' => 'Reason', 'value' => $this->truncate($this->bannedIp->reason)],
                    ['name' => 'URL', 'value' => $this->truncate($this->bannedIp->request_data['url'] ?? 'N/A')],
                ],
            ]],
        ];
    }

    /**
     * Payload for a Microsoft Teams incoming webhook (MessageCard).
     */
    public function toTeams($notifiable): array
    {
        return [
            '@type' => 'MessageCard',
            '@context' => 'http://schema.org/extensions',
            'themeColor' => 'D9534F',
            'summary' => 'Wafy: IP Banned',
            'sections' => [[
                'activityTitle' => '🚨 Wafy Alert: IP Banned',
                'activitySubtitle' => 'Malicious activity detected and blocked',
                'facts' => [
                    ['name' => 'IP Address', 'value' => (string) $this->bannedIp->ip_address],
                    ['name' => 'Reason', 'value' => $this->truncate($this->bannedIp->reason)],
                    ['name' => 'Method', 'value' => (string) ($this->bannedIp->request_data['method'] ?? 'N/A')],
                    ['name' => 'URL', 'value' => $this->truncate($this->bannedIp->request_data['url'] ?? 'N/A')],
                ],
                'markdown' => true,
            ]],
        ];
    }

    /**
     * Keep webhook field values within provider limits.
     */
    private function truncate($value, int $max = 1000): string
    {
        $value = (string) ($value ?? 'N/A');

        if ($value === '') {
            return 'N/A';
        }

        return strlen($value) > $max ? substr($value, 0, $max - 1) . '…' : $value;
    }
}