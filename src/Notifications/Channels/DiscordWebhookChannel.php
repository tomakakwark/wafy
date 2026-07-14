<?php

namespace Bdsa\Wafy\Notifications\Channels;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class DiscordWebhookChannel
{
    /**
     * Send the given notification to a Discord incoming webhook.
     *
     * Errors are allowed to propagate: on the sync queue driver they are caught
     * by DetectMaliciousRequests::banIp(); on a real queue they surface as a
     * failed job; and wafy:test-notification catches them to report per channel.
     */
    public function send($notifiable, Notification $notification): void
    {
        $url = $notifiable->routeNotificationFor('discord', $notification);

        if (empty($url) || !method_exists($notification, 'toDiscord')) {
            return;
        }

        Http::timeout(5)
            ->asJson()
            ->throw()
            ->post($url, $notification->toDiscord($notifiable));
    }
}
