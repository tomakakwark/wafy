<?php

namespace Bdsa\Wafy\Notifications\Channels;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Http;

class TeamsWebhookChannel
{
    /**
     * Send the given notification to a Microsoft Teams incoming webhook
     * (MessageCard / connector format).
     *
     * Errors propagate — see DiscordWebhookChannel for the rationale.
     */
    public function send($notifiable, Notification $notification): void
    {
        $url = $notifiable->routeNotificationFor('teams', $notification);

        if (empty($url) || !method_exists($notification, 'toTeams')) {
            return;
        }

        Http::timeout(5)
            ->asJson()
            ->throw()
            ->post($url, $notification->toTeams($notifiable));
    }
}
