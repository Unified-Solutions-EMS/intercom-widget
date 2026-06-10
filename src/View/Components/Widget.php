<?php

declare(strict_types=1);

namespace Unified\IntercomWidget\View\Components;

use Firebase\JWT\JWT;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\View\View;
use Illuminate\Support\Facades\Log;
use Illuminate\View\Component;
use Unified\IntercomWidget\Contracts\IntercomPayloadResolver;

class Widget extends Component
{
    public function __construct(
        protected ConfigRepository $config,
        protected IntercomPayloadResolver $resolver,
    ) {}

    public function render(): View|string
    {
        $appId = $this->config->get('intercom.app_id');

        if (! is_string($appId) || $appId === '') {
            return '';
        }

        $payload = $this->resolver->resolve();

        if ($payload === null) {
            return '';
        }

        $secret = $this->config->get('intercom.jwt_secret');
        $token = is_string($secret) && $secret !== ''
            ? $this->signJwt($payload->toJwtClaims(), $secret)
            : null;
        // A non-empty but unusable secret (e.g. shorter than the 32-byte HMAC
        // floor php-jwt v7 enforces) signs to null below, not a hard failure.

        $apiBase = (string) $this->config->get('intercom.api_base', 'https://api-iam.intercom.io');

        $settings = [
            'api_base' => $apiBase,
            'app_id' => $appId,
        ];

        if ($token !== null) {
            $settings['intercom_user_jwt'] = $token;
        } else {
            // No secret configured — fall back to unauthenticated boot
            // so the Messenger still loads in local dev. Identity claims
            // are dropped on the floor; nothing about the user is sent.
        }

        return view('intercom-widget::components.widget', [
            'appId' => $appId,
            'settings' => $settings,
        ]);
    }

    /**
     * Sign the Intercom identity JWT, or return null (→ unauthenticated boot)
     * if the configured secret can't produce a valid token. php-jwt v7 rejects
     * HMAC keys shorter than the algorithm's block size, so a misconfigured
     * secret must degrade gracefully rather than 500 every page render.
     *
     * @param  array<string, mixed>  $claims
     */
    private function signJwt(array $claims, string $secret): ?string
    {
        $now = time();
        $ttl = (int) $this->config->get('intercom.jwt_ttl_seconds', 3600);

        $claims['iat'] = $now;
        $claims['exp'] = $now + $ttl;

        try {
            return JWT::encode($claims, $secret, 'HS256');
        } catch (\Throwable $e) {
            Log::warning('intercom-widget: could not sign identity JWT, falling back to unauthenticated boot.', [
                'reason' => $e->getMessage(),
            ]);

            return null;
        }
    }
}
