<?php

namespace App\Services;

use App\Models\IntegrationToken;

/**
 * Validates an integration token against its provider API before it is saved.
 */
class IntegrationTokenValidator
{
    /**
     * @param  int|null  $teamId  The team that owns the token. Without it, AWS host credentials are refused.
     */
    public function validate(string $provider, #[\SensitiveParameter] string $token, array $capabilities, array $metadata = [], ?int $teamId = null): bool
    {
        return match ($provider) {
            'cloudflare' => app(CloudflareTokenValidator::class)->validate($token, $capabilities),
            'doppler' => (new DopplerService($token))->validate(),
            'infisical' => (new InfisicalService(
                (string) data_get($metadata, 'base_url', 'https://app.infisical.com'),
                (string) data_get($metadata, 'client_id'),
                $token,
                IntegrationToken::requestTimeout($metadata),
            ))->validate(),
            'vault' => (new VaultService(
                (string) data_get($metadata, 'base_url'),
                $token,
                data_get($metadata, 'namespace'),
                IntegrationToken::requestTimeout($metadata),
            ))->validate(),
            'aws_secrets_manager' => $this->validateAws($teamId, $token, $metadata),
            default => false,
        };
    }

    /**
     * @param  array<string, mixed>  $metadata
     */
    private function validateAws(?int $teamId, #[\SensitiveParameter] string $token, array $metadata): bool
    {
        try {
            return AwsSecretsManagerService::forTeam($teamId ?? -1, $token, $metadata)->validate();
        } catch (\Throwable) {
            return false;
        }
    }

    public function errorMessage(string $provider): string
    {
        return match ($provider) {
            'cloudflare' => 'The token could not access the selected Cloudflare capabilities. Check its permissions and zone resources.',
            'doppler' => 'The Doppler token could not be verified. Check the token and its access.',
            'infisical' => 'Infisical login failed. Check the base URL, the client ID, and the client secret.',
            'vault' => 'The Vault token could not be verified. Check the base URL, the namespace, and the token.',
            'aws_secrets_manager' => 'The AWS credentials could not be verified. Check the region and the access key. For host credentials, check that the Coolify host has an IAM role and that the Coolify container can reach the instance metadata service.',
            default => 'The token could not be verified.',
        };
    }

    public function connectionErrorMessage(string $provider): string
    {
        $name = IntegrationToken::PROVIDER_NAMES[$provider] ?? ucfirst($provider);

        return "Could not connect to the {$name} API. Check the network connection of Coolify and try again.";
    }
}
