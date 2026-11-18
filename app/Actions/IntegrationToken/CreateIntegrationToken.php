<?php

namespace App\Actions\IntegrationToken;

use App\Models\IntegrationToken;
use App\Services\AwsSecretsManagerService;
use App\Services\Dns\CloudflareDnsProvider;
use App\Services\IntegrationTokenValidator;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;
use Lorisleiva\Actions\Concerns\AsAction;
use RuntimeException;

/**
 * Creates an integration token after the provider accepted it. A Cloudflare token also gets its zones in the same
 * transaction, so a token without zone access is never stored. The security page and the API use this action.
 */
class CreateIntegrationToken
{
    use AsAction;

    public function __construct(
        private IntegrationTokenValidator $validator,
        private CloudflareDnsProvider $cloudflare,
    ) {}

    /**
     * Validation rules for the token fields. `automatic_dns` and `proxied_dns` are validated by the caller.
     *
     * @param  int|null  $teamId  The team that owns the token. Only the root team may select AWS host credentials.
     * @return array<string, array<int, mixed>>
     */
    public static function rules(string $provider, ?int $teamId = null): array
    {
        $rules = [
            'provider' => ['required', 'in:'.implode(',', array_keys(IntegrationToken::PROVIDER_NAMES))],
            'name' => ['required', 'string', 'max:255'],
            'token' => ['required', 'string'],
            'capabilities' => ['required', 'array', 'min:1', function (string $attribute, mixed $value, \Closure $fail): void {
                if (is_array($value) && in_array('tunnel', $value, true) && ! in_array('dns', $value, true)) {
                    $fail('Cloudflare Tunnel also needs the DNS capability.');
                }
            }],
            'capabilities.*' => ['required', 'in:'.implode(',', IntegrationToken::allowedCapabilities($provider))],
        ];

        if ($provider === 'doppler') {
            $rules['token'][] = 'regex:/^dp\.(st|sa)\./';
        } elseif ($provider === 'infisical') {
            $rules['metadata.base_url'] = ['required', 'url:http,https'];
            $rules['metadata.client_id'] = ['required', 'string'];
            $rules['metadata.timeout'] = ['nullable', 'integer', 'min:1', 'max:300'];
        } elseif ($provider === 'vault') {
            $rules['metadata.base_url'] = ['required', 'url:http,https'];
            $rules['metadata.namespace'] = ['nullable', 'string'];
            $rules['metadata.timeout'] = ['nullable', 'integer', 'min:1', 'max:300'];
        } elseif ($provider === 'aws_secrets_manager') {
            $host = IntegrationToken::AWS_CREDENTIAL_SOURCE_HOST;
            $credentialSources = [IntegrationToken::AWS_CREDENTIAL_SOURCE_ACCESS_KEY];
            if ($teamId !== null && IntegrationToken::mayUseAwsHostCredentials($teamId)) {
                $credentialSources[] = $host;
            }

            // The secret access key; host credentials need none.
            $rules['token'] = ["required_unless:metadata.credential_source,{$host}", 'nullable', 'string'];
            $rules['metadata.region'] = ['required', 'string', 'regex:'.AwsSecretsManagerService::REGION_PATTERN];
            $rules['metadata.credential_source'] = ['nullable', 'in:'.implode(',', $credentialSources)];
            $rules['metadata.access_key_id'] = [
                "required_unless:metadata.credential_source,{$host}", 'nullable', 'string', 'regex:'.AwsSecretsManagerService::ACCESS_KEY_ID_PATTERN,
            ];
            $rules['metadata.timeout'] = ['nullable', 'integer', 'min:1', 'max:300'];
        }

        return $rules;
    }

    /**
     * Messages for the rules of the provider.
     *
     * @return array<string, string>
     */
    public static function messages(string $provider): array
    {
        if ($provider !== 'aws_secrets_manager') {
            return [];
        }

        return [
            'token.required_unless' => 'Enter the secret access key.',
            'metadata.region.regex' => 'Enter an AWS region, such as us-east-1.',
            'metadata.access_key_id.required_unless' => 'Enter the access key ID.',
            'metadata.access_key_id.regex' => 'Enter an AWS access key ID, such as AKIAIOSFODNN7EXAMPLE.',
            'metadata.credential_source.in' => 'Select an access key. Only the root team can use the AWS credentials of the Coolify host.',
        ];
    }

    /**
     * Settings of an AWS token with an explicit credential source. Host credentials keep no access key ID.
     *
     * @param  array<string, mixed>  $metadata
     * @return array<string, mixed>
     */
    public static function normalizeAwsMetadata(array $metadata): array
    {
        if (IntegrationToken::usesAwsHostCredentials($metadata)) {
            unset($metadata['access_key_id']);

            return $metadata;
        }

        return ['credential_source' => IntegrationToken::AWS_CREDENTIAL_SOURCE_ACCESS_KEY] + $metadata;
    }

    /**
     * Refuses AWS host credentials for every team except the root team. The rules check this too; this check
     * also covers callers that skip them.
     *
     * @param  array<string, mixed>  $metadata
     *
     * @throws ValidationException
     */
    public static function ensureAwsHostCredentialsAllowed(string $provider, array $metadata, int $teamId): void
    {
        if ($provider === 'aws_secrets_manager'
            && IntegrationToken::usesAwsHostCredentials($metadata)
            && ! IntegrationToken::mayUseAwsHostCredentials($teamId)) {
            throw ValidationException::withMessages([
                'metadata.credential_source' => 'Only the root team can use the AWS credentials of the Coolify host.',
            ]);
        }
    }

    /**
     * @param  array<int, string>  $capabilities
     * @param  array<string, mixed>  $metadata  Provider settings (base URL, client ID, ...); empty values are dropped.
     *
     * @throws ValidationException when a team other than the root team selects AWS host credentials
     * @throws RuntimeException when the provider rejects the token or Cloudflare zones cannot be read
     */
    public function handle(
        int $teamId,
        string $provider,
        string $name,
        #[\SensitiveParameter] string $token,
        array $capabilities,
        array $metadata = [],
        bool $automaticDns = true,
        bool $proxiedDns = false,
    ): IntegrationToken {
        $metadata = array_filter($metadata, fn ($value) => filled($value));
        if ($provider === 'aws_secrets_manager') {
            $metadata = self::normalizeAwsMetadata($metadata);
            self::ensureAwsHostCredentialsAllowed($provider, $metadata, $teamId);
            if (IntegrationToken::usesAwsHostCredentials($metadata)) {
                $token = '';
            }
        }
        if ($provider === 'cloudflare' && ! $automaticDns) {
            $metadata['automatic_dns'] = false;
        }
        if ($provider === 'cloudflare' && $proxiedDns) {
            $metadata['proxied_dns'] = true;
        }

        if (! $this->validator->validate($provider, $token, $capabilities, $metadata, $teamId)) {
            throw new RuntimeException($this->validator->errorMessage($provider));
        }

        return DB::transaction(function () use ($teamId, $provider, $name, $token, $capabilities, $metadata): IntegrationToken {
            $integrationToken = IntegrationToken::query()->create([
                'team_id' => $teamId, 'provider' => $provider, 'name' => $name, 'token' => $token,
                'capabilities' => $capabilities, 'metadata' => $metadata ?: null,
            ]);
            if ($provider === 'cloudflare') {
                $this->cloudflare->syncZones($integrationToken);
            }

            return $integrationToken;
        });
    }
}
