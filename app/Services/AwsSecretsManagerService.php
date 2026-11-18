<?php

namespace App\Services;

use App\Models\IntegrationToken;
use Aws\Credentials\CredentialProvider;
use Aws\Credentials\Credentials;
use Aws\Exception\AwsException;
use Aws\Exception\CredentialsException;
use Aws\SecretsManager\SecretsManagerClient;
use Aws\Sts\StsClient;
use InvalidArgumentException;
use RuntimeException;

/**
 * Reads one AWS Secrets Manager secret that holds key/value pairs (a JSON object).
 *
 * With an access key, the SDK uses only that key: it never falls back to the credentials of the Coolify host.
 * With host credentials, the SDK default chain is used (environment, ECS task role, EC2 instance profile).
 * Only tokens of the root team may use host credentials, see IntegrationToken::mayUseAwsHostCredentials().
 */
class AwsSecretsManagerService
{
    /** An AWS region such as us-east-1 or us-gov-west-1. The SDK builds the endpoint host name from it. */
    public const REGION_PATTERN = '/^[a-z]{2,4}(-[a-z]+)+-\d{1,2}$/D';

    public const ACCESS_KEY_ID_PATTERN = '/^[A-Z0-9]{16,128}$/D';

    /** A secret name (letters, digits, and /_+=.@-) or a secret ARN. */
    public const SECRET_ID_PATTERN = '/^[A-Za-z0-9\/_+=.@:-]{1,2048}$/D';

    /**
     * @param  callable|null  $handler  HTTP handler of the SDK; tests pass an Aws\MockHandler.
     */
    public function __construct(
        private string $region,
        private string $accessKeyId,
        #[\SensitiveParameter] private string $secretAccessKey,
        private bool $useHostCredentials = false,
        private ?int $timeout = null,
        private mixed $handler = null,
    ) {
        if (preg_match(self::REGION_PATTERN, $this->region) !== 1) {
            throw new InvalidArgumentException('The AWS region is not valid.');
        }
        if (! $this->useHostCredentials && (blank($this->accessKeyId) || blank($this->secretAccessKey))) {
            throw new InvalidArgumentException('An AWS access key ID and secret access key are required.');
        }
    }

    /**
     * Builds the service for a token of the team. Host credentials are refused for every team except the root team.
     *
     * @param  array<string, mixed>  $metadata
     *
     * @throws RuntimeException when a team other than the root team asks for host credentials
     */
    public static function forTeam(int $teamId, #[\SensitiveParameter] string $secretAccessKey, array $metadata): self
    {
        $useHostCredentials = IntegrationToken::usesAwsHostCredentials($metadata);
        if ($useHostCredentials && ! IntegrationToken::mayUseAwsHostCredentials($teamId)) {
            throw new RuntimeException('Only the root team can use the AWS credentials of the Coolify host.');
        }

        return app(self::class, [
            'region' => (string) data_get($metadata, 'region'),
            'accessKeyId' => $useHostCredentials ? '' : (string) data_get($metadata, 'access_key_id'),
            'secretAccessKey' => $useHostCredentials ? '' : $secretAccessKey,
            'useHostCredentials' => $useHostCredentials,
            'timeout' => IntegrationToken::requestTimeout($metadata),
        ]);
    }

    /**
     * Checks the credentials with STS GetCallerIdentity, which needs no IAM permission.
     */
    public function validate(): bool
    {
        try {
            $this->stsClient()->getCallerIdentity();

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Reads the current version of the secret. Non-string values are returned as JSON strings.
     *
     * @return array<string, string>
     *
     * @throws RuntimeException when the secret cannot be read or is not a JSON object
     */
    public function fetchSecrets(string $secretId): array
    {
        if (preg_match(self::SECRET_ID_PATTERN, $secretId) !== 1) {
            throw new RuntimeException('AWS Secrets Manager error: the secret name or ARN is not valid.');
        }

        try {
            $result = $this->secretsManagerClient()->getSecretValue(['SecretId' => $secretId]);
        } catch (AwsException $e) {
            throw $this->readableError($e);
        } catch (CredentialsException $e) {
            throw new RuntimeException($this->missingCredentialsMessage(), previous: $e);
        }

        $secretString = $result['SecretString'] ?? null;
        if (! is_string($secretString)) {
            throw new RuntimeException('AWS Secrets Manager error: the secret has no text value. Store it as key/value pairs.');
        }

        $values = json_decode($secretString, true);
        if (! is_array($values) || ($values !== [] && array_is_list($values))) {
            throw new RuntimeException('AWS Secrets Manager error: the secret is not a JSON object of key/value pairs.');
        }

        return collect($values)
            ->mapWithKeys(fn (mixed $value, int|string $key): array => [(string) $key => is_string($value) ? $value : (string) json_encode($value)])
            ->all();
    }

    private function readableError(AwsException $e): RuntimeException
    {
        if ($e->getAwsErrorCode() === null) {
            return new RuntimeException("Could not connect to AWS Secrets Manager in {$this->region}.", previous: $e);
        }

        $message = 'AWS Secrets Manager error: '.$e->getAwsErrorCode();
        if (filled($e->getAwsErrorMessage())) {
            $message .= ' ('.$e->getAwsErrorMessage().')';
        }

        return new RuntimeException($message, previous: $e);
    }

    private function missingCredentialsMessage(): string
    {
        return $this->useHostCredentials
            ? 'No AWS credentials were found on the Coolify host. Attach an IAM role to the instance and let the Coolify container reach the instance metadata service.'
            : 'The AWS access key could not be used.';
    }

    private function secretsManagerClient(): SecretsManagerClient
    {
        return new SecretsManagerClient($this->clientConfig());
    }

    private function stsClient(): StsClient
    {
        return new StsClient($this->clientConfig() + ['sts_regional_endpoints' => 'regional']);
    }

    /**
     * @return array<string, mixed>
     */
    private function clientConfig(): array
    {
        $config = [
            'version' => 'latest',
            'region' => $this->region,
            'retries' => 2,
            'http' => [
                'connect_timeout' => $this->timeout ?? 5,
                'timeout' => $this->timeout ?? 10,
            ],
        ];

        if ($this->useHostCredentials) {
            $config['credentials'] = CredentialProvider::defaultProvider();
        } else {
            $config['credentials'] = new Credentials($this->accessKeyId, $this->secretAccessKey);
            // Do not read ~/.aws/config or ~/.aws/credentials of the host either.
            $config['use_aws_shared_config_files'] = false;
        }

        if ($this->handler !== null) {
            $config['handler'] = $this->handler;
        }

        return $config;
    }
}
