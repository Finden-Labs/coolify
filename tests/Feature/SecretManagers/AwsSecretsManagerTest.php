<?php

use App\Actions\IntegrationToken\UpdateIntegrationToken;
use App\Livewire\Security\IntegrationTokenForm;
use App\Models\Application;
use App\Models\Environment;
use App\Models\InstanceSettings;
use App\Models\IntegrationToken;
use App\Models\Project;
use App\Models\SecretManagerLink;
use App\Models\Server;
use App\Models\Team;
use App\Models\User;
use App\Services\AwsSecretsManagerService;
use App\Services\SecretManagers\ResourceSecretManager;
use Aws\CommandInterface;
use Aws\Exception\AwsException;
use Aws\MockHandler;
use Aws\Result;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
use Livewire\Livewire;

uses(RefreshDatabase::class);

beforeEach(function () {
    if (! InstanceSettings::query()->whereKey(0)->exists()) {
        $settings = new InstanceSettings;
        $settings->id = 0;
        $settings->save();
    }

    $this->team = Team::factory()->create();
    $this->user = User::factory()->create();
    $this->team->members()->attach($this->user->id, ['role' => 'owner']);
    session(['currentTeam' => $this->team]);
    $this->actingAs($this->user);
});

/**
 * Builds every AwsSecretsManagerService on a mock handler with the responses, and records the arguments of each build.
 *
 * @return array{0: MockHandler, 1: ArrayObject<int, array<string, mixed>>}
 */
function fakeAwsSecretsManager(array $responses): array
{
    $handler = new MockHandler($responses);
    $builds = new ArrayObject;
    app()->bind(AwsSecretsManagerService::class, function ($app, array $parameters) use ($handler, $builds) {
        $builds->append($parameters);

        return new AwsSecretsManagerService(...$parameters, handler: $handler);
    });

    return [$handler, $builds];
}

/**
 * Runs the callback with AWS credentials in the environment, as on a host that has them.
 */
function withHostAwsCredentials(Closure $callback): mixed
{
    putenv('AWS_ACCESS_KEY_ID=AKIAHOSTCREDENTIALS1');
    putenv('AWS_SECRET_ACCESS_KEY=host-secret-access-key');

    try {
        return $callback();
    } finally {
        putenv('AWS_ACCESS_KEY_ID');
        putenv('AWS_SECRET_ACCESS_KEY');
    }
}

function makeRootTeamCurrent(): Team
{
    $rootTeam = Team::factory()->create(['id' => 0]);
    $rootTeam->members()->attach(test()->user->id, ['role' => 'owner']);
    test()->user->unsetRelation('teams');
    session(['currentTeam' => $rootTeam]);

    return $rootTeam;
}

function createAwsSecretManagerLink(int $teamId, array $metadata, string $secretId = 'prod/web'): SecretManagerLink
{
    $server = Server::factory()->create(['team_id' => $teamId]);
    $destination = $server->standaloneDockers()->firstOrFail();
    $project = Project::factory()->create(['team_id' => $teamId]);
    $environment = Environment::factory()->create(['project_id' => $project->id]);
    $application = Application::factory()->create([
        'environment_id' => $environment->id,
        'destination_id' => $destination->id,
        'destination_type' => $destination->getMorphClass(),
    ]);

    $token = IntegrationToken::query()->create([
        'team_id' => $teamId,
        'provider' => 'aws_secrets_manager',
        'name' => 'AWS',
        'token' => 'token-secret-access-key',
        'capabilities' => ['secrets'],
        'metadata' => $metadata,
    ]);

    return $application->secretManagerLink()->create([
        'integration_token_id' => $token->id,
        'settings' => ['secret_id' => $secretId],
    ]);
}

describe('AwsSecretsManagerService', function () {
    test('reads a secret of key value pairs with the access key of the token, not of the host', function () {
        $handler = new MockHandler([
            new Result(['SecretString' => json_encode(['DB_PASSWORD' => 's3cret', 'REPLICAS' => 3, 'FLAGS' => ['beta' => true]])]),
        ]);

        $secrets = withHostAwsCredentials(fn () => (new AwsSecretsManagerService('eu-west-1', 'AKIATOKENCREDENTIAL1', 'token-secret', handler: $handler))
            ->fetchSecrets('prod/my-app'));

        expect($secrets)->toBe(['DB_PASSWORD' => 's3cret', 'REPLICAS' => '3', 'FLAGS' => '{"beta":true}'])
            ->and($handler->getLastCommand()->getName())->toBe('GetSecretValue')
            ->and($handler->getLastCommand()['SecretId'])->toBe('prod/my-app')
            ->and($handler->getLastRequest()->getUri()->getHost())->toBe('secretsmanager.eu-west-1.amazonaws.com')
            ->and($handler->getLastRequest()->getHeaderLine('Authorization'))->toContain('Credential=AKIATOKENCREDENTIAL1/');
    });

    test('rejects a secret that is not a json object', function (Result $result) {
        $handler = new MockHandler([$result]);

        expect(fn () => (new AwsSecretsManagerService('us-east-1', 'AKIATOKENCREDENTIAL1', 'secret', handler: $handler))->fetchSecrets('prod/app'))
            ->toThrow(RuntimeException::class, 'AWS Secrets Manager error: the secret');
    })->with([
        'plain text' => fn () => new Result(['SecretString' => 'just-a-password']),
        'json list' => fn () => new Result(['SecretString' => '["a","b"]']),
        'binary' => fn () => new Result(['SecretBinary' => 'binary-value']),
    ]);

    test('throws a readable error when aws refuses the read', function () {
        $handler = new MockHandler([
            fn (CommandInterface $command) => new AwsException('Denied', $command, [
                'code' => 'AccessDeniedException',
                'message' => 'User is not authorized to perform secretsmanager:GetSecretValue',
            ]),
        ]);

        expect(fn () => (new AwsSecretsManagerService('us-east-1', 'AKIATOKENCREDENTIAL1', 'secret', handler: $handler))->fetchSecrets('prod/app'))
            ->toThrow(RuntimeException::class, 'AWS Secrets Manager error: AccessDeniedException (User is not authorized to perform secretsmanager:GetSecretValue)');
    });

    test('names the region when aws cannot be reached', function () {
        $connectionError = fn (CommandInterface $command) => new AwsException('Connection refused', $command, ['connection_error' => true]);
        $handler = new MockHandler([$connectionError, $connectionError, $connectionError]);

        expect(fn () => (new AwsSecretsManagerService('us-east-1', 'AKIATOKENCREDENTIAL1', 'secret', handler: $handler))->fetchSecrets('prod/app'))
            ->toThrow(RuntimeException::class, 'Could not connect to AWS Secrets Manager in us-east-1.');
    });

    test('refuses a region that is not an aws region before any request', function (string $region) {
        expect(fn () => new AwsSecretsManagerService($region, 'AKIATOKENCREDENTIAL1', 'secret'))
            ->toThrow(InvalidArgumentException::class, 'The AWS region is not valid.');
    })->with([
        'host name' => 'attacker.example.com',
        'trailing newline' => "us-east-1\n",
        'path' => 'us-east-1/../x',
    ]);

    test('never falls back to the host credentials when the access key is missing', function () {
        expect(fn () => new AwsSecretsManagerService('us-east-1', '', ''))
            ->toThrow(InvalidArgumentException::class, 'An AWS access key ID and secret access key are required.');
    });

    test('validates the credentials with sts get caller identity', function () {
        $handler = new MockHandler([
            new Result(['Account' => '123456789012', 'Arn' => 'arn:aws:iam::123456789012:user/coolify']),
            fn (CommandInterface $command) => new AwsException('Invalid', $command, ['code' => 'InvalidClientTokenId']),
        ]);
        $service = new AwsSecretsManagerService('eu-central-1', 'AKIATOKENCREDENTIAL1', 'secret', handler: $handler);

        expect($service->validate())->toBeTrue()
            ->and($handler->getLastCommand()->getName())->toBe('GetCallerIdentity')
            ->and($handler->getLastRequest()->getUri()->getHost())->toBe('sts.eu-central-1.amazonaws.com')
            ->and($service->validate())->toBeFalse();
    });
});

describe('credentials of the coolify host', function () {
    test('only the root team can build the service with host credentials', function () {
        [, $builds] = fakeAwsSecretsManager([]);
        $metadata = ['region' => 'us-east-1', 'credential_source' => 'host'];

        expect(fn () => AwsSecretsManagerService::forTeam($this->team->id, '', $metadata))
            ->toThrow(RuntimeException::class, 'Only the root team can use the AWS credentials of the Coolify host.')
            ->and($builds)->toHaveCount(0);

        AwsSecretsManagerService::forTeam(0, 'stored-secret', $metadata);

        expect($builds[0])->toMatchArray(['useHostCredentials' => true, 'accessKeyId' => '', 'secretAccessKey' => '']);
    });

    test('the root team can add a token that uses the host credentials without a secret', function () {
        makeRootTeamCurrent();
        [$handler] = fakeAwsSecretsManager([new Result(['Account' => '123456789012'])]);

        withHostAwsCredentials(fn () => Livewire::test(IntegrationTokenForm::class)
            ->set('provider', 'aws_secrets_manager')
            ->set('name', 'EC2 role')
            ->set('metadata', ['region' => 'us-east-1', 'credential_source' => 'host', 'access_key_id' => 'AKIALEFTOVERVALUE01'])
            ->call('addToken')
            ->assertHasNoErrors());

        $token = IntegrationToken::query()->where('provider', 'aws_secrets_manager')->firstOrFail();

        expect($token->team_id)->toBe(0)
            ->and($token->token)->toBe('')
            ->and($token->metadata)->toEqual(['region' => 'us-east-1', 'credential_source' => 'host'])
            ->and($handler->getLastRequest()->getHeaderLine('Authorization'))->toContain('Credential=AKIAHOSTCREDENTIALS1/');
    });

    test('another team cannot add a token that uses the host credentials', function () {
        [, $builds] = fakeAwsSecretsManager([]);

        Livewire::test(IntegrationTokenForm::class)
            ->set('provider', 'aws_secrets_manager')
            ->set('name', 'EC2 role')
            ->set('metadata', ['region' => 'us-east-1', 'credential_source' => 'host'])
            ->call('addToken')
            ->assertHasErrors(['metadata.credential_source']);

        expect($builds)->toHaveCount(0);
        $this->assertDatabaseCount('integration_tokens', 0);
    });

    test('a host credentials token outside the root team cannot read secrets', function () {
        [, $builds] = fakeAwsSecretsManager([]);
        // For example a token that was imported into another team.
        $link = createAwsSecretManagerLink($this->team->id, ['region' => 'us-east-1', 'credential_source' => 'host']);

        expect(fn () => $link->fetchSecrets())
            ->toThrow(RuntimeException::class, 'Only the root team can use the AWS credentials of the Coolify host.')
            ->and($builds)->toHaveCount(0);
    });

    test('switching a token to host credentials removes the stored access key', function () {
        makeRootTeamCurrent();
        fakeAwsSecretsManager([new Result(['Account' => '123456789012'])]);
        $token = IntegrationToken::query()->create([
            'team_id' => 0, 'provider' => 'aws_secrets_manager', 'name' => 'AWS', 'token' => 'old-secret', 'capabilities' => ['secrets'],
            'metadata' => ['credential_source' => 'access_key', 'region' => 'us-east-1', 'access_key_id' => 'AKIATOKENCREDENTIAL1'],
        ]);

        withHostAwsCredentials(fn () => UpdateIntegrationToken::run(
            $token, 'AWS', null, ['secrets'], ['credential_source' => 'host', 'region' => 'us-east-1', 'access_key_id' => 'AKIATOKENCREDENTIAL1'], true, false, 'ui',
        ));

        $token->refresh();
        expect($token->token)->toBe('')
            ->and($token->metadata)->toEqual(['credential_source' => 'host', 'region' => 'us-east-1']);
    });
});

describe('access key tokens', function () {
    test('an access key token is validated before it is saved', function () {
        [, $builds] = fakeAwsSecretsManager([new Result(['Account' => '123456789012'])]);

        Livewire::test(IntegrationTokenForm::class)
            ->set('provider', 'aws_secrets_manager')
            ->assertSet('metadata', ['credential_source' => 'access_key'])
            ->set('name', 'AWS production')
            ->set('token', 'token-secret-access-key')
            ->set('metadata', ['region' => 'eu-west-1', 'access_key_id' => 'AKIATOKENCREDENTIAL1'])
            ->call('addToken')
            ->assertHasNoErrors();

        $token = IntegrationToken::query()->where('provider', 'aws_secrets_manager')->firstOrFail();

        expect($token->token)->toBe('token-secret-access-key')
            ->and($token->metadata)->toEqual(['credential_source' => 'access_key', 'region' => 'eu-west-1', 'access_key_id' => 'AKIATOKENCREDENTIAL1'])
            ->and($builds[0])->toMatchArray(['useHostCredentials' => false, 'region' => 'eu-west-1']);
    });

    test('an access key token needs the access key and a valid region', function () {
        [, $builds] = fakeAwsSecretsManager([]);

        Livewire::test(IntegrationTokenForm::class)
            ->set('provider', 'aws_secrets_manager')
            ->set('name', 'AWS production')
            ->set('metadata', ['region' => 'attacker.example.com'])
            ->call('addToken')
            ->assertHasErrors(['token', 'metadata.access_key_id', 'metadata.region']);

        expect($builds)->toHaveCount(0);
    });

    test('changing the access key id needs the secret access key again', function () {
        $token = IntegrationToken::query()->create([
            'team_id' => $this->team->id, 'provider' => 'aws_secrets_manager', 'name' => 'AWS', 'token' => 'old-secret', 'capabilities' => ['secrets'],
            'metadata' => ['credential_source' => 'access_key', 'region' => 'us-east-1', 'access_key_id' => 'AKIATOKENCREDENTIAL1'],
        ]);

        expect(fn () => UpdateIntegrationToken::run(
            $token, 'AWS', null, ['secrets'], ['credential_source' => 'access_key', 'region' => 'us-east-1', 'access_key_id' => 'AKIAOTHERCREDENTIAL1'], true, false, 'ui',
        ))->toThrow(ValidationException::class);
    });

    test('a link reads the configured secret with the token of its team', function () {
        [$handler] = fakeAwsSecretsManager([new Result(['SecretString' => '{"API_KEY":"value"}'])]);
        $link = createAwsSecretManagerLink($this->team->id, [
            'credential_source' => 'access_key', 'region' => 'ap-southeast-2', 'access_key_id' => 'AKIATOKENCREDENTIAL1', 'timeout' => 20,
        ], 'arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:prod/web-AbCdEf');

        expect($link->fetchSecrets())->toBe(['API_KEY' => 'value'])
            ->and($link->sourceSummary())->toBe('arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:prod/web-AbCdEf')
            ->and($handler->getLastCommand()['SecretId'])->toBe('arn:aws:secretsmanager:ap-southeast-2:123456789012:secret:prod/web-AbCdEf')
            ->and($handler->getLastRequest()->getHeaderLine('Authorization'))->toContain('Credential=AKIATOKENCREDENTIAL1/');
    });

    test('a link needs a valid secret name or arn', function (array $settings) {
        $token = new IntegrationToken(['provider' => 'aws_secrets_manager']);
        $rules = app(ResourceSecretManager::class)->settingsRules($token);

        expect(Validator::make(['settings' => $settings], $rules)->fails())->toBeTrue();
    })->with([
        'missing' => [[]],
        'invalid characters' => [['secret_id' => 'prod/web secret']],
    ]);
});
