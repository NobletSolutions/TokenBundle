<?php declare(strict_types=1);

namespace NS\TokenBundle\DependencyInjection;

use Lcobucci\JWT\Signer\Key;
use NS\TokenBundle\Generator\TokenGenerator;
use Symfony\Component\Config\Definition\Exception\InvalidConfigurationException;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Alias;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;

class NSTokenExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config        = $this->processConfiguration($configuration, $configs);

        $defaultConfig = $config['default'];
        if (!isset($config['jwt_configs'][$defaultConfig])) {
            throw new InvalidConfigurationException('A default that does not exist is set. Requested %s options %s', $defaultConfig, implode(array_keys($config['jwt_configs'])));
        }

        foreach ($config['jwt_configs'] as $name => $jwtConfig) {
            $serviceName      = 'ns_token.jwt_configuration_' . $name;
            $tokenServiceName = 'ns_token.generator_' . $name;

            if ($jwtConfig['type'] === 'unsecured') {
                $confService = $container->register($serviceName)
                    ->setClass(\Lcobucci\JWT\Configuration::class)
                    ->setPublic(true)
                    ->setFactory([\Lcobucci\JWT\Configuration::class, 'forUnsecuredSigner']);

                $tokenService = $container->register($tokenServiceName)
                    ->setClass(TokenGenerator::class)
                    ->setPublic(true)
                    ->setArguments([$confService, $jwtConfig['id'], $jwtConfig['issuer'], $jwtConfig['audience'] ?? null, $jwtConfig['expiration'] ?? null]);

                if ($defaultConfig === $name) {
                    $container->addAliases(['ns_token.generator' => $tokenServiceName, TokenGenerator::class => $tokenServiceName]);
                }

                continue;
            }

            if (!isset($jwtConfig['sign_key']['signer'])) {
                throw new \RuntimeException('Invalid configuration');
            }

            $keyConfig = [Key\InMemory::class, $jwtConfig['sign_key']['base64'] ? 'base64Encoded' : 'plainText'];

            $signerService = $container->register('ns_token.signer_' . $name)
                ->setClass($jwtConfig['sign_key']['signer'])
                ->setPublic(false);

            $keyService = $container->register('ns_token.key_' . $name)
                ->setClass($keyConfig[0])
                ->setPublic(false)
                ->setFactory($keyConfig)
                ->setArguments([$jwtConfig['sign_key']['value'], $jwtConfig['sign_key']['passphrase'] ?? '']);

            if ($jwtConfig['type'] === 'symmetric') {
                $confService = $container->register($serviceName)
                    ->setClass(\Lcobucci\JWT\Configuration::class)
                    ->setPublic(false)
                    ->setFactory([\Lcobucci\JWT\Configuration::class, 'forSymmetricSigner'])
                    ->setArguments([$signerService, $keyService]);

                $tokenService = $container->register($tokenServiceName)
                    ->setClass(TokenGenerator::class)
                    ->setPublic(true)
                    ->setArguments([$confService, $jwtConfig['id'], $jwtConfig['issuer'], $jwtConfig['audience'] ?? null, $jwtConfig['expiration'] ?? null]);

                if ($defaultConfig === $name) {
                    $container->addAliases(['ns_token.generator' => $tokenServiceName, TokenGenerator::class => $tokenServiceName]);
                }

                continue;
            }

            if (isset($jwtConfig['verification_key'])) {
                $keyConfig = [Key\InMemory::class, $jwtConfig['verification_key']['base64'] ? 'base64Encoded' : 'plainText'];

                $verificationKeyService = $container->register('ns_token.verification_key_' . $name)
                    ->setClass($keyConfig[0])
                    ->setPublic(false)
                    ->setFactory($keyConfig)
                    ->setArguments([$jwtConfig['verification_key']['value'], $jwtConfig['verification_key']['passphrase'] ?? '']);

                $confService = $container->register($serviceName)
                    ->setClass(\Lcobucci\JWT\Configuration::class)
                    ->setPublic(false)
                    ->setFactory([\Lcobucci\JWT\Configuration::class, 'forAsymmetricSigner'])
                    ->setArguments([$signerService, $keyService, $verificationKeyService]);

                $tokenService = $container->register($tokenServiceName)
                    ->setClass(TokenGenerator::class)
                    ->setPublic(true)
                    ->setArguments([$confService, $jwtConfig['id'], $jwtConfig['issuer'], $jwtConfig['audience'] ?? null, $jwtConfig['expiration'] ?? null]);

                if ($defaultConfig === $name) {
                    $container->addAliases(['ns_token.generator' => $tokenServiceName, TokenGenerator::class => $tokenServiceName]);
                }
            }
        }

        $container->setParameter('ns_token.short_expiration', $config['short_expiration']);
        $container->setParameter('ns_token.long_expiration', $config['long_expiration']);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');
    }
}
