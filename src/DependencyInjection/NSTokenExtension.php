<?php

namespace NS\TokenBundle\DependencyInjection;

use Lcobucci\JWT\Signer\Key;
use NS\TokenBundle\Generator\TokenGenerator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

class NSTokenExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->setParameter('ns_token.id', $config['id']);
        $container->setParameter('ns_token.issuer', $config['issuer']);
        $container->setParameter('ns_token.signer', $config['signer']);
        $container->setParameter('ns_token.short_expiration', $config['short_expiration']);
        $container->setParameter('ns_token.long_expiration', $config['long_expiration']);
        $container->setParameter('ns_token.audience', $config['audience'] ?? null);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');

        $keyService = $container->register('ns_token.key')
            ->setClass(Key::class)
            ->setPublic(false)
            ->setArguments([$config['key']]);

        $def = $container->getDefinition(TokenGenerator::class);
        $def->setArgument(2, $keyService);
    }
}
