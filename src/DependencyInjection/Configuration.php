<?php

namespace NS\TokenBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files.
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/configuration.html}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritdoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('ns_token');

        $rootNode
            ->children()
                ->scalarNode('id')->cannotBeEmpty()->end()
                ->scalarNode('key')->cannotBeEmpty()->end()
                ->scalarNode('issuer')->cannotBeEmpty()->end()
                ->scalarNode('audience')->end()
                ->scalarNode('signer')->defaultValue('Lcobucci\JWT\Signer\Hmac\Sha256')->end()
                ->scalarNode('short_expiration')->defaultValue(3600)->end()
                ->scalarNode('long_expiration')->defaultValue(2592000)->end()
            ->end();

        return $treeBuilder;
    }
}
