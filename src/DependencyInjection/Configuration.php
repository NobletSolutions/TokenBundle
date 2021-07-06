<?php

namespace NS\TokenBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;
use Lcobucci\JWT\Signer\Hmac\Sha256;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('ns_token');

        $treeBuilder
            ->getRootNode()
            ->children()
                ->scalarNode('id')->cannotBeEmpty()->end()
                ->scalarNode('key')->cannotBeEmpty()->end()
                ->scalarNode('issuer')->cannotBeEmpty()->end()
                ->scalarNode('audience')->end()
                ->scalarNode('signer')->defaultValue(Sha256::class)->end()
                ->scalarNode('short_expiration')->defaultValue(3600)->end()
                ->scalarNode('long_expiration')->defaultValue(2592000)->end()
            ->end();

        return $treeBuilder;
    }
}
