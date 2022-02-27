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
                ->scalarNode('default')->cannotBeEmpty()->end()
                ->scalarNode('short_expiration')->defaultValue(3600)->end()
                ->scalarNode('long_expiration')->defaultValue(2592000)->end()
                ->arrayNode('jwt_configs')
                    ->useAttributeAsKey('name')
                    ->arrayPrototype()
                        ->children()
                            ->enumNode('type')->values(['symmetric','asymmetric','unsecured'])->defaultValue('symmetric')->end()
                            ->scalarNode('id')->cannotBeEmpty()->end()
                            ->scalarNode('issuer')->cannotBeEmpty()->end()
                            ->scalarNode('audience')->end()
                            ->arrayNode('sign_key')
                                ->children()
                                    ->booleanNode('base64')->defaultValue(false)->end()
                                    ->scalarNode('value')->cannotBeEmpty()->end()
                                    ->scalarNode('passphrase')->end()
                                    ->scalarNode('signer')->defaultValue(Sha256::class)->end()
                                ->end()
                            ->end()
                            ->arrayNode('verification_key')
                                ->children()
                                    ->booleanNode('base64')->defaultValue(false)->end()
                                    ->scalarNode('value')->cannotBeEmpty()->end()
                                    ->scalarNode('passphrase')->end()
                                ->end()
                            ->end()
                            ->scalarNode('expiration')->defaultValue(2592000)->end()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
