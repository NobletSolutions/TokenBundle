Installation
============

```yaml
  composer require ns/token-bundle
```

Edit AppKernel.php and add the bundle

```yaml
    new NS\TokenBundle\NSTokenBundle(),
```

Edit app/config/config.yml

```yaml
    ns_token:
        generator:
            id: <some random string>
            key: <another random string>
            issuer: <string (often the site source)>
            short_expiration: 3600
            long_expiration: 2592000
            signer: Lcobucci\JWT\Signer\Rsa\Sha256 #default
```
You can use your own signer by implementing the Lcobucci\JWT\Signer interface.
