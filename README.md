Installation
============

    composer require ns/token-bundle

Edit AppKernel.php and add the bundle

    ...
    new NS\TokenBundle\NSTokenBundle(),

Edit app/config/config.yml

    ...
    ns_token:
        generator:
            id: <some random string>
            key: <another random string>
            issuer: <string (often the site source)>
            signer: Lcobucci\JWT\Signer\Rsa\Sha256 #default
            
You can use your own signer by implementing the Lcobucci\JWT\Signer interface.
