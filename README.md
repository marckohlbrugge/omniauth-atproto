# README

This is a work-in-progress for an omnauth strategy for AT Proto. (Bluesky, etc.)

It is definitely not production ready yet. Only some parts work.

Your help is very welcome.

Eventually we could turn this into a Ruby gem.

## How to run

### Generating credentials

```
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve | openssl pkcs8 -topk8 -nocrypt -outform pem > oauth-private-key.pem

openssl ec -in oauth-private-key.pem -pubout > oauth-public-key.pem
```

This should generate 2 files: `oauth-private-key.pem` and `oauth-public-key.pem`.

```
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM5BHQhVKR9STxiJG
IE+Jb/yxQvftew9HknEQUGaRsSqhRANCAAQH3r8GHE27Gsy0sHQRUSo9yqu8r58F
nBuWEIaxldS8he/3ZVHUim7qXe9knTa1O2aHsIVTnC8FiZ6J0tvJecE8
-----END PRIVATE KEY-----
```

```
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB96/BhxNuxrMtLB0EVEqPcqrvK+f
BZwblhCGsZXUvIXv92VR1Ipu6l3vZJ02tTtmh7CFU5wvBYmeidLbyXnBPA==
-----END PUBLIC KEY-----
```

Remove the header and footer from the `.pem` files and set the base64 encoded string for the private key, and the public key.

```bash
rails credentials:edit -e development
```

```yaml
atproto:
  private_key: |
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgM5BHQhVKR9STxiJG
    IE+Jb/yxQvftew9HknEQUGaRsSqhRANCAAQH3r8GHE27Gsy0sHQRUSo9yqu8r58F
    nBuWEIaxldS8he/3ZVHUim7qXe9knTa1O2aHsIVTnC8FiZ6J0tvJecE8
  public_key: |
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB96/BhxNuxrMtLB0EVEqPcqrvK+f
    BZwblhCGsZXUvIXv92VR1Ipu6l3vZJ02tTtmh7CFU5wvBYmeidLbyXnBPA==
  key_pair_id: banana
  public_url: https://local.blueskycounter.com
```

### Running the server

```
rails server
cloudflared tunnel run
```

NOTE: Running cloudflared tunnel requires some more setup. You can also use ngrok, etc. Basically you need to get a public URL.

## Development

You need to restart the server when you change the credentials, or omniauth strategy.

Make sure `http://local.blueskycounter.com/auth/atproto/client-metadata.json` returns a valid response.

## What seems to work

* Findind DID based on handle
* Redirecting to the authentication server


## What does NOT seem to work yet

* Processing the callback correctly
* Refreshing access tokens


## Hard-coded URL

AT Proto doesn't seem to work well with `localhost:3000` so we have to use some tunnel (like ngrok or cloudflare) to get it working. BEcuase of this, I needed to hardocde a URL in several places. Please update them when testing/developing.

* `config/initializers/omniauth.rb`
* `lib/omniauth/strategies/atproto.rb`
* `app/controllers/atproto_controller.rb`
* `config/environments/development.rb`


## Relevant documentation and code

* https://docs.bsky.app/blog/oauth-atproto
* https://docs.bsky.app/docs/advanced-guides/oauth-client
* https://github.com/pilcrowonpaper/atproto-oauth-example
* https://github.com/bluesky-social/cookbook/blob/main/python-oauth-web-app/atproto_oauth.py