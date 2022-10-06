## Syapse Flask JWT Consumer

> Flask extension for JWT token validation

This is a fork of [dmi3y/flask-jwt-consumer](https://github.com/dmi3y/flask-jwt-consumer), intended for internal use at Syapse. Dmi3y's original tool has been used extensively in Syapse's flask applications. Now that our JWT-handling needs have expanded to require additional flexibility, we have forked the original project.

Based on [pyJWT](https://github.com/jpadilla/pyjwt). Supports multi public key validation in form of simplified `authorized_keys` format, with only keys, and comments, no options. Good for key rotations or when you need multi issuer support.

### Rational

We initially decided to fork this project based on a need to create applications that can support *both* header-auth and cookie-auth, simultaneously. See the API in [minerva-service](https://github.com/syapse/minerva-service) for examples of this.

From the original author:
Inspired by [Flask JWT Simple](https://github.com/vimalloc/flask-jwt-simple), nice package I was enjoying until the need for multi key support. So that's where many backward compatible settings came from.

### Configuration

- `JWT_ALGORITHM` default `RS256`, algorithm used to decode JWT. As current iteration only asymmetric algorithms are considered. So anything symmetric will likely fail.
- `JWT_HEADER_NAME` default `Authorization`, header where JWT expected to be.
- `JWT_HEADER_TYPE` default `Bearer`, type of the token, part of the header's value.
- `JWT_IDENTITY` optional, if provided JWT will use it.
- `JWT_AUTHORIZED_KEYS` new line separated list of OpenSSH formatted keys.
- `VERIFY_AUD` disable verification of `aud` during JWT decoding.

### Decorators

*@requires_jwt* - use on the flask endpoint that is desired to be protected, accepts additional parameter `pass_token_payload` which will add named parameter `token_payload` at the very end of the parameters accepted by decorated function.

```py
@requires_jwt
def get(search):
    # ...GET logic with search parameter

@requires_jwt(pass_token_payload=True)
def post(data, token_payload):
    # ...POST logic with data parameter and token payload
```

### Cookie-auth vs. Header-Auth

`syapse-flask-jwt-consumer`, unlike the original project, is able to support both header-auth and cookie-auth in a single application. We do this by first checking a request for an authorization jwt token in the request cookie, and using the token if found in the cook. If we do not find a request auth-cookie, we checker the request headers for an authorization token, again using this for the auth token. If neither cookie nor header are found, we surface an error.

This feature is used in `minerva-serice`, where the MTB/Patient-Finder API uses header-auth to support internal, server-server requests, while the Provenance API uses cookie-auth to facilitate external client-server requests.
