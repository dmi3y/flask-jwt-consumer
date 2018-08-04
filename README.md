[![CircleCI](https://circleci.com/gh/dmi3y/flask-jwt-consumer.svg?style=svg)](https://circleci.com/gh/dmi3y/flask-jwt-consumer) [![Maintainability](https://api.codeclimate.com/v1/badges/2012c48af0e1d47d7f3a/maintainability)](https://codeclimate.com/github/dmi3y/flask-jwt-consumer/maintainability)

## Flask JWT consumer

> Flask extension for JWT token validation

Based on [pyJWT](https://github.com/jpadilla/pyjwt). Supports multi public key validation in form of simplified `authorized_keys` format, with only keys, and comments, no options. Good for key rotations or when you need multi issuer support.

### Rational
Inspired by [Flask JWT Simple](https://github.com/vimalloc/flask-jwt-simple), nice package I was enjoying until the need for multi key support. So that's where many backward compatible settings came from.

### Configuration

- `JWT_ALGORITHM` default `RS256`, algorithm used to decode JWT. As current iteration only asymmetric algorithms are considered. So anything symmetric will likely fail.
- `JWT_HEADER_NAME` default `Authorization`, header where JWT expected to be.
- `JWT_HEADER_TYPE` default `Bearer`, type of the token, part of the header's value.
- `JWT_IDENTITY` optional, if provided JWT will use it.
- `JWT_AUTHORIZED_KEYS` new line separated list of OpenSSH formatted keys.
