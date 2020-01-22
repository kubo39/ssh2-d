# ssh2-d

D bindings to libssh2.

## Prerequirements

* D Compiler
* OpenSSL >= 1.1.0.

## Develop

- libssh2: 1.8.0
- OpenSSL: 1.1.1

### Ubuntu 18.04

```console
$ apt install libssh2-1-dev
```

## Tests

**NOTE**: Since DMD 2.090.0 default test mode has been changed. Do not run tests DMD >= 2.090.0 at least now.

```console
$ tests/run_integration_tests.sh
```
