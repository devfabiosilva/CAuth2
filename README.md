# CAuth2
CAuth2 is a tiny C TOTP Auth2 authenticator

See [documentation](https://devfabiosilva.github.io/CAuth2/)

To compile C library (static and dynamic):

```sh
make
```

To build with test:

```sh
make test
```

To build documentation:

```sh
make doc
```

To clean documentation:

```sh
make doc_clean
```

To clean build:

```sh
make clean
```

### Note

By default it is compiled in _little_endian_. If you want to compile in _big_endian_ type:

```sh
make ENDIANESS=CAUTH_BIG_ENDIAN
```

## panelauth library for Python3

This tiny library has a _panelauth_ library for Python 3.

To compile just type:

```sh
make panelauth_build
```

To install:

```sh
make panelauth_install
```

### DEBUG MODE

If you want to debug type

_To compile just type:_

```sh
make panelauth_build DEBUG=P_DEBUG
```

_To install:_

```sh
make panelauth_install DEBUG=P_DEBUG
```
## License
MIT

## Donation

Donations are welcome :smile:

**Bitcoin**: `1EcvCevxkbDvYXLuo8UzyG8YxJk78Lwe3e`
