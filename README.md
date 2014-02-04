Extends [twisted-socks](https://github.com/ln5/twisted-socks) with support for
* SOCKS 4
* SOCKS 5

Tested SOCKS 4 and SOCKS4a with
* `twistd -n socks`
* TOR
* public socks servers out in the wild

Tested SOCKS 5 with dante socks server on my VPS.

### Planned

+ Support for gssapi authentication method
+ Maybe UDP ASSOCIATED or TCP BIND commands
