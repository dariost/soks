# Soks
Soks is minimalistic SOCKS5 proxy over a network interface (like a VPN or a second physical network device).
A possible use case is to use it in conjunction with PAC (Proxy Auto-Config) to make browsers and other applications visit a certain set of sites using a differente network device.

Soks doesn't implement the whole SOCKS5 protocol, it only supports the `NO AUTHENTICATION REQUIRED` authentication method and `TCP CONNECT` request type.
This is enough to make it work with browsers like Mozilla Firefox or other applications like ssh (when proxied with netcat).

```
Usage: ./soks -i <interface>

    Soks is a minimalistic SOCKS5 proxy over a network interface (like a VPN or
    a second physical network device)

    -i <interface>    set the network interface name to redirect the traffic to
    -l <address>      set the address to listen to (default 127.0.0.1)
    -p <port>         set the port to listen to (default 1080)
    -n <niceness>     increase niceness for the children processes (default 10)
    -t <timeout>      set the timeout (in seconds) for connections (default 60)
    -v                be verbose (default false)
    -h, --help        print this help

Usage example: ./soks -i tun0 -l 127.0.0.1 -p 1080

Soks was written by Dario Ostuni <dario.ostuni@gmail.com>
The code is licensed under the MPL2 licence <http://mozilla.org/MPL/2.0/>
The project repository can be found at https://github.com/dariost/soks
```
