This file ``forceIP.c`` is for an ``LD_PRELOAD`` shim for Linux to intercept networking API calls and bind sockets to a specified source address.

For an explanation of the function of the ``LD_PRELAOD`` environment variable in Linus see the man page for ``ld.so``. For example here:

https://www.man7.org/linux/man-pages/man8/ld.so.8.html

It is meant to be used when a VPN is operating but is not the defaut gateway. A scheme for this is described on the wiki page "[Running OpenVPN on Linux without VPN as Default Gateway](https://github.com/tool-maker/VPN_just_for_torrents/wiki/Running-OpenVPN-on-Linux-without-VPN-as-Default-Gateway)" found here:

https://github.com/tool-maker/VPN_just_for_torrents/wiki/Running-OpenVPN-on-Linux-without-VPN-as-Default-Gateway

Since the address to which we force a bind will not be the IP address of the default gateway interface, you will need to set up source address routing. You need two commands similar to this:

```
sudo ip -4 route add default via 10.4.0.1 dev tun0 table 1234
sudo ip -4 rule add from 10.4.36.17 table 1234
```

In that ``tun0`` was the name of the local interface for the VPN and ``10.4.0.1`` was the gateway IP address for the VPN. And ``10.4.36.17`` was the IP address of the local interface for the VPN, to which this shim can bind all sockets for a network program. The first line adds a non-default routing table numbered as ``1234``. The second line adds a routing policy rule that says that any packet coming from a socket bound to address ``10.4.36.17`` should use the routing table numbered ``1234`` rather than the normal default routing table.

To build:

```
# install gcc if not already installed
sudo apt-get update
sudo apt-get install gcc

# create target folder and upload source
mkdir ~/forceIP
pushd ~/forceIP
curl https://raw.githubusercontent.com/tool-maker/forceIP/main/forceIP.c > forceIP.c
ls -la

# compile it
gcc -nostartfiles -fpic -shared forceIP.c -o forceIP.so -ldl
ls -la

# leave target folder
popd
```

To have this shim preload before a network program starts, set the ``LD_PRELOAD`` environment variable before starting the program:

```
export LD_PRELOAD=~/forceIP/forceIP.so
```

Also before starting the network program, set other environment variables ("``export fIP_?=...``") as desired:

```
  fIP_TRACE        - trace all calls (set to anything)
  fIP_BINDADDR     - IPv4 address to force as source address for calls to "bind"
  fIP_BINDADDR6    - IPv6 address to force as source address for calls to "bind"
                     bind to localhost, 127.0.0.0, ::1 is left alone
  fIP_BINDLOCAL    - force bind source address for localhost too (set to anything)
  fIP_LISTENADDR   - IPv4 address to force as source address for calls to "listen"
  fIP_LISTENADDR6  - IPv6 address to force as source address for calls to "listen"
                     listen on localhost, 127.0.0.0, ::1 is left alone
  fIP_LISTENLOCAL  - force listen source address for localhost too (set to anything)
  fIP_CONNECTADDR  - IPv4 address to force as source address for calls to "connect", "sendto" and "sendmsg"
  fIP_CONNECTADDR6 - IPv6 address to force as source address for calls to "connect", "sendto" and "sendmsg"
                     connect to destination localhost, 127.0.0.0, ::1 is left alone
  fIP_DNSSKIP      - do not modify UDP packets with detination port 53 (DNS) (set to anything)
```
