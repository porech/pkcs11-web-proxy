# pkcs11-web-proxy

A very simple reverse proxy that performs all requests with TLS client authentication from a PCKS#11 device.

# WARNING
Please think at least twice before using it. Try to understand what it means: you are exposing a port (on your host only, by default)
which can be reached over HTTP and will perform requests to your target server, via HTTPS, authenticated with the certificate on YOUR PKCS#11 device.

The certificate on a smart card may be something that can legally prove your identity, and allow someone to do (bad?) things on your behalf.

Needless to say, this poses lots of security risks.

Those are some cases in which it MAY be a good idea to use it:
- You are developing a client that integrates with an API that requires client authentication, and your preferred tool to play with it doesn't support PKCS#11 devices (looking bat at you, Postman)
- You're in your super-secure network with only your devices attached to it, you want to access a service from multiple PCs, but you have only one smart card

In all the other cases, it's probably a bad idea to use it.

# Usage
Install golang and clone this repo. Build with `go build .` and run with `./pkcs11-web-proxy -help` to see the options:
```
  -destination-url string
    	URL to forward requests to.
  -listen-addr string
    	Address to listen on (default "127.0.0.1")
  -listen-port int
    	Port to listen on (default 8080)
  -log-requests
    	Log each request to stdout.
  -no-preserve-host
    	Do not preserve the host header in the request.
  -pin string
    	PIN to access the card. Cannot be used with -pin-file.
  -pin-file string
    	File containing the PIN to access the card (will be deleted after read!). Cannot be used with -pin.
  -pkcs11-path string
    	Path to the PKCS11 module. Use the card vendor-specific one, or run 'pkcs11-tool --help' and look for '--module' default value for a good one to use.
  -token-serial string
    	Serial number of the token. Run 'pkcs11-tool --list-token-slots' to find it.
```

# Example
```
./pkcs11-web-proxy -destination-url https://clientecho.alerinaldi.it -pin 12345 -pkcs11-path /lib/bit4id/libbit4xpki.so -token-serial 1234567898765432
```

# You should not use -pin
As you may guess, the PIN is sensitive information. If you pass it as a command line argument, it will be visible to anyone that can run `ps aux` on your machine, and in the shell history.
You should use the `-pin-file` option instead, which will read the PIN from a file and delete it after reading.

You might want to use a script like this:
```sh
#!/bin/bash
echo -n "Enter PIN: "
read -r -s pin_val
echo ""
echo -n $pin_val > /tmp/pin-val.txt
./pkcs11-web-proxy -destination-url https://clientecho.alerinaldi.it -pin-file /tmp/pin-val.txt -pkcs11-path /lib/bit4id/libbit4xpki.so -token-serial 1234567898765432
# If something went really wrong starting the proxy, delete the file anyway
if [ -f /tmp/pin-val.txt ]; then
rm /tmp/pin-val.txt
fi
```
