# pkcs11-web-proxy

A very simple reverse proxy that listens for plain HTTP requests and sends them to an upstream server with TLS client authentication from a PCKS#11 device (like a smart card).

# WARNING

Please think at least twice before using it. Try to understand what it means: you are exposing a port (on your host only, by default)
which can be reached over HTTP and will perform requests to your target server, via HTTPS, authenticated with the certificate on YOUR PKCS#11 device.

The certificate on a smart card may be something that can legally prove your identity, and allow someone to do (bad?) things on your behalf.

Needless to say, this poses lots of security risks.

Those are some cases in which it MAY be a good idea to use it:

- You are developing a client that integrates with an API that requires client authentication, and your preferred tool to play with it doesn't support PKCS#11 devices (looking bad at you, [Postman](https://github.com/postmanlabs/postman-app-support/issues/3789))
- You're in your super-secure network with only your devices attached to it, you want to access a service from multiple PCs, but you have only one smart card

In all the other cases, it's probably a bad idea to use it.

# Usage

First of all, you should probably install OpenSC. It's not a dependency, but it brings the `pkcs11-tool` utility to get the token serial, and also a good PKCS#11 module if you don't have one from your device vendor.

Install golang and clone this repo. Build with `go build .` and run with `./pkcs11-web-proxy -help` to see the options:

```
  -listen-addr string
    	Address to listen on (default "127.0.0.1")

  -listen-port int
    	Port to listen on (default 8080)

  -destination-url string
    	URL to forward requests to.

  -no-preserve-host
    	Do not preserve the host header in the request.

  -log-requests
    	Log each request to stdout.

  -pkcs11-path string
    	Path to the PKCS11 module. Use the card vendor-specific one, or run 'pkcs11-tool --help' and look for '--module' default value for a good one to use.

  -token-serial string
    	Serial number of the token. Run 'pkcs11-tool --list-token-slots' to find it.

  -pin string
    	PIN to access the card. Cannot be used with --pin-file.

  -pin-file string
    	File containing the PIN to access the card (will be deleted after read!). Cannot be used with --pin.

  -certificate-index int
    	Index of the certificate to use. Run './pkcs11-web-proxy -token-serial ... [-pin/-pin-file] ... list-certificates' to find the index. By default, the first found certificate (index 0) will be used.

  -listen-tls
        Listen on TLS instead of plain HTTP (useful if your upstream sets 'secure' cookies)

  -listen-tls-cert
        Path to the certificate or chain file for the TLS listener (required if --listen-tls is set)

  -listen-tls-key
        Path to the private key file for the TLS listener (required if --listen-tls is set)
```

If you have multiple certificates on the same card, you can choose the one to use with its index. To list all of the available certificates you can run:

```
./pkcs11-web-proxy -token-serial ... [-pin/-pin-file] ... list-certificates
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

# TLS listener

It seems counterintuitive to run such a tool to listen over TLS, but sometimes an upstream server may set cookies with the "secure" flag, which will be ignored by the browser if the connection is not over HTTPS.
This may lead to issues with authentication on such services.

By using the TLS listener, you may avoid this issue: the connection to the reverse proxy will be over HTTPS, but it won't require a client certificate, that will be injected by the proxy itself when connecting to the upstream server.

You can generate a self-signed certificate and key with openssl:

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650 -nodes
```

And then run the proxy with:

```
./pkcs11-web-proxy -destination-url https://clientecho.alerinaldi.it -pin 12345 -pkcs11-path /lib/bit4id/libbit4xpki.so -token-serial 1234567898765432 -listen-tls -listen-tls-cert cert.pem -listen-tls-key key.pem
```

You'll need to trust your certificate on your browser or application to avoid security warnings.
