# I. The Web and Nginx for Linux SysAds (Part I)

**The Web and Nginx for Linux SysAds (Part I)**

Michael Filio

# II. Why this training and what?

## Why?
* Lots of new admins without a fundamental background in the internet and
webhosting technologies.
* Increasing market share of Nginx is making it more important to know.
From Jan to Oct 2015 14% - 16% or 128mil to 146mil (Netcraft)

## What?

**Part I**

* Basic Internet and networking architecture.
* Provide some insight into web application architecture for sysadmins with
  no developer experience.
* Cover the fundamental differences between Nginx and Apache.
* Provide an introduction to Nginx and provide resources for more information.
* Basic system tuning including kernel tunables and file systems.

**Part II**
* Labs with nginx configuration.

# III. Networking

* Without Networking there is no Internet or web sites.
* You should know some basic vocabulary about networking and how it functions.
Particularly the OSI and TCP/IP models.

Not going to go into too much depth on the models, but this diagram is great.

![OSI and TCP/IP Model](http://www.inetdaemon.com/img/network_models.png)

# IV. Protocols

* IP/ICMP - Networking (Layer 3)
* TCP/UDP - Transport (Layer 4)
* DNS/HTTP - Application (Layer 7)

If there are problems with any of these you don't get your webpage.

# V. DNS (Linux)
* /etc/nsswitch.conf - Name Service Switch
  * hosts: files dns
* /etc/hosts
* /etc/resolv.conf

(Process to be replaced by nifty graphics)

```
Server -> Name Server
  Cached - returns record
ROOT server returns TLD
Request the NS from TLD
Then finally request against the NS for domain returns record
```
There's a cost for DNS lookups, and also you always want to know you're
connecting to the right server.

# VI. TCP

As HTTP sits on top of TCP a brief mention here is needed.

TCP as a protocol uses connections that do error handling to make sure data
arrives correctly. As part of this process, it establishes a connection with
the '3 way handshake'

Opening:

![3 way handshake](http://aosabook.org/en/posa/chrome-images/three-way.png)

These connections are expensive and add a round trip time (RTT) to the total
time (a ping) for each connection so the recommendation is usually to
enable keep alives. Is this correct? Depends on your site. Can lead to slower
load times with keep alive on.

After the connection is open the HTTP traffic is sent.

```
Client -> HTTP Request -> Server
Client <- HTTP Response <- Server
```
Closing:

```
Server -> FIN -> Client
Server <- ACK <- Client

Server <- FIN <- Client
Server -> ACK -> Client
```

Common admin error using ss or netstat (This IP is DOS'ing me!):

So what's wrong with your netstat one liners?

```
ESTABLISHED
TIME_WAIT (Linux has a hard coded value for 60 seconds)
```

**TIME_WAIT** The OS keeps the connection locally to prevent reusing it and
getting errant packets from a previous TCP session.

# VII. HTTP

## HTTP protocols
* HTTP 1.0 May 1996
* HTTP 1.1 last update June 1999
  * One request per TCP connection
  * HTTP pipelining. Declared not practical. Returned requests in order and
  browsers have it off by default. Lots of problems with intermediate devices
  (home  routers, proxies, NAT).
  * Client browsers just use multiple connections instead (6)
     * Domain sharding (Using different subdomains so more connections made.
       Recommendation is not to use more than 2.)
     * Concatenation - Combine resources (CSS, JS, images) into a single larger
       resource.
        * Cons
          * poor cache utilization - one update means entire resource needs to
          be refreshed
          * delays - must download entire resource before any part of it can be
          used
     * Inlining - embed directly inside HTML
       * Cons
           * duplication - has to be inlined everywhere it is used

* HTTP 2 is here and coming soon as of 1.9.5 nginx supports it. Current mainline
is now 1.9.9 as of 12/09/2015.

# VIII. HTTP 2

* Based on SPDY developed by Google since 2009
* Multiple requests over single TCP connection
* Out of order completion
* Headers no longer plain text but in binary format
* Request Prioritization
  * Can weight content and assign dependencies.
* Server Push
  * Server can push resources before client requests it.
* Header Compression
  * HPACK - protocol for encoding the binary headers
  [Read more](https://http2.github.io/http2-spec/compression.html)
* Mandatory SSL
  * RFC does not mandate it, but chrome and firefox will only support http2
    with ssl
  * Google does give higher rankings to sites that are encrypted.
* Negotiation
  * ALPN (OpenSSL 1.0.2)
  * NPN (OpenSSL 1.0.1)

*It is not backwards compatible with HTTP 1.1*

What may be the next protocol?
  * [QUIC - Quick UDP Internet Connections](https://www.chromium.org/quic)

# IX. HTTP 2 as it is in nginx

* 1.9.5-9 is built against 1.0.1 OpenSSL.
* Only built for incoming connections not backend. Also only with ssl enabled.
* No server push yet.
* Likely have 15 - 20% gain over just https.
* Streaming doesn't work well over ssl and so no real performance gains
  if that's your model.
* Other implications:
  * RHEL7 is still on 1.0.1 for OpenSSL, curl is 7.29, support for http2
  not until 7.36.0, etc.

# X. Web Server processing

1. Accept the connection
2. Receive the HTTP request
3. Process the request
4. Access and map the resources
   * uri to filename translation
   * access permissions
5. Build the response
   * module processing - handlers
6. Send the response
7. Logging

# XI. Browser rendering

Critical Rendering Path

[Read more](http://calendar.perfplanet.com/2012/deciphering-the-critical-rendering-path/)

![Critical Rendering Path](http://www.igvita.com/posts/12/doc-render-js.png)


[Read even more](https://developers.google.com/web/fundamentals/performance/)

*CSS at the top. JavaScript at the bottom.*

# XII. The browser request

Tying it all together...

What happens when you make a browser request:

1. URL in browser
2. DNS
3. Establish TCP connection and get initial html
4. Make additional requests for items on page (6 on current versions of
   firefox and chrome)
5. Webserver processing
6. Browser rendering

# XIII. Sources

I stole all this information from the following:

* [HTTP The Definitive Guide](http://shop.oreilly.com/product/9781565925090.do)
* [HTTP Essentials](http://www.amazon.com/HTTP-Essentials-Protocols-Secure-Scaleable/dp/0471398233)
* [High Performance Websites](http://shop.oreilly.com/product/9780596529307.do)
* [Even Faster Websites](http://shop.oreilly.com/product/9780596522315.do)
* [High-Performance Browser Networking](https://www.igvita.com/)
* [What's new in HTTP/2?](https://www.nginx.com/resources/webinars/whats-new-in-http2/)
* [HTTP/2: Ask me anything](https://www.nginx.com/resources/webinars/http2-ask-me-anything/)
* [HTTP/2 is Here, Let's Optimize!](https://www.youtube.com/watch?v=ouIK1S0KdJE)
* [Deciphering the Critical Rendering Path](http://calendar.perfplanet.com/2012/deciphering-the-critical-rendering-path/)

Some additional resources:

* [The TCP/IP Guide](http://www.tcpipguide.com/)
* [InetDaemon.Com](http://www.inetdaemon.com/)
* [Google Developers](https://developers.google.com/web/fundamentals/performance/)
* [PageSpeed Insights](https://developers.google.com/speed/pagespeed/insights/)
* [GTmetrix](https://gtmetrix.com/)
* [WebPageTest](http://www.webpagetest.org/)
* [Can I Use](http://caniuse.com/)
* [High Performance Networking in Chrome](http://aosabook.org/en/posa/high-performance-networking-in-chrome.html)
* [Anatomy of an HTTP Transaction](http://blog.catchpoint.com/2010/09/17/anatomyhttp/)

# XIV. nginx

[History of nginx](http://www.aosabook.org/en/nginx.html):
* Public launch in 2004
* C10K

What is nginx?
* It's not just a web server (but we're focused only on the traditional
web parts.)
  * reverse proxy
  * cache server
  * load balancer
  * mail proxy
  * media streamer

Future nginx versions may have dynamic modules.

# XV. Releases

There are basically 5 types of nginx you might encounter:
* OS repository package
* nginx mainline
* nginx stable
* nginx legacy
* nginx r7 plus - their commercial enterprise version with support

nginx mainline is actively developed and nginx r7 plus is made from it, so
in theory you should likely be using the mainline. If you want http2, you **have
to use mainline.**

# XVI. nginx vs Apache prefork/worker/event

nginx uses a master process with workers. Each worker is single threaded and
uses an event loop to process requests. The default worker_connections it allows
is 1024. nginx is statically compiled and any functionality you want to use
must be compiled in.

# nginx configuration

# nginx worker and worker_connections

# nginx and php-fpm

# Plesk, nginx, and Apache

Plesk can use nginx (80/443) in front of Apache(7080/7081) since 11.x. It does
this by using two custom modules for apache:

* [mod_aclr2](https://github.com/defanator/mod_aclr2)
* [mod_rpaf](https://github.com/gnif/mod_rpaf)

mod_rpaf essentially adds a header to allow the IPs to be correctly
noted in the logs for the proxy connection between nginx and apache.

mod_aclr2 is what allows apache to respond to headers that nginx adds so that
web traffic will flow through the apache modules and process .htaccess files
and on static files has nginx serve the files instead of apache.

If nginx is on, and their site has problems the solution is **not** to disable
it. It is most likely mod_fcgid timeouts.

[Plesk doc](http://download1.parallels.com/Plesk/Doc/en-US/online/plesk-administrator-guide/index.htm?fileName=70837.htm)


# nginx ssl / http2

There's a lot to configure for SSL/TLS these days. The actual configuration
syntax in nginx is simple, but everything that you might want to do is now quite
extensive.

* **OSCP** - Online Certificate Status Protocol
  * Checking for certificate is revoked
* **HSTS** - HTTP Strict Transport Security
  * Prevent man in the middle attacks
* **HPKP** - HTTP Public Key Pinning
  * If your CA is compromised
* **CSP** - Content Security Policy
  * To prevent XSS type attacks
* **Set-Cookie** - An HTTP header
  * To secure cookies are only transferred over https

To get an A+ with SSLlabs you will need to have a 2048 bit diffie-helman params
or eliminate those ciphers, and likely the **HSTS** header as well.

The server config:

```
listen 443 ssl http2 default_server;
server_name  www.filio.us filio.us;
ssl_certificate /etc/pki/tls/certs/filio.us.crt;
ssl_certificate_key /etc/pki/tls/private/filio.us.key;

#oscp - online certificate status protocol
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/pki/tls/certs/startssl.ca.certs.pem;

#hsts - http strict transport security
# preload : https://hstspreload.appspot.com/
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; always";
# example preload
#add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; always; preload";

#hpkp - http public key pinning
set $hpkp1 'pin-sha256="qDo23MpsRAXCSsMMvQRZ5WSa2IlR7p7xUFaN4roiPhQ=";';
set $hpkp2 'pin-sha256="bUt20Xnw2ji4KxfgpzFl53EGeSIFX2cHXaEy45foM5A=";';
set $hpkp3 'pin-sha256="omFq/rCHiz9sUsCxK56w3RGMp15ApJ0lEi6z32xO/zU=";';
add_header Public-Key-Pins "$hpkp1 $hpkp2 $hpkp3 max-age=31536000; includeSubDomains";
```

I did a ssl_common.conf as well:

```
ssl_prefer_server_ciphers on;
ssl_protocols TLSv1 TLSv1.1 TLSv1.2;

#ssltool ciphers
ssl_ciphers EECDH+AESGCM:EECDH+AES256:EECDH+AES128:EECDH+3DES:EDH+AES:RSA+AESGCM:RSA+AES:RSA+3DES:!ECDSA:!NULL:!MD5:!DSS;

ssl_session_cache shared:SSL:20m;
ssl_session_timeout 60m;

#2048 bit diffie-helman for a+ on ssllabs
#openssl dhparam -out /etc/nginx/dhparam.pem 2048
ssl_dhparam /etc/nginx/dhparam.pem;

#for oscp stapling
resolver 72.3.128.241 72.3.128.240;
```

One liner to test oscp:
```
#test for oscp
echo QUIT | openssl s_client -connect filio.us:443 -status 2> /dev/null | grep -A 17 'OCSP response:' | grep -B 17 'Next Update'
```

One liner to get base64 hash from csr for HPKP (broken up on the pipes):
```
 openssl req -inform pem -pubkey -noout < filio.us.csr
   | openssl pkey -pubin -outform der
   | openssl dgst -sha256 -binary
   | base64
```

One example for a Content-Security-Policy header:

```
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; frame-src 'self'; connect-src 'self' https://apis.google.com; object-src 'none' ";
```

Finally, the the **Set-Cookie** header. This in general should be applied by the
developer in the application, but you can modify it on the web server level and
may now pop up in PCI scans. The two additional arguments that would need to
be appended to the existing header:

```
httponly; secure
```

Enough headers anyone?

# apache migration to nginx considerations

* Must decide on how to process php, usually fascgi to php-fpm
* Ownership of files, apache vs. nginx vs. php-fpm
* Does the site have .htaccess or use HTTP Auth
  * CMSs using .htaccess to deny access to certain directories
  * If php_flag or php_value, must transfer to php-fpm
* Does the site make extensive use of mod_rewrite rules?

# nginx and linux kernel tunables

# Additional support considerations
