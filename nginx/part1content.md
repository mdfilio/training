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

```
Client -> SYN (Synchronize) -> Server
Client <- SYN / ACK (Acknowledge) <- Server
Client -> ACK -> Server
```

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
Server -> FIN/ACK -> Client
Server <- ACK <- Client

Server <- FIN/ACK <- Client
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

# XII. Summary of web infrastructure

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



# XIV. nginx
