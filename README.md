# EVSpot
EasyVision CaptivePortal

# Needed library for compilation
- libevent
- libnet
- libpcap
- libconfig
- libtokyocabinet

# Configuration file
Default configuration file is stored in `/etc/evspot.conf`, for now, only 2 parameters are supported:
- url: UAM server to use, must start with `http(s)://`.
- interface: Local interface to listen to.

# Compilation
- Just run `make` for release version
- When compiled with `make debug`, a test version will be generated, that will use a pcap file under `/tmp/evspot.pcap` as input.

# Execute
`sudo ./evspot` is the way to execute the program, no argument supproted yet.

# Todo
- Stack Communication Layer: The way to pass packet between stakc layer (upper -> lower and lower -> upper)
- Application Stack Registration: Permit an application to register it's handler into a stack when packet is received.
- Multi-stack supprot: Support of RAW SOCKET, NFQUEUE and PCAP.
- TUN : Use TUN/TAP interface to route packet.
- ConnTrack: Connection tracking module.
- Host: Host module.
- DNS: DNS server/relay module.
- HTTP server: To Redirect client. 

# The MIT License
Copyright 2017.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
