# evspot
EasyVision CaptivePortal

# Needed library for compilation
- libevent
- libnet
- libpcap
- libconfig
- libtokyocabinet

# Configuration file
Defautl configuration file is stored in `/etc/evspot.conf`, for now, only 2 parameters are supported:
- url: UAM server to use, must start with `http(s)://`.
- interface: Local interface to listen to.

# Compilation
- Just run `make` for release version
- When compiled with `make debug`, a test version is generated witch use a pcap file under `/tmp/evspot.pcap` as input.

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
