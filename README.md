# evspot
EasyVision CaptivePortal

# Needed library for compilation
- livevent
- libnet
- libpcap
- libconfig

# Configuration file
Defautl configuration file is stored in `/etc/evspot.conf`, for now, only 2 parameters are supported:
- url: UAM server to use, must start with `http(s)://`.
- interface: Local interface to listen to.

# Compilation
- just run `make` for release version
- When compiled with `make debug`, a test version is generated witch use a pcap file under `/tmp/evspot.pcap` as input.

# Execute
`sudo evspot` is the way to execute the program, no argument supproted yet.

# Todo
