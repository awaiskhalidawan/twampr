# TWAMP
TWAMP (Two Way Active Measurement Protocol) is an open protocol defined in RFC-5357. It is used to measure the network performance between two network devices.

TWAMP protocol can measure multiple network parameters such: 
- round trip time (rtt)
- uplink time
- downlink time
- jitter
- (An many other network parameters according to the user requirement). 

Current repository contains the implementation of TWAMP protocol in Rust programming language.

Currently the TWAMP client is available. TWAMP server implementation in Rust will be available soon.

The current implementation of TWAMP client is able to connect with a TWAMP server and start a TWAMP test session.

The TWAMP client is thoroughly tested with an already existing TWAMP server written in C++. The current Rust implementation of TWAMP client is compliant with RFC-5357 (https://datatracker.ietf.org/doc/html/rfc5357).

# Build
Below are the steps to to build the software.

1. `git clone git@github.com:awaiskhalidawan/twampr.git`
2. `cd twampr`
3. `cargo build`
(The binary will be generated in `.\twampr\target\debug` folder).

# Run
Below are the steps to run the TWAMP client.
.\twampr.exe <mode> <twamp_server_ip> <twamp_server_port> <local_ip> <twamp_test_packet_size> <number_of_twamp_test_packets> <interpacket_interval_ms>

Example: .\twampr -c 127.0.0.1 50000 127.0.0.1 300 10 100

Example .\twampr -h (for help)

# Support
For queries, support or demo: please reach out at awais.khalid.awan@gmail.com


