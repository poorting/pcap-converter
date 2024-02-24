# pcap-converter

Converts pcap(ng) files to parquet, similar to [pcap2parquet](https://github.com/poorting/pcap2parquet) but written directly in Rust rather than using tshark. This direct approach is about 5 to 10 times faster than pcap2parquet. Downside is less flexibility, but since the output is intended for DDoS analysis the fields needed are fairly static anyway.

My first project in Rust, so expect rusty code.
