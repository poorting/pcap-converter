use anyhow::{Context, Result};
use clap::Parser;
use etherparse::*;
use pcap_parser::data::PacketData;
use pcap_parser::*;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;
use std::net::*;
use std::path::Path;

use arrow2::{
    array::{Array, Int64Array, UInt16Array, UInt32Array, UInt8Array, Utf8Array},
    chunk::Chunk,
    datatypes::{Field, Schema},
    io::parquet::write::{
        transverse, CompressionOptions, Encoding, FileWriter, RowGroupIterator, Version,
        WriteOptions,
    },
};

use arrow2::datatypes::DataType::{Timestamp, UInt16, UInt32, UInt8, Utf8};
use arrow2::datatypes::TimeUnit::Microsecond;
use etherparse::icmpv4::TYPE_DEST_UNREACH;

use domain::base::*;
use num_format::{Locale, ToFormattedString};

/// Parse a PCAP file and detect whether source IP addresses are spoofed.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// File path of the PCAP file
    #[arg(short, long)]
    file: String,
    /// File path of the parquet file
    #[arg(short, long)]
    out: String,
    #[arg(short, long)]
    /// Show counter while processing
    #[arg(short, long)]
    verbose: bool,
    /// Print out details while running
    #[arg(short, long)]
    printout: bool,
}

#[derive(Default, Debug, Clone)]
struct PacketDetail {
    frame_time: Option<i64>,
    frame_len: Option<u32>,
    eth_type: Option<u16>,
    ip_src: Option<String>,
    ip_dst: Option<String>,
    ip_proto: Option<u8>,
    ip_ttl: Option<u8>,
    ip_frag_offset: Option<u16>,
    icmp_type: Option<u8>,
    udp_length: Option<u16>,
    udp_srcport: Option<u16>,
    udp_dstport: Option<u16>,
    tcp_flags: Option<String>,
    tcp_srcport: Option<u16>,
    tcp_dstport: Option<u16>,
    //     Rest added to maintain compatibility with parquet files from tcpdump exports
    col_info: Option<String>,
    col_source: Option<String>,
    col_destination: Option<String>,
    col_protocol: Option<String>,
    dns_qry_name: Option<String>,
    dns_qry_type: Option<u16>,
    http_request_uri: Option<String>,
    http_host: Option<String>,
    http_request_method: Option<String>,
    http_user_agent: Option<String>,
    http_file_data: Option<String>,
    ntp_priv_reqcpde: Option<u8>,
}

#[derive(Default, Debug, Clone)]
struct PacketsDetail {
    frame_time: Vec<Option<i64>>,
    frame_len: Vec<Option<u32>>,
    eth_type: Vec<Option<u16>>,
    ip_src: Vec<Option<String>>,
    ip_dst: Vec<Option<String>>,
    ip_proto: Vec<Option<u8>>,
    ip_ttl: Vec<Option<u8>>,
    ip_frag_offset: Vec<Option<u16>>,
    icmp_type: Vec<Option<u8>>,
    udp_length: Vec<Option<u16>>,
    udp_srcport: Vec<Option<u16>>,
    udp_dstport: Vec<Option<u16>>,
    tcp_flags: Vec<Option<String>>,
    tcp_srcport: Vec<Option<u16>>,
    tcp_dstport: Vec<Option<u16>>,
    //     Rest added to maintain compatibility with parquet files from tcpdump exports
    col_info: Vec<Option<String>>,
    col_source: Vec<Option<String>>,
    col_destination: Vec<Option<String>>,
    col_protocol: Vec<Option<String>>,
    dns_qry_name: Vec<Option<String>>,
    dns_qry_type: Vec<Option<u16>>,
    http_request_uri: Vec<Option<String>>,
    http_host: Vec<Option<String>>,
    http_request_method: Vec<Option<String>>,
    http_user_agent: Vec<Option<String>>,
    http_file_data: Vec<Option<String>>,
    ntp_priv_reqcpde: Vec<Option<u8>>,

    pcap_file: Vec<Option<String>>,
}

// Used in a hashmap to link these to an IP packed identifier
// for fragmented packets
#[derive(Default, Debug, Clone)]
struct FragmentCache {
    src: u16,
    dst: u16,
    dns_qry_name: String,
    dns_qry_type: u16,
}

impl FragmentCache {
    fn new() -> FragmentCache {
        FragmentCache {
            src: 0,
            dst: 0,
            dns_qry_name: "".to_string(),
            dns_qry_type: 0,
        }
    }
}

struct PcapDetails {
    pcap_file: String,
    // pq_filename: String,
    pq_filewriter: FileWriter<File>,
    options: WriteOptions,
    fields: Vec<Field>,
    printout: bool,
    verbose: bool,
    packet_detail: PacketDetail,
    pack_buf: PacketsDetail,
    frag_pack: HashMap<u16, FragmentCache>,
    pack_cnt: i64,
    errors: i64,
    cache_misses: i64,
}

fn create_fields() -> Vec<Field> {
    let mut fields: Vec<Field> = Vec::new();

    fields.push(Field::new(
        "frame_time",
        Timestamp(Microsecond, None).to_logical_type().clone(),
        true,
    ));
    fields.push(Field::new("frame_len", UInt32, true));
    fields.push(Field::new("eth_type", UInt16, true));
    fields.push(Field::new("ip_src", Utf8, true));
    fields.push(Field::new("ip_dst", Utf8, true));
    fields.push(Field::new("ip_proto", UInt8, true));
    fields.push(Field::new("ip_ttl", UInt8, true));
    fields.push(Field::new("ip_frag_offset", UInt16, true));
    fields.push(Field::new("icmp_type", UInt8, true));
    fields.push(Field::new("udp_length", UInt16, true));
    fields.push(Field::new("udp_srcport", UInt16, true));
    fields.push(Field::new("udp_dstport", UInt16, true));
    fields.push(Field::new("tcp_flags", Utf8, true));
    fields.push(Field::new("tcp_srcport", UInt16, true));
    fields.push(Field::new("tcp_dstport", UInt16, true));
    fields.push(Field::new("col_info", Utf8, true));
    fields.push(Field::new("col_source", Utf8, true));
    fields.push(Field::new("col_destination", Utf8, true));
    fields.push(Field::new("col_protocol", Utf8, true));
    fields.push(Field::new("dns_qry_name", Utf8, true));
    fields.push(Field::new("dns_qry_type", UInt16, true));
    fields.push(Field::new("http_request_uri", Utf8, true));
    fields.push(Field::new("http_host", Utf8, true));
    fields.push(Field::new("http_request_method", Utf8, true));
    fields.push(Field::new("http_user_agent", Utf8, true));
    fields.push(Field::new("http_file_data", Utf8, true));
    fields.push(Field::new("ntp_priv_reqcode", UInt8, true));
    fields.push(Field::new("pcap_file", Utf8, true));

    fields
}

impl PcapDetails {
    fn new(
        pcap_filename: &str,
        parquet_filename: &str,
        printout: bool,
        verbose: bool,
    ) -> Result<PcapDetails> {
        let pcap_file = Path::new(pcap_filename);
        let file_stem = pcap_file.file_name().unwrap();

        let options = WriteOptions {
            write_statistics: true,
            compression: CompressionOptions::Snappy,
            // compression: CompressionOptions::Uncompressed,
            version: Version::V2,
            data_pagesize_limit: Some(128*1024*1024),
        };

        let fields = create_fields();

        let schema = Schema::from(fields.clone());

        let file = File::create(parquet_filename)?;
        let writer = FileWriter::try_new(file, schema, options)?;

        let pcapdetails = PcapDetails {
            pcap_file: file_stem.to_str().unwrap().to_string(),
            pq_filewriter: writer,
            options: options,
            fields: fields,
            printout: printout,
            verbose: verbose,
            packet_detail: Default::default(),
            pack_buf: Default::default(),
            frag_pack: Default::default(),
            pack_cnt: 0,
            errors: 0,
            cache_misses: 0,
        };

        Ok(pcapdetails)
    }

    fn push(&mut self) {
        self.pack_cnt += 1;

        if self.printout {
            eprintln!("Push packet {:#?}", self.packet_detail)
        }

        self.pack_buf.frame_time.push(self.packet_detail.frame_time);
        self.pack_buf.frame_len.push(self.packet_detail.frame_len);
        self.pack_buf.eth_type.push(self.packet_detail.eth_type);
        self.pack_buf.ip_src.push(self.packet_detail.ip_src.clone());
        self.pack_buf.ip_dst.push(self.packet_detail.ip_dst.clone());
        self.pack_buf.ip_proto.push(self.packet_detail.ip_proto);
        self.pack_buf.ip_ttl.push(self.packet_detail.ip_ttl);
        self.pack_buf
            .ip_frag_offset
            .push(self.packet_detail.ip_frag_offset);
        self.pack_buf.icmp_type.push(self.packet_detail.icmp_type);
        self.pack_buf.udp_length.push(self.packet_detail.udp_length);
        self.pack_buf
            .udp_srcport
            .push(self.packet_detail.udp_srcport);
        self.pack_buf
            .udp_dstport
            .push(self.packet_detail.udp_dstport);
        self.pack_buf
            .tcp_flags
            .push(self.packet_detail.tcp_flags.clone());
        self.pack_buf
            .tcp_srcport
            .push(self.packet_detail.tcp_srcport.clone());
        self.pack_buf
            .tcp_dstport
            .push(self.packet_detail.tcp_dstport.clone());
        self.pack_buf
            .col_info
            .push(self.packet_detail.col_info.clone());
        self.pack_buf
            .col_source
            .push(self.packet_detail.col_source.clone());
        self.pack_buf
            .col_destination
            .push(self.packet_detail.col_destination.clone());
        self.pack_buf
            .col_protocol
            .push(self.packet_detail.col_protocol.clone());
        self.pack_buf
            .dns_qry_name
            .push(self.packet_detail.dns_qry_name.clone());
        self.pack_buf
            .dns_qry_type
            .push(self.packet_detail.dns_qry_type);
        self.pack_buf
            .http_request_uri
            .push(self.packet_detail.http_request_uri.clone());
        self.pack_buf
            .http_host
            .push(self.packet_detail.http_host.clone());
        self.pack_buf
            .http_request_method
            .push(self.packet_detail.http_request_method.clone());
        self.pack_buf
            .http_user_agent
            .push(self.packet_detail.http_user_agent.clone());
        self.pack_buf
            .http_file_data
            .push(self.packet_detail.http_file_data.clone());
        self.pack_buf
            .ntp_priv_reqcpde
            .push(self.packet_detail.ntp_priv_reqcpde);

        self.pack_buf.pcap_file.push(Some(self.pcap_file.clone()));

        self.packet_detail = Default::default();

        if self.pack_buf.frame_time.len() >= 50_000 {
            self.flush_out();
            self.pack_buf = Default::default();
        }
    }

    fn close_parquet(&mut self) -> Result<()> {
        // Write out any remaining data
        self.flush_out();
        let _size = self.pq_filewriter.end(None)?;
        Ok(())
    }

    fn write_chunk(&mut self, chunk: Chunk<Box<dyn Array>>) -> arrow2::error::Result<()> {
        let iter = vec![Ok(chunk)];

        let schema = Schema::from(self.fields.clone());

        let encodings = schema
            .fields
            .iter()
            .map(|f| transverse(&f.data_type, |_| Encoding::Plain))
            .collect();

        let row_groups =
            RowGroupIterator::try_new(iter.into_iter(), &schema, self.options, encodings)?;

        for group in row_groups {
            self.pq_filewriter.write(group?)?;
        }

        Ok(())
    }

    fn flush_out(&mut self) {
        if self.verbose {
            eprint!(
                "\rPackets processed: {0} (Errors: {1}, Fragmentation misses: {2})",
                self.pack_cnt.to_formatted_string(&Locale::en),
                self.errors.to_formatted_string(&Locale::en),
                self.cache_misses.to_formatted_string(&Locale::en),
            );
        }

        let frame_time = Int64Array::from(&self.pack_buf.frame_time);
        let frame_len = UInt32Array::from(&self.pack_buf.frame_len);
        let eth_type = UInt16Array::from(&self.pack_buf.eth_type);
        let ip_src = Utf8Array::<i32>::from(&self.pack_buf.ip_src);
        let ip_dst = Utf8Array::<i32>::from(&self.pack_buf.ip_dst);
        let ip_proto = UInt8Array::from(&self.pack_buf.ip_proto);
        let ip_ttl = UInt8Array::from(&self.pack_buf.ip_ttl);
        let ip_frag_offset = UInt16Array::from(&self.pack_buf.ip_frag_offset);
        let icmp_type = UInt8Array::from(&self.pack_buf.icmp_type);
        let udp_length = UInt16Array::from(&self.pack_buf.udp_length);
        let udp_srcport = UInt16Array::from(&self.pack_buf.udp_srcport);
        let udp_dstport = UInt16Array::from(&self.pack_buf.udp_dstport);
        let tcp_flags = Utf8Array::<i32>::from(&self.pack_buf.tcp_flags);
        let tcp_srcport = UInt16Array::from(&self.pack_buf.tcp_srcport);
        let tcp_dstport = UInt16Array::from(&self.pack_buf.tcp_dstport);
        let col_info = Utf8Array::<i32>::from(&self.pack_buf.col_info);
        let col_source = Utf8Array::<i32>::from(&self.pack_buf.col_source);
        let col_destination = Utf8Array::<i32>::from(&self.pack_buf.col_destination);
        let col_protocol = Utf8Array::<i32>::from(&self.pack_buf.col_protocol);
        let dns_qry_name = Utf8Array::<i32>::from(&self.pack_buf.dns_qry_name);
        let dns_qry_type = UInt16Array::from(&self.pack_buf.dns_qry_type);
        let http_request_uri = Utf8Array::<i32>::from(&self.pack_buf.http_request_uri);
        let http_host = Utf8Array::<i32>::from(&self.pack_buf.http_host);
        let http_request_method = Utf8Array::<i32>::from(&self.pack_buf.http_request_method);
        let http_user_agent = Utf8Array::<i32>::from(&self.pack_buf.http_user_agent);
        let http_file_data = Utf8Array::<i32>::from(&self.pack_buf.http_file_data);
        let ntp_priv_reqcode = UInt8Array::from(&self.pack_buf.ntp_priv_reqcpde);

        let pcap_file = Utf8Array::<i32>::from(&self.pack_buf.pcap_file);

        let chunk = Chunk::new(vec![
            frame_time.boxed(),
            frame_len.boxed(),
            eth_type.boxed(),
            ip_src.boxed(),
            ip_dst.boxed(),
            ip_proto.boxed(),
            ip_ttl.boxed(),
            ip_frag_offset.boxed(),
            icmp_type.boxed(),
            udp_length.boxed(),
            udp_srcport.boxed(),
            udp_dstport.boxed(),
            tcp_flags.boxed(),
            tcp_srcport.boxed(),
            tcp_dstport.boxed(),
            col_info.boxed(),
            col_source.boxed(),
            col_destination.boxed(),
            col_protocol.boxed(),
            dns_qry_name.boxed(),
            dns_qry_type.boxed(),
            http_request_uri.boxed(),
            http_host.boxed(),
            http_request_method.boxed(),
            http_user_agent.boxed(),
            http_file_data.boxed(),
            ntp_priv_reqcode.boxed(),
            pcap_file.boxed(),
        ]);

        // eprint!("{:?}", schema);
        match self.write_chunk(chunk) {
            Err(e) => eprintln!("{}", e),
            Ok(_) => (),
        }
    }

    fn analyze_packet_headers(&mut self, pkt_headers: PacketHeaders) {
        let mut ip_id: u16 = 0;
        // eprintln!("{:#?}", pkt_headers);
        let EtherType(et) = pkt_headers.link.unwrap().ether_type;
        self.packet_detail.eth_type = Some(et);
        match pkt_headers.net {
            // Ipv4(Ipv4Header, Ipv4Extensions),
            Some(NetHeaders::Ipv4(ip, _)) => {
                // May be replaced by transport or application protocol later on
                self.packet_detail.col_protocol = Some("IPv4".to_string());
                // self.packet_detail.frame_len = Some(ip.total_len as u32);
                ip_id = ip.identification;

                self.packet_detail.ip_src = Some(Ipv4Addr::from(ip.source).to_string());
                self.packet_detail.ip_dst = Some(Ipv4Addr::from(ip.destination).to_string());
                self.packet_detail.col_source = Some(Ipv4Addr::from(ip.source).to_string());
                self.packet_detail.col_destination =
                    Some(Ipv4Addr::from(ip.destination).to_string());
                self.packet_detail.ip_ttl = Some(ip.time_to_live);
                self.packet_detail.ip_proto = Some(u8::from(ip.protocol));

                let frag_offset = u16::from(ip.fragment_offset);
                self.packet_detail.ip_frag_offset = Some(frag_offset);

                if u16::from(ip.fragment_offset) > 0 {
                    match self.frag_pack.get(&ip_id) {
                        Some(cache) => {
                            self.packet_detail.udp_srcport = Some(cache.src);
                            self.packet_detail.udp_dstport = Some(cache.dst);
                            self.packet_detail.udp_length = Some(ip.total_len);
                            self.packet_detail.dns_qry_type = Some(cache.dns_qry_type);
                            self.packet_detail.dns_qry_name = Some(cache.dns_qry_name.clone());
                        }
                        None => {
                            // cache miss
                            // eprintln!("cache miss");
                            self.cache_misses += 1;
                        }
                    }
                }
            }
            Some(NetHeaders::Ipv6(ip, _)) => {
                // May be replaced by transport or application protocol later on
                self.packet_detail.col_protocol = Some("IPv6".to_string());
                // self.packet_detail.frame_len = Some(ip.payload_length as u32);
                // eprintln!("{:#?}",ip);
                self.packet_detail.ip_src = Some(Ipv6Addr::from(ip.source).to_string());
                self.packet_detail.ip_dst = Some(Ipv6Addr::from(ip.destination).to_string());
                self.packet_detail.col_source = Some(Ipv6Addr::from(ip.source).to_string());
                self.packet_detail.col_destination =
                    Some(Ipv6Addr::from(ip.destination).to_string());
                self.packet_detail.ip_ttl = Some(ip.hop_limit);
                self.packet_detail.ip_proto = Some(u8::from(ip.next_header));
            }
            _ => (),
        }

        match pkt_headers.transport {
            Some(TransportHeader::Udp(udp)) => {
                // if self.printout {eprintln!("UDP: {:?}",udp)};

                let ports: FragmentCache = FragmentCache {
                    src: udp.source_port,
                    dst: udp.destination_port,
                    dns_qry_type: 0,
                    dns_qry_name: "".to_string(),
                };
                self.frag_pack.entry(ip_id).or_insert(ports);

                // May be replaced by transport protocol later on
                self.packet_detail.col_protocol = Some("UDP".to_string());

                self.packet_detail.udp_srcport = Some(udp.source_port);
                self.packet_detail.udp_dstport = Some(udp.destination_port);
                self.packet_detail.udp_length = Some(udp.length);

                if udp.source_port == 53 || udp.destination_port == 53 {
                    self.packet_detail.col_protocol = Some("DNS".to_string());
                    // match Message::from_slice(&pkt_headers.payload.slice()) {
                    match Message::from_octets(&pkt_headers.payload.slice()) {
                        Ok(dns) => {
                            // println!("{:#?}", dns.first_question().unwrap());
                            match dns.first_question() {
                                Some(question) => {
                                    // eprintln!("{:?}", question.qname().is_root());
                                    // eprintln!("{:?}", question.qtype().to_int());
                                    let name = if question.qname().is_root() {
                                        "<Root>".to_string()
                                    } else {
                                        question.qname().to_string()
                                    };
                                    self.packet_detail.dns_qry_name = Some(name.clone());
                                    self.packet_detail.dns_qry_type =
                                        Some(question.qtype().to_int());

                                    let fc =
                                        self.frag_pack.entry(ip_id).or_insert(FragmentCache::new());
                                    (*fc).dns_qry_name = name;
                                    (*fc).dns_qry_type = question.qtype().to_int();
                                }
                                _ => {
                                    self.errors += 1;
                                }
                            }
                        }
                        Err(_e) => {
                            if self.printout {
                                eprintln!("{}", _e);
                            }
                            self.errors += 1;
                        }
                    }
                }
            }

            Some(TransportHeader::Tcp(tcp)) => {
                if self.printout {
                    eprintln!("TCP: {:#?}", tcp)
                };
                // May be replaced by transport protocol later on
                self.packet_detail.col_protocol = Some("TCP".to_string());

                self.packet_detail.tcp_srcport = Some(tcp.source_port);
                self.packet_detail.tcp_dstport = Some(tcp.destination_port);
                let mut flags = String::from("........");
                if tcp.fin {
                    flags.replace_range(7..8, "F")
                };
                if tcp.syn {
                    flags.replace_range(6..7, "S")
                };
                if tcp.rst {
                    flags.replace_range(5..6, "R")
                };
                if tcp.psh {
                    flags.replace_range(4..5, "P")
                };
                if tcp.ack {
                    flags.replace_range(3..4, "A")
                };
                if tcp.urg {
                    flags.replace_range(1..3, "U")
                };
                if tcp.ece {
                    flags.replace_range(1..2, "E")
                };
                if tcp.cwr {
                    flags.replace_range(0..1, "C")
                };
                self.packet_detail.tcp_flags = Some(flags);
            }
            Some(TransportHeader::Icmpv4(icmp)) => {
                if self.printout {
                    eprintln!("ICMPv4: {:?}", icmp)
                };
                // May be replaced by transport or application protocol later on
                self.packet_detail.col_protocol = Some("ICMP".to_string());

                let bytes = icmp.to_bytes();
                // println!("{:?}", bytes);
                self.packet_detail.icmp_type = Some(bytes[0]);
                if bytes[0] == TYPE_DEST_UNREACH {
                    // Payload contains header of the original packet
                    // eprintln!("{:?}", pkt_headers.payload);
                    match PacketHeaders::from_ip_slice(pkt_headers.payload.slice()) {
                        Ok(icmp_ph) => {
                            // eprintln!("{:#?}", icmp_ph);
                            match icmp_ph.transport {
                                Some(TransportHeader::Udp(udp)) => {
                                    // eprintln!("UDP: {:?}", udp);
                                    self.packet_detail.udp_srcport = Some(udp.source_port);
                                    self.packet_detail.udp_dstport = Some(udp.destination_port);
                                }
                                Some(TransportHeader::Tcp(tcp)) => {
                                    // eprintln!("TCP: {:#?}", tcp);
                                    self.packet_detail.tcp_srcport = Some(tcp.source_port);
                                    self.packet_detail.tcp_dstport = Some(tcp.destination_port);
                                    let mut flags = String::from("........");
                                    if tcp.fin {
                                        flags.replace_range(7..8, "F")
                                    };
                                    if tcp.syn {
                                        flags.replace_range(6..7, "S")
                                    };
                                    if tcp.rst {
                                        flags.replace_range(5..6, "R")
                                    };
                                    if tcp.psh {
                                        flags.replace_range(4..5, "P")
                                    };
                                    if tcp.ack {
                                        flags.replace_range(3..4, "A")
                                    };
                                    if tcp.urg {
                                        flags.replace_range(1..3, "U")
                                    };
                                    if tcp.ece {
                                        flags.replace_range(1..2, "E")
                                    };
                                    if tcp.cwr {
                                        flags.replace_range(0..1, "C")
                                    };
                                    self.packet_detail.tcp_flags = Some(flags);
                                }
                                _ => (),
                            }
                        }
                        Err(_) => (),
                    }
                }
            }
            Some(TransportHeader::Icmpv6(icmp)) => {
                if self.printout {
                    eprintln!("ICMPv6: {:#?}", icmp)
                };
                // self.packet_detail.icmp_type = Some(u8::from(icmp.icmp_type));
            }
            _ => (),
        }
    }

    fn analyze_packet(&mut self, pkt_data: PacketData) -> Result<()> {
        match pkt_data {
            PacketData::L2(eth_data) => {
                self.analyze_packet_headers(PacketHeaders::from_ethernet_slice(eth_data)?)
            }
            PacketData::L3(_, ip_data) => {
                self.analyze_packet_headers(PacketHeaders::from_ip_slice(ip_data)?)
            }
            _ => todo!(),
        };

        self.push();

        Ok(())
    }
}

// ****************************************************************************************************** //
// ****************************************************************************************************** //
// ****************************************************************************************************** //

fn main() -> Result<()> {
    let args = Args::parse();

    let file = File::open(&args.file)?;
    let mut reader = create_reader(65536, file)?;
    let mut consecutive_errors = 0;

    let mut num_blocks = 0;

    let mut linktype = Linktype::ETHERNET; // Legacy PCAP files
    let mut if_linktypes = Vec::new(); // PCAP-NG files
    let mut if_tsresol: u8 = 6;

    let mut pcapdetails: PcapDetails =
        PcapDetails::new(&args.file, &args.out, args.printout, args.verbose)?;

    loop {
        if args.printout {
            eprintln!(
                "********************* {} ****************************",
                num_blocks
            )
        }
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let tsusec: i64 =
                            i64::from(b.ts_sec) * i64::pow(10, 6) + i64::from(b.ts_usec);
                        // let ndt = NaiveDateTime::from_timestamp_micros(tsusec);
                        pcapdetails.packet_detail.frame_time = Some(tsusec);
                        pcapdetails.packet_detail.frame_len = Some(b.origlen);
                        // if args.printout {
                        //     eprintln!("L: Analyze packet data: linktype: {}, len: {}",linktype, b.origlen);
                        //     if let Some(ndt) = ndt { println!("{}", ndt);}
                        //     eprintln!("{:?}", b);
                        //     eprintln!("---------------------------------------------")
                        // }
                        let pkt_data =
                            pcap_parser::data::get_packetdata(b.data, linktype, b.caplen as usize)
                                .context("Legacy PCAP Error get_packetdata")?;
                        pcapdetails.analyze_packet(pkt_data)?;
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        if_linktypes = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                        if_tsresol = idb.if_tsresol;
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        // let linktype = if_linktypes[epb.if_id as usize];

                        let ts_pkt: i64 =
                            i64::from(epb.ts_high) * i64::pow(2, 32) + i64::from(epb.ts_high);
                        let ts_res: i64 =
                            i64::from(ts_pkt) * i64::pow(10, 9 - u32::from(if_tsresol));
                        // let ndt = NaiveDateTime::from_timestamp_nanos(ts_res);
                        // convert to microseconds
                        pcapdetails.packet_detail.frame_time = Some(ts_res / 1000);
                        pcapdetails.packet_detail.frame_len = Some(epb.caplen);
                        // if args.printout {
                        //     eprintln!("NG-EP: Analyze packet data: linktype: {}, len: {}",linktype, epb.caplen);
                        //     if let Some(ndt) = ndt { println!("timestamp: {}", ndt);}
                        // }
                        let pkt_data = pcap_parser::data::get_packetdata(
                            epb.data,
                            linktype,
                            epb.caplen as usize,
                        )
                        .context("PCAP-NG EnhancedPacket Error get_packetdata")?;
                        pcapdetails.analyze_packet(pkt_data)?;
                        // println!("Analyze packet data: data: {:#?}",pkt_data);
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        if args.printout {
                            println!("NG-SP: Analyze packet data: linktype: {}", linktype);
                        }
                        let pkt_data = pcap_parser::data::get_packetdata(spb.data, linktype, blen)
                            .context("PCAP-NG SimplePacket Error get_packetdata")?;
                        pcapdetails.analyze_packet(pkt_data)?;
                        // println!("Analyze packet data: data: {:#?}",pkt_data);
                    }
                    PcapBlockOwned::NG(block) => {
                        if args.printout {
                            eprintln!("unsupported block: {:#?}", block);
                        }
                    }
                }

                reader.consume(offset);
                consecutive_errors = 0;
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                // If the last packet is not complete, the reader might get stuck in a loop.
                // In that case, after too many consecutive errors we stop the execution.
                consecutive_errors += 1;
                if consecutive_errors > 1000 {
                    break;
                }
                reader.refill().unwrap();
            }
            Err(e) => panic!("Error reading file: {:?}", e),
        }

        if args.printout && num_blocks > 5 {
            break;
        }

        // if num_blocks > 100 {
        //     break;
        // }
    }

    pcapdetails.close_parquet()?;
    // let output_filename = Path::new(&args.file)
    //     .file_stem()
    //     .context("Invalid file name")?
    //     .to_str()
    //     .context("Invalid file name")?;
    // analysis.write_to_file(output_filename)?;

    // eprintln!("num_blocks: {}", num_blocks);
    eprintln!();

    Ok(())
}
