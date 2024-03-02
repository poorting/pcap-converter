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

use packetstats::*;
use statswriter::*;

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

pub mod packetstats;
pub mod statswriter;

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


    // fn write_chunk(&mut self, chunk: Chunk<Box<dyn Array>>) -> arrow2::error::Result<()> {
    //     let iter = vec![Ok(chunk)];

    //     let schema = Schema::from(self.fields.clone());

    //     let encodings = schema
    //         .fields
    //         .iter()
    //         .map(|f| transverse(&f.data_type, |_| Encoding::Plain))
    //         .collect();

    //     let row_groups =
    //         RowGroupIterator::try_new(iter.into_iter(), &schema, self.options, encodings)?;

    //     for group in row_groups {
    //         self.pq_filewriter.write(group?)?;
    //     }

    //     Ok(())
    // }

    // fn flush_out(&mut self) {
    //     if self.verbose {
    //         eprint!(
    //             "\rPackets processed: {0} (Errors: {1}, Fragmentation misses: {2})",
    //             self.pack_cnt.to_formatted_string(&Locale::en),
    //             self.errors.to_formatted_string(&Locale::en),
    //             self.cache_misses.to_formatted_string(&Locale::en),
    //         );
    //     }

    //     let frame_time = Int64Array::from(&self.pack_buf.frame_time);
    //     let frame_len = UInt32Array::from(&self.pack_buf.frame_len);
    //     let eth_type = UInt16Array::from(&self.pack_buf.eth_type);
    //     let ip_src = Utf8Array::<i32>::from(&self.pack_buf.ip_src);
    //     let ip_dst = Utf8Array::<i32>::from(&self.pack_buf.ip_dst);
    //     let ip_proto = UInt8Array::from(&self.pack_buf.ip_proto);
    //     let ip_ttl = UInt8Array::from(&self.pack_buf.ip_ttl);
    //     let ip_frag_offset = UInt16Array::from(&self.pack_buf.ip_frag_offset);
    //     let icmp_type = UInt8Array::from(&self.pack_buf.icmp_type);
    //     let udp_length = UInt16Array::from(&self.pack_buf.udp_length);
    //     let udp_srcport = UInt16Array::from(&self.pack_buf.udp_srcport);
    //     let udp_dstport = UInt16Array::from(&self.pack_buf.udp_dstport);
    //     let tcp_flags = Utf8Array::<i32>::from(&self.pack_buf.tcp_flags);
    //     let tcp_srcport = UInt16Array::from(&self.pack_buf.tcp_srcport);
    //     let tcp_dstport = UInt16Array::from(&self.pack_buf.tcp_dstport);
    //     let col_info = Utf8Array::<i32>::from(&self.pack_buf.col_info);
    //     let col_source = Utf8Array::<i32>::from(&self.pack_buf.col_source);
    //     let col_destination = Utf8Array::<i32>::from(&self.pack_buf.col_destination);
    //     let col_protocol = Utf8Array::<i32>::from(&self.pack_buf.col_protocol);
    //     let dns_qry_name = Utf8Array::<i32>::from(&self.pack_buf.dns_qry_name);
    //     let dns_qry_type = UInt16Array::from(&self.pack_buf.dns_qry_type);
    //     let http_request_uri = Utf8Array::<i32>::from(&self.pack_buf.http_request_uri);
    //     let http_host = Utf8Array::<i32>::from(&self.pack_buf.http_host);
    //     let http_request_method = Utf8Array::<i32>::from(&self.pack_buf.http_request_method);
    //     let http_user_agent = Utf8Array::<i32>::from(&self.pack_buf.http_user_agent);
    //     let http_file_data = Utf8Array::<i32>::from(&self.pack_buf.http_file_data);
    //     let ntp_priv_reqcode = UInt8Array::from(&self.pack_buf.ntp_priv_reqcpde);

    //     let pcap_file = Utf8Array::<i32>::from(&self.pack_buf.pcap_file);

    //     let chunk = Chunk::new(vec![
    //         frame_time.boxed(),
    //         frame_len.boxed(),
    //         eth_type.boxed(),
    //         ip_src.boxed(),
    //         ip_dst.boxed(),
    //         ip_proto.boxed(),
    //         ip_ttl.boxed(),
    //         ip_frag_offset.boxed(),
    //         icmp_type.boxed(),
    //         udp_length.boxed(),
    //         udp_srcport.boxed(),
    //         udp_dstport.boxed(),
    //         tcp_flags.boxed(),
    //         tcp_srcport.boxed(),
    //         tcp_dstport.boxed(),
    //         col_info.boxed(),
    //         col_source.boxed(),
    //         col_destination.boxed(),
    //         col_protocol.boxed(),
    //         dns_qry_name.boxed(),
    //         dns_qry_type.boxed(),
    //         http_request_uri.boxed(),
    //         http_host.boxed(),
    //         http_request_method.boxed(),
    //         http_user_agent.boxed(),
    //         http_file_data.boxed(),
    //         ntp_priv_reqcode.boxed(),
    //         pcap_file.boxed(),
    //     ]);

    //     // eprint!("{:?}", schema);
    //     match self.write_chunk(chunk) {
    //         Err(e) => eprintln!("{}", e),
    //         Ok(_) => (),
    //     }
    // }


// ****************************************************************************************************** //
// ****************************************************************************************************** //
// ****************************************************************************************************** //

fn main() -> Result<()> {
    let args = Args::parse();

    // let test1 = PacketStats::new();

    // test.set_ip_src("127.0.0.1".to_string());
    // test.set_frame_time(100);
    // println!("{:#?}", test);
    // test.copy_from_no_frame(&test1);
    // println!("{:#?}", test);
 
    // std::process::exit(0);


    let file = File::open(&args.file)?;
    let mut reader = create_reader(65536*1024, file)?;
    let mut consecutive_errors = 0;

    let mut num_blocks = 0;

    let mut linktype = Linktype::ETHERNET; // Legacy PCAP files
    let mut if_linktypes = Vec::new(); // PCAP-NG files
    let mut if_tsresol: u8 = 6;

    // let mut pcapdetails: PcapDetails =
    //     PcapDetails::new(&args.file, &args.out, args.printout, args.verbose)?;
    let mut statswriter: StatsWriter = StatsWriter::new(&args.out, &args.file, args.verbose)?;

    loop {
        match reader.next() {
            Ok((offset, block)) => {

                let mut packet_stats:PacketStats = PacketStats::new();

                num_blocks += 1;
                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let tsusec: i64 =
                            i64::from(b.ts_sec) * i64::pow(10, 6) + i64::from(b.ts_usec);
                        packet_stats.frame_time = Some(tsusec);
                        packet_stats.frame_len = Some(b.origlen);
                        let pkt_data =
                            pcap_parser::data::get_packetdata(b.data, linktype, b.caplen as usize)
                                .context("Legacy PCAP Error get_packetdata")?;

                        packet_stats.analyze_packet(pkt_data)?;
                        statswriter.push(packet_stats);
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
                        let ts_pkt: i64 =
                            i64::from(epb.ts_high) * i64::pow(2, 32) + i64::from(epb.ts_high);
                        let ts_res: i64 =
                            i64::from(ts_pkt) * i64::pow(10, 9 - u32::from(if_tsresol));
                        packet_stats.frame_time = Some(ts_res / 1000);
                        packet_stats.frame_len = Some(epb.caplen);
                        let pkt_data = pcap_parser::data::get_packetdata(
                            epb.data,
                            linktype,
                            epb.caplen as usize,
                        )
                        .context("PCAP-NG EnhancedPacket Error get_packetdata")?;
                        packet_stats.analyze_packet(pkt_data)?;
                        statswriter.push(packet_stats);                        
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        let pkt_data = pcap_parser::data::get_packetdata(spb.data, linktype, blen)
                            .context("PCAP-NG SimplePacket Error get_packetdata")?;
                        packet_stats.analyze_packet(pkt_data)?;
                        statswriter.push(packet_stats);                        
                    }
                    PcapBlockOwned::NG(block) => {
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

        // if num_blocks > 100 {
        //     break;
        // }
    }

    statswriter.close_parquet();
    statswriter.writer.close();
 
    eprintln!();

    Ok(())
}
