use anyhow::Result;
use clap::Parser;
use pcap_parser::*;
use std::{fmt::Debug, fs};
use std::fs::*;
use rand::distributions::{Alphanumeric, DistString};
use std::env;
use std::thread::{self, JoinHandle};

use duckdb::Connection;

use crossbeam::channel::{bounded, unbounded};

use packetstats::*;
use statswriter::*;

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
    /// Show counter while processing
    #[arg(short, long)]
    verbose: bool,
    /// Do not combine fragments
    #[arg(short, long)]
    nodefrag: bool,
    /// Number of processing threads
    #[arg(short, default_value("2")) ]
    j: isize,
}

// ****************************************************************************************************** //
#[derive(Debug, Clone)]
pub struct PktMsg {
    pub frame_time: i64,
    pub frame_len: u32,
    // pub data: &'a [u8],
    pub data: Vec<u8>,
    pub caplen: u32,
    pub linktype: Linktype,
    pub origlen: u32,
}

// ****************************************************************************************************** //

fn main() -> Result<()> {
    let args = Args::parse();

    let temp_file = format!("{}/pcap-converter-{}.parquet", env::temp_dir().display(), Alphanumeric.sample_string(&mut rand::thread_rng(), 16));
    // println!("{}", temp_file);

    let file = File::open(&args.file)?;
    let mut consecutive_errors = 0;

    let mut linktype = Linktype::ETHERNET; // Legacy PCAP files
    let mut if_linktypes = Vec::new(); // PCAP-NG files
    let mut if_tsresol: u8 = 6;

    let mut statswriter: StatsWriter = StatsWriter::new(&temp_file, &args.file, args.verbose)?;
    
    let (pkt_s, pkt_r) = bounded::<PktMsg>(4_000_000);
    let (stw_s, stw_r) = unbounded::<PacketStats>();

    let sw_thread = thread::spawn(move || {
        for pkt_stats in stw_r.iter() {
            statswriter.push(pkt_stats);
        }
        statswriter.close_parquet();
        statswriter.writer.close().unwrap();
    });

    let mut pkt_threads:Vec<JoinHandle<()>> = Vec::new();
    for _ in 0..args.j {
        let r = pkt_r.clone();
        let s = stw_s.clone();
        let pkt_thread = thread::spawn( move || {
            for pkt_msg in r.iter() {
                let mut packet_stats:PacketStats = PacketStats::new();
                packet_stats.frame_time = Some(pkt_msg.frame_time);
                packet_stats.frame_len = Some(pkt_msg.frame_len);
                let slice = pkt_msg.data;
                let pkt_data = pcap_parser::data::get_packetdata(&slice, pkt_msg.linktype, pkt_msg.caplen as usize).expect("Error getting packet data");

                // s.send(packet_stats).unwrap();
                let result = packet_stats.analyze_packet(pkt_data);
                match result {
                    Ok(_) => s.send(packet_stats).unwrap(),
                    Err(_) => (),
                }
            }
        });
        pkt_threads.push(pkt_thread);
    }

    let mut reader = create_reader(65536*1024 , file)?;

    loop {
        match reader.next() {
            Ok((offset, block)) => {

                match block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                    }
                    PcapBlockOwned::Legacy(b) => {
                        let frame_time: i64 =
                            i64::from(b.ts_sec) * i64::pow(10, 6) + i64::from(b.ts_usec);
                        let frame_len: u32 = b.origlen;
                        let pkt_msg = PktMsg {
                            frame_time: frame_time,
                            frame_len: frame_len,
                            data: b.data.to_owned(),
                            caplen: b.caplen,
                            linktype: linktype,
                            origlen: frame_len,
                        };
                        pkt_s.send(pkt_msg).unwrap();
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
                            i64::from(epb.ts_high) * i64::pow(2, 32) + i64::from(epb.ts_low);
                        let ts_res: i64 =
                            i64::from(ts_pkt) * i64::pow(10, 9 - u32::from(if_tsresol));
                        let frame_time = ts_res / 1000;
                        let frame_len = epb.caplen;
                        let pkt_msg = PktMsg {
                            frame_time: frame_time,
                            frame_len: frame_len,
                            data: epb.data.to_owned(),
                            caplen: epb.caplen,
                            linktype: linktype,
                            origlen: frame_len,
                        };
                        pkt_s.send(pkt_msg).unwrap();
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = spb.block_len1 - 16;
                        let pkt_msg = PktMsg {
                            frame_time: 0,
                            frame_len: spb.origlen,
                            data: spb.data.to_owned(),
                            caplen: blen,
                            linktype: linktype,
                            origlen: spb.origlen,
                        };
                        pkt_s.send(pkt_msg).unwrap();
                    }
                    PcapBlockOwned::NG(_block) => {
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
    }

    drop(pkt_s);

    for pkt_thread in pkt_threads {
        match pkt_thread.join() {
            Ok(_) => (),
            Err(err) => {
                eprintln!("{:#?}", err);
            }
        }
    }

    drop(stw_s);
    sw_thread.join().unwrap();

    if args.verbose {
        eprintln!();
    }

    if args.nodefrag {
        // Simply copy the temp file to args.out
        // Move/rename will not work if moving to another filesystem
        // Which is the default case in Debian
        fs::copy(&temp_file, &args.out)?;
    } else {
        // Do some smart duckdb wrangling
        let conn = Connection::open_in_memory()?;
        conn.execute(&format!("create view pcap as select * from '{}'", temp_file), [])?;

        let row = conn.query_row("select round(100*count()/(select count() from 'pcap')) from 'pcap' where (ip_frag_offset=0 and ip_mf=true) or ip_frag_offset>0", [], |row| {row.get::<usize, f64>(0)});
        let percentage = row.unwrap();

        if percentage < 1.0 { 
            drop(conn);
            if args.verbose {
                eprintln!("{}% fragmented traffic (<1%), not doing defragmentation", percentage);
            }
            fs::copy(&temp_file, &args.out)?;
 
        } else {
            if args.verbose {
                eprintln!("{}% fragmented traffic. Setting UDP/DNS/NTP info based on first fragment (if available)", percentage);
            }
            conn.execute("create view ff as select ip_src, ip_dst, ip_id, ip_proto, first(udp_srcport) as udp_srcport, first(udp_dstport) as udp_dstport, first(ntp_priv_reqcode) as ntp_priv_reqcode, first(dns_qry_type) as dns_qry_type, first(dns_qry_name) as dns_qry_name, first(col_protocol) as col_protocol from pcap where ip_proto=17 and ip_mf=1 and ip_frag_offset=0 group by all", [])?;
            conn.execute("create view raw as select pcap.* exclude (udp_srcport, udp_dstport, ntp_priv_reqcode, dns_qry_type, dns_qry_name, col_protocol), coalesce(ff.udp_srcport, pcap.udp_srcport) as udp_srcport, coalesce(ff.udp_dstport, pcap.udp_dstport) as udp_dstport, coalesce(ff.ntp_priv_reqcode,pcap.ntp_priv_reqcode) as ntp_priv_reqcode, coalesce(ff.dns_qry_type, pcap.dns_qry_type) as dns_qry_type, coalesce(ff.dns_qry_name, pcap.dns_qry_name) as dns_qry_name, coalesce(ff.col_protocol, pcap.col_protocol) as col_protocol from pcap left join ff using (ip_src,ip_dst, ip_proto, ip_id)", [])?;
            conn.execute(&format!("COPY raw to '{}' (format parquet)", args.out), [])?;
        }
    }

    // Remove the temp file
    fs::remove_file(temp_file)?;

    Ok(())
}
