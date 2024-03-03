use anyhow::{Context, Result};
use clap::Parser;
use pcap_parser::*;
use std::collections::HashMap;
use std::fmt::Debug;
use std::fs::File;

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
    #[arg(short, long)]
    /// Show counter while processing
    #[arg(short, long)]
    verbose: bool,
}



// ****************************************************************************************************** //
// ****************************************************************************************************** //
// ****************************************************************************************************** //

fn main() -> Result<()> {
    let args = Args::parse();

    let mut cache = HashMap::new();
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

                        packet_stats.analyze_packet(pkt_data, &mut cache)?;
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
                        packet_stats.analyze_packet(pkt_data, &mut cache)?;
                        statswriter.push(packet_stats);                        
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        let pkt_data = pcap_parser::data::get_packetdata(spb.data, linktype, blen)
                            .context("PCAP-NG SimplePacket Error get_packetdata")?;
                        packet_stats.analyze_packet(pkt_data, &mut cache)?;
                        statswriter.push(packet_stats);                        
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

        // if num_blocks > 100 {
        //     break;
        // }
    }

    statswriter.close_parquet();
    statswriter.writer.close()?;
 
    eprintln!();

    Ok(())
}
