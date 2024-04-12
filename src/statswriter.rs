use std::collections::HashMap;
use std::{fmt::Debug, sync::Arc};
use std::path::Path;
use std::fs::File;
use crate::packetstats::*;
use anyhow::Error;
use num_format::{Locale, ToFormattedString};
use arrow::datatypes::*;
use arrow::array::*;
use arrow::datatypes::DataType::*;
use parquet::{
    basic::{Compression, Encoding},
    file::properties::*,
    arrow::ArrowWriter,
};


#[derive(Debug, Default)]
pub struct PacketCache {
   pub srcport: Option<u16>,
   pub dstport: Option<u16>,
   pub protocol: Option<String>,
   pub dns_qry_name: Option<String>,
   pub dns_qry_type: Option<u16>,
   pub ip_total_len: u16,
   pub ntp_priv_reqcode: Option<u8>,
}


#[derive(Debug)]
pub struct StatsWriter {
    // filename: String,
    // fields: Vec<Field>,
    pcap_file: String,
    schema: Schema,
    pub writer: ArrowWriter<std::fs::File>,
    packets: Vec<PacketStats>,
    // frag_cache: HashMap<u16, FragmentCache>,
    packet_count: i64,
    cache_misses: i64,
    errors: i64,
    verbose: bool,
    // let mut cache = HashMap::new();
    cache: HashMap<u16, PacketCache>,
 }


impl StatsWriter {
    pub fn new(filename: &str, pcap_file: &str, verbose: bool) -> Result<StatsWriter, Error> {
        // return Default::default()

        let fields = StatsWriter::create_fields();
        let schema = Schema::new(fields.clone());
        let props = WriterProperties::builder()
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .set_encoding(Encoding::PLAIN)
        .set_compression(Compression::SNAPPY)
        .build();
    // .set_column_encoding(ColumnPath::from("col1"), Encoding::DELTA_BINARY_PACKED)
    
        let file = File::create(filename).unwrap();

        let writer = ArrowWriter::try_new(file, Arc::new(schema.clone()), Some(props))?;
    
        let path = Path::new(pcap_file);
        let filename = path.file_name().unwrap();
        let sw = StatsWriter { 
            // filename: filename.to_string(),
            // fields: StatsWriter::create_fields(), 
                pcap_file: filename.to_str().unwrap().to_string(),
                schema: schema,
                writer: writer,
                packets: Vec::new(),
                // frag_cache: HashMap::new(),
                packet_count: 0,
                cache_misses: 0,
                errors: 0,
                verbose: verbose,
                cache: HashMap::new(),
            };
    
        Ok(sw)
    }

    fn create_fields() -> Vec<Field> {
        let mut fields: Vec<Field> = Vec::new();
    
        fields.push(Field::new(
            "frame_time",
            Timestamp(TimeUnit::Microsecond, None),
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
    
    pub fn push(&mut self, mut packet: PacketStats) {

        // self.cache_misses += packet.cache_miss;
        self.errors += packet.errors;

        match packet.ip_frag_offset {
            Some(offset) => {
                if offset > 0 {
                    match self.cache.get(&packet.ip_id) {
                        Some(cache) => {
                            packet.udp_srcport = cache.srcport;
                            packet.udp_dstport = cache.dstport;
                            packet.col_protocol = cache.protocol.clone();
                            packet.dns_qry_type = cache.dns_qry_type;
                            packet.dns_qry_name = cache.dns_qry_name.clone();
                            packet.ntp_priv_reqcode = cache.ntp_priv_reqcode;
                        }
        
                        None => {
                            // cache miss
                            // eprintln!("cache miss");
                            self.cache_misses += 1;
                        }
                    }
                } else {
                    if packet.more_fragments {
                        let ports: PacketCache = PacketCache {
                            srcport: packet.udp_srcport,
                            dstport: packet.udp_dstport,
                            protocol: packet.col_protocol.clone(),
                            dns_qry_type: packet.dns_qry_type,
                            dns_qry_name: packet.dns_qry_name.clone(),
                            ip_total_len: packet.ip_total_len,
                            ntp_priv_reqcode: packet.ntp_priv_reqcode,
                        };
                        self.cache.entry(packet.ip_id).or_insert(ports);
                    }
                }
            }
            None => ()
        }
        // if packet.is_first_fragment() {
        //     // Push to cache
        //     let ports: PacketCache = PacketCache {
        //         srcport: packet.udp_srcport,
        //         dstport: packet.udp_dstport,
        //         protocol: packet.col_protocol.clone(),
        //         dns_qry_type: packet.dns_qry_type,
        //         dns_qry_name: packet.dns_qry_name.clone(),
        //         ip_total_len: packet.ip_total_len,
        //         ntp_priv_reqcode: packet.ntp_priv_reqcode,
        //     };
        //     self.cache.entry(ip_id).or_insert(ports);
        // } else if packet.is_fragment() {
        //     match packet.ip_id {
        //         Some(ip_id) => {
        //             match self.cache.get(&ip_id) {
        //                 Some(cache) => {
        //                     packet.udp_srcport = cache.srcport;
        //                     packet.udp_dstport = cache.dstport;
        //                     packet.col_protocol = cache.protocol.clone();
        //                     packet.dns_qry_type = cache.dns_qry_type;
        //                     packet.dns_qry_name = cache.dns_qry_name.clone();
        //                     packet.ntp_priv_reqcode = cache.ntp_priv_reqcode;
        //                 }
        
        //                 None => {
        //                     // cache miss
        //                     // eprintln!("cache miss");
        //                     self.cache_misses += 1;
        //                 }
        //             }
        //         },
        //         None => (),
        //     }
        // }

        self.packets.push(packet);
        self.packet_count += 1;

        if self.packets.len() >= 10_000 {
            self.write_batch();
        }

    }

    fn record_batch(&mut self) -> RecordBatch {
        let frame_time = TimestampMicrosecondArray::from(self.packets.iter().map(|p| p.frame_time).collect::<Vec<Option<i64>>>());
        let frame_len = UInt32Array::from(self.packets.iter().map(|p| p.frame_len).collect::<Vec<Option<u32>>>());
        let eth_type = UInt16Array::from(self.packets.iter().map(|p| p.eth_type).collect::<Vec<Option<u16>>>());
        let ip_src = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.ip_src.clone()).collect::<Vec<Option<String>>>());
        let ip_dst = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.ip_dst.clone()).collect::<Vec<Option<String>>>());
        let ip_proto = UInt8Array::from(self.packets.iter().map(|p| p.ip_proto).collect::<Vec<Option<u8>>>());
        let ip_ttl = UInt8Array::from(self.packets.iter().map(|p| p.ip_ttl).collect::<Vec<Option<u8>>>());
        let ip_frag_offset = UInt16Array::from(self.packets.iter().map(|p| p.ip_frag_offset).collect::<Vec<Option<u16>>>());
        let icmp_type = UInt8Array::from(self.packets.iter().map(|p| p.icmp_type).collect::<Vec<Option<u8>>>());
        let udp_length = UInt16Array::from(self.packets.iter().map(|p| p.udp_length).collect::<Vec<Option<u16>>>());
        let udp_srcport = UInt16Array::from(self.packets.iter().map(|p| p.udp_srcport).collect::<Vec<Option<u16>>>());
        let udp_dstport = UInt16Array::from(self.packets.iter().map(|p| p.udp_dstport).collect::<Vec<Option<u16>>>());
        let tcp_flags = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.tcp_flags.clone()).collect::<Vec<Option<String>>>());
        let tcp_srcport = UInt16Array::from(self.packets.iter().map(|p| p.tcp_srcport).collect::<Vec<Option<u16>>>());
        let tcp_dstport = UInt16Array::from(self.packets.iter().map(|p| p.tcp_dstport).collect::<Vec<Option<u16>>>());
        let col_info = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_info.clone()).collect::<Vec<Option<String>>>());
        let col_source = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_source.clone()).collect::<Vec<Option<String>>>());
        let col_destination = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_destination.clone()).collect::<Vec<Option<String>>>());
        let col_protocol = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.col_protocol.clone()).collect::<Vec<Option<String>>>());
        let dns_qry_name = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.dns_qry_name.clone()).collect::<Vec<Option<String>>>());
        let dns_qry_type = UInt16Array::from(self.packets.iter().map(|p| p.dns_qry_type).collect::<Vec<Option<u16>>>());
        let http_request_uri = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_request_uri.clone()).collect::<Vec<Option<String>>>());
        let http_host = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_host.clone()).collect::<Vec<Option<String>>>());
        let http_request_method = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_request_method.clone()).collect::<Vec<Option<String>>>());
        let http_user_agent = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_user_agent.clone()).collect::<Vec<Option<String>>>());
        let http_file_data = GenericStringArray::<i32>::from(self.packets.iter().map(|p| p.http_file_data.clone()).collect::<Vec<Option<String>>>());
        let ntp_priv_reqcode = UInt8Array::from(self.packets.iter().map(|p| p.ntp_priv_reqcode).collect::<Vec<Option<u8>>>());
        let pcap_file = GenericStringArray::<i32>::from(vec![self.pcap_file.clone(); self.packets.len()]);
        

        let batch = RecordBatch::try_new(
            Arc::new(self.schema.clone()),
            vec![
                Arc::new(frame_time),
                Arc::new(frame_len),
                Arc::new(eth_type),
                Arc::new(ip_src),
                Arc::new(ip_dst),
                Arc::new(ip_proto),
                Arc::new(ip_ttl),
                Arc::new(ip_frag_offset),
                Arc::new(icmp_type),
                Arc::new(udp_length),
                Arc::new(udp_srcport),
                Arc::new(udp_dstport),
                Arc::new(tcp_flags),
                Arc::new(tcp_srcport),
                Arc::new(tcp_dstport),
                Arc::new(col_info),
                Arc::new(col_source),
                Arc::new(col_destination),
                Arc::new(col_protocol),
                Arc::new(dns_qry_name),
                Arc::new(dns_qry_type),
                Arc::new(http_request_uri),
                Arc::new(http_host),
                Arc::new(http_request_method),
                Arc::new(http_user_agent),
                Arc::new(http_file_data),
                Arc::new(ntp_priv_reqcode),
                Arc::new(pcap_file),
                ]
        ).unwrap();

        return batch;

    }


    pub fn flush(&mut self) {
        self.write_batch();
    }

    fn write_batch(&mut self) {
        let batch = self.record_batch();
        self.writer.write(&batch).unwrap();
        self.packets = Vec::new();

        if self.verbose {
            eprint!("\rPackets: {} Errors: {} Cache misses: {}", 
                self.packet_count.to_formatted_string(&Locale::en), 
                self.errors.to_formatted_string(&Locale::en),
                self.cache_misses.to_formatted_string(&Locale::en));
        }
    }
 
    pub fn close_parquet(&mut self) {
        self.flush();
        let _ = self.writer.flush();
    }

}


