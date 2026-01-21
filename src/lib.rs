#![deny(clippy::expect_used)]
#![deny(clippy::unwrap_used)]

use netflow_parser::variable_versions::{
    data_number::{DataNumber, FieldValue},
    v9,
};

use std::{collections::BTreeMap, num::NonZeroU16};

#[derive(clap::Parser, Debug)]
pub struct CliOpts {
    #[clap(short, long, default_value = "0.0.0.0")]
    pub bind_address: String,

    #[clap(short, long, default_value = "2055")]
    pub port: NonZeroU16,
    #[clap(short, long, default_value = "false")]
    pub debug: bool,
}

pub fn handle_flowset(
    cli: &CliOpts,
    timestamp: u64,
    addr: &std::net::SocketAddr,
    flowset: v9::FlowSet,
) {
    match flowset.body {
        v9::FlowSetBody::Data(records) => {
            for record in records.fields {
                let mut actual_data: BTreeMap<String, String> = BTreeMap::new();
                actual_data.insert("flow_source".to_string(), addr.to_string());
                actual_data.insert("time".to_string(), timestamp.to_string());
                for (field_name, field_value) in record {
                    let value = match field_value {
                        FieldValue::ApplicationId(application_id) => {
                            format!("{application_id:?}")
                        }
                        FieldValue::String(_) => todo!(),
                        FieldValue::DataNumber(data_number) => match data_number {
                            DataNumber::U8(val) => val.to_string(),
                            DataNumber::I8(val) => val.to_string(),
                            DataNumber::U16(val) => val.to_string(),
                            DataNumber::I16(val) => val.to_string(),
                            DataNumber::U24(val) => val.to_string(),
                            DataNumber::I24(val) => val.to_string(),
                            DataNumber::U32(val) => val.to_string(),
                            DataNumber::U64(val) => val.to_string(),
                            DataNumber::I64(val) => val.to_string(),
                            DataNumber::U128(val) => val.to_string(),
                            DataNumber::I128(val) => val.to_string(),
                            DataNumber::I32(val) => val.to_string(),
                        },
                        FieldValue::Float64(val) => val.to_string(),
                        FieldValue::Duration(duration) => duration.as_secs_f64().to_string(),
                        FieldValue::Ip4Addr(ipv4_addr) => ipv4_addr.to_string(),
                        FieldValue::Ip6Addr(ipv6_addr) => ipv6_addr.to_string(),
                        FieldValue::MacAddr(mac_addr) => mac_addr,
                        FieldValue::Vec(items) => format!("{items:?}"),
                        FieldValue::ProtocolType(protocol_type) => {
                            format!("{protocol_type:?}")
                        }
                        FieldValue::Unknown(items) => {
                            format!("Unknown: {items:?}")
                        }
                    };
                    actual_data.insert(format!("{field_name:?}"), value);
                }
                println!("{}", serde_json::json!(actual_data))
            }
        }
        v9::FlowSetBody::OptionsTemplate(template) => {
            if cli.debug {
                eprintln!("Options Template Flowset received from {addr}: {template:?}");
            }
        }
        v9::FlowSetBody::OptionsData(data) => {
            if cli.debug {
                eprintln!("Options Data Flowset received from {addr}: {data:?}");
            }
        }
        v9::FlowSetBody::Template(template) => {
            if cli.debug {
                eprintln!("Template Flowset received from {addr}: template = {template:?}");
            }
        }
    }
}
