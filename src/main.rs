use clap::{crate_authors, crate_name, crate_version, Arg};
use std::str::FromStr;
use regex::Regex;
use itertools::Itertools;
use prometheus_exporter::{prometheus::register_gauge_vec, prometheus::GaugeVec};
use prometheus_exporter::{self, prometheus::register_int_gauge_vec, prometheus::IntGaugeVec};
use std::env;
use std::net::IpAddr;
use lazy_static::lazy_static;
use reqwest::blocking::Client;

type DDWrtResult<T> = Result<T, Box<dyn std::error::Error>>;

lazy_static! {
    static ref REC_SEP: Regex = Regex::new(r"\{(\w+)::([^}]*)\}").expect("Invalid regex");
    static ref UNIT_SEP: Regex = Regex::new(r"'([^']*)'\s*,?").expect("Invalid regex");
    static ref TIME_FMT: Regex = Regex::new(r"((?P<day>\d+) ?days? )?((?P<hour>\d+):)?(?P<min>d\d):(?P<sec>\d\d)").expect("Invalid regex");
}
const PREFIX: &str = "ddwrt_exporter";

/*
 * Known endpoints with info:
 *
 * Info.live.htm
 * AOSS.live.asp
 * AnchorFree.live.asp
 * DDNS.live.asp
 * FreeRadius.live.asp
 * Networking.live.asp
 * Status_Internet.live.asp
 * Status_Lan.live.asp
 * Status_Router.live.asp
 * Status_SputnikAPD.live.asp
 * Status_Wireless.live.asp
 * Statusinfo.live.asp
 * UPnP.live.asp
 * USB.live.asp
 * Wiviz.live.asp
 */

struct PrometheusGauges {
    exporter: prometheus_exporter::Exporter,

    // Status_Lan
    lan_info: IntGaugeVec,
    arp_connections: IntGaugeVec,
    arp_data_in: IntGaugeVec,
    arp_data_out: IntGaugeVec,
    arp_data_total: IntGaugeVec,

    // Status_Wireless
    wl_info: IntGaugeVec,
    wl_client_signal: IntGaugeVec,
    wl_client_noise: IntGaugeVec,
    wl_client_snr: IntGaugeVec,
    wl_client_uptime: IntGaugeVec,
    wl_client_sig_quality: GaugeVec,
}

// Status_Lan.live.asp
#[derive(Debug)]
struct ArpInfo {
    hostname: String,
    ip_addr: String,
    mac_addr: String,
    connections: i64,
    interface: String,
    data_in: i64,
    data_out: i64,
    data_total: i64,

}
#[derive(Default,Debug)]
struct StatusLan {
    lan_mac: String,
    lan_ip: String,
    lan_gateway: String,
    lan_dns: String,
    // lan_proto: String,
    // dhcp_start: String,
    // dhcp_end: String,
    // dhcp_num: usize,
    // dhcp_lease_time: usize,
    // dhcp_leases: ???,
    // pptp_leases: ???,
    // pppoe_leases: ???,
    arp_table: Vec<ArpInfo>,
    // uptime: String,
    // ipinfo: String,
}

impl FromStr for StatusLan {
    type Err = std::num::ParseIntError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut status = Self::default();

        for caps in REC_SEP.captures_iter(input) {
            let field = caps.get(1).map_or("", |m| m.as_str());
            let value = caps.get(2).map_or("", |m| m.as_str());


            match field {
                "lan_mac" => status.lan_mac = value.to_owned(),
                "lan_ip" => status.lan_ip = value.to_owned(),
                "lan_gateway" => status.lan_gateway = value.to_owned(),
                "lan_dns" => status.lan_dns = value.to_owned(),
                "arp_table" => status.arp_table = UNIT_SEP
                        .captures_iter(value)
                        .filter_map(|cap| cap.get(1).map(|m| m.as_str()))
                        .tuples::<(_,_,_,_,_,_,_,_)>()
                        .filter_map(|(
                            hostname,
                            ip_addr,
                            mac_addr,
                            connections,
                            interface,
                            data_in,
                            data_out,
                            data_total
                        )| {
                            Some(ArpInfo {
                                hostname: hostname.to_owned(),
                                ip_addr: ip_addr.to_owned(),
                                mac_addr: mac_addr.to_owned(),
                                connections: connections.parse().ok()?,
                                interface: interface.to_owned(),
                                data_in: data_in.parse().ok()?,
                                data_out: data_out.parse().ok()?,
                                data_total: data_total.parse().ok()?,
                            })
                        })
                        .collect(),

                _ => (),
                // _ => println!("\n{:?}: {:?}\n", field, value),
            }

        }

        return Ok(status);
    }
}

// Status_Wireless.live.asp
#[derive(Debug)]
struct WirelessClient {
    mac_addr: String,
    _radio_name: String,
    interface: String,
    uptime: i64,  // seconds
    _tx_rate: String,
    _rx_rate: String,
    _info: String,
    signal: i64,
    noise: i64,
    snr: i64,
    signal_quality: i64,
    _unknown12: i64,
    _unknown13: i64,
    _unknown14: i64,
    _unknown15: i64,
}
#[derive(Default,Debug)]
struct StatusWireless {
    wl_mac: String,
    wl_ssid: String,
    // wl_channel: usize,
    // wl_radio: bool,
    // wl_xmit: String,
    // wl_rate: usize,  // Mb/s?
    // wl_busy: ???,
    // wl_active: ???,
    // wl_quality: ???,
    // wl_ack: ???,
    active_wireless: Vec<WirelessClient>,
    // active_wds: ???,
    // assoc_count: usize,
    // packet_info: struct,
    // uptime: String,
    // ipinfo: String,

}

impl FromStr for StatusWireless {
    type Err = std::num::ParseIntError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut status = Self::default();

        for caps in REC_SEP.captures_iter(input) {
            let field = caps.get(1).map_or("", |m| m.as_str());
            let value = caps.get(2).map_or("", |m| m.as_str());

            match field {
                "wl_mac" => status.wl_mac = value.to_owned(),
                "wl_ssid" => status.wl_ssid = value.to_owned(),
                "active_wireless" => status.active_wireless = UNIT_SEP
                        .captures_iter(value)
                        .filter_map(|cap| cap.get(1).map(|m| m.as_str()))
                        .tuples::<(_,_,_,_,_)>()
                        .tuples::<(_,_,_)>()
                        .filter_map(|(
                            (mac_addr, radio, interface, uptime, tx_rate),
                            (rx_rate, info, signal, noise, snr),
                            (quality, _u12, _u13, _u14, _u15),
                        )| {
                            Some(WirelessClient {
                                mac_addr: mac_addr.to_owned(),
                                _radio_name: radio.to_owned(),
                                interface: interface.to_owned(),
                                uptime: to_sec(uptime),
                                _tx_rate: tx_rate.to_owned(),
                                _rx_rate: rx_rate.to_owned(),
                                _info: info.to_owned(),
                                signal: signal.parse().ok()?,
                                noise: noise.parse().ok()?,
                                snr: snr.parse().ok()?,
                                signal_quality: quality.parse().ok()?,
                                _unknown12: _u12.parse().ok()?,
                                _unknown13: _u13.parse().ok()?,
                                _unknown14: _u14.parse().ok()?,
                                _unknown15: _u15.parse().ok()?,
                            })
                        })
                        .collect(),

                _ => (),
                // _ => println!("\n{:?}: {:?}\n", field, value),
            }

        }

        return Ok(status);
    }
}

fn to_sec(time: &str) -> i64 {
    if let Some(caps) = TIME_FMT.captures(time) {
        let mut time = 0;

        for name in TIME_FMT.capture_names() {
            if let Some(name) = name {
                let val = caps.name(name).map_or(0, |m| m.as_str().parse().unwrap());
                time += match name {
                    "day"  => val * 60 * 60 * 24,
                    "hour" => val * 60 * 60 ,
                    "min"  => val * 60,
                    "sec"  => val,
                    _      => 0,
                };
            }
        }

        return time;
    }
    else {
        return 0;
    }
}

fn parse_args() -> clap::ArgMatches {
    clap::Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .arg(
            Arg::new("addr")
                .short('l')
                .long("address")
                .env("PROMETHEUS_DDWRT_EXPORTER_ADDRESS")
                .help("exporter address to listen on")
                .default_value("0.0.0.0")
                .takes_value(true),
        )
        .arg(
            Arg::new("port")
                .short('p')
                .long("port")
                .env("PROMETHEUS_DDWRT_EXPORTER_PORT")
                .help("exporter port to listen on")
                .default_value("9983")
                .takes_value(true),
        )
        .arg(
            Arg::new("username")
                .short('U')
                .long("username")
                .env("PROMETHEUS_DDWRT_EXPORTER_USERNAME")
                .help("username to send to DD-WRT device when connecting")
                .takes_value(true),
        )
        .arg(
            Arg::new("password")
                .short('P')
                .long("password")
                .env("PROMETHEUS_DDWRT_EXPORTER_PASSWORD")
                .help("password to send to DD-WRT device when connecting")
                .takes_value(true),
        )
        .arg(
            Arg::new("url")
                .env("PROMETHEUS_DDWRT_EXPORTER_URL")
                .help("address of DD-WRT device to connect to")
                .takes_value(true),
        )
        .get_matches()
}

fn setup_prometheus_exporter(args: &clap::ArgMatches) -> PrometheusGauges {
    let port = args.value_of("port").unwrap();
    let port = port.parse::<u16>().expect("port must be a valid number");
    let addr = args.value_of("addr").unwrap().parse::<IpAddr>().unwrap();
    let bind = (addr, port).into();

    let exporter = prometheus_exporter::start(bind).expect("Couldn't bind address");
    println!("listening on http://{bind}/metrics");

    PrometheusGauges {
        exporter,

        // Status_Lan
        lan_info:		register_int_gauge_vec!(format!("{PREFIX}_lan_info"),		"Information about the router",		&["mac", "ipaddr", "gateway", "dns"]).unwrap(),
        arp_connections:	register_int_gauge_vec!(format!("{PREFIX}_arp_connections"),	"Connections made to this host",	&["hostname", "ipaddr", "mac", "iface"]).unwrap(),
        arp_data_in:		register_int_gauge_vec!(format!("{PREFIX}_arp_data_in"),	"Data sent by this host",		&["hostname", "ipaddr", "mac", "iface"]).unwrap(),
        arp_data_out:		register_int_gauge_vec!(format!("{PREFIX}_arp_data_out"),	"Data sent to this host",		&["hostname", "ipaddr", "mac", "iface"]).unwrap(),
        arp_data_total:		register_int_gauge_vec!(format!("{PREFIX}_arp_data_total"),	"Total data sent to/from this host",	&["hostname", "ipaddr", "mac", "iface"]).unwrap(),

        // Status_Wireless
        wl_info:		register_int_gauge_vec!(format!("{PREFIX}_wl_info"),		"Information about wireless networks",	&["mac", "ssid"]).unwrap(),
        wl_client_signal:	register_int_gauge_vec!(format!("{PREFIX}_wl_client_signal"),	"Wireless device signal",		&["mac", "iface"]).unwrap(),
        wl_client_noise:	register_int_gauge_vec!(format!("{PREFIX}_wl_client_noise"),	"Wireless device noise",		&["mac", "iface"]).unwrap(),
        wl_client_snr:		register_int_gauge_vec!(format!("{PREFIX}_wl_client_snr"),	"Wireless device signal/noise",		&["mac", "iface"]).unwrap(),
        wl_client_uptime:	register_int_gauge_vec!(format!("{PREFIX}_wl_client_uptime"),	"Wireless device time seen",		&["mac", "iface"]).unwrap(),
        wl_client_sig_quality:	register_gauge_vec!(format!("{PREFIX}_wl_client_sig_quality"),	"Wireless device signal quality",	&["mac", "iface"]).unwrap(),
    }
}

fn process_request(
    args: &clap::ArgMatches,
    gauges: &PrometheusGauges,
    client: &Client
) {
    let url = args.value_of("url")
        .expect("URL must be specified")
        .trim_end_matches("/");

    let lan = client
        .get(format!("{url}/Status_Lan.live.asp"))
        .basic_auth(args.value_of("username").unwrap(), args.value_of("password"))
        .send().unwrap()
        .text().unwrap();
    if let Ok(lan) = lan.parse::<StatusLan>() {
        gauges.lan_info.reset();
        gauges.arp_connections.reset();
        gauges.arp_data_in.reset();
        gauges.arp_data_out.reset();
        gauges.arp_data_total.reset();

        gauges.lan_info
            .with_label_values(&[&lan.lan_mac, &lan.lan_ip, &lan.lan_gateway, &lan.lan_dns])
            .set(1);

        for host in lan.arp_table {
            let info: [&str;4] = [
                &host.hostname,
                &host.ip_addr,
                &host.mac_addr,
                &host.interface
            ];

            gauges.arp_connections
                .with_label_values(&info)
                .set(host.connections);

            gauges.arp_data_in.
                with_label_values(&info)
                .set(host.data_in);

            gauges.arp_data_out
                .with_label_values(&info)
                .set(host.data_out);

            gauges.arp_data_total
                .with_label_values(&info)
                .set(host.data_total);
        }
    }
    let wl = client
        .get(format!("{url}/Status_Wireless.live.asp"))
        .basic_auth(args.value_of("username").unwrap(), args.value_of("password"))
        .send().unwrap()
        .text().unwrap();
    if let Ok(wl) = wl.parse::<StatusWireless>() {
        gauges.wl_info.reset();
        gauges.wl_client_noise.reset();
        gauges.wl_client_noise.reset();
        gauges.wl_client_snr.reset();
        gauges.wl_client_uptime.reset();
        gauges.wl_client_sig_quality.reset();

        gauges.wl_info
            .with_label_values(&[&wl.wl_mac, &wl.wl_ssid])
            .set(1);

        for client in wl.active_wireless {
            let info: [&str; 2] = [&client.mac_addr, &client.interface];
            gauges.wl_client_signal
                .with_label_values(&info)
                .set(client.signal);

            gauges.wl_client_noise
                .with_label_values(&info)
                .set(client.noise);

            gauges.wl_client_snr
                .with_label_values(&info)
                .set(client.snr);

            gauges.wl_client_uptime
                .with_label_values(&info)
                .set(client.uptime);

            gauges.wl_client_sig_quality
                .with_label_values(&info)
                .set((client.signal_quality as f64) / 1000_f64);
        }
    }
}

fn main()-> DDWrtResult<()> {
    let args = parse_args();
    let gauges = setup_prometheus_exporter(&args);

    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    loop {
        // Will block until a new request comes in.
        let _guard = gauges.exporter.wait_request();

        process_request(&args, &gauges, &client);
    }
}
