#![no_std]
#![no_main]

// TODOs:
// * move all nvs login inside "Data" struct
// *

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::{net::Ipv4Addr, str::FromStr};

use embassy_executor::Spawner;
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4,
};
use embassy_time::{with_timeout, Duration, Timer};
use embedded_storage::{ReadStorage, Storage};
use esp_alloc as _;
use esp_backtrace as _;
use esp_bootloader_esp_idf::partitions;
use esp_hal::{clock::CpuClock, rng::Rng, timer::timg::TimerGroup};
use esp_println::println;
use esp_storage::FlashStorage;
use esp_wifi::{
    init,
    wifi::{
        AccessPointConfiguration, ClientConfiguration, Configuration, WifiController, WifiDevice,
        WifiEvent,
    },
    EspWifiController,
};
esp_bootloader_esp_idf::esp_app_desc!();

// When you are okay with using a nightly compiler it's better to use https://docs.rs/static_cell/2.1.0/static_cell/macro.make_static.html
macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

const MAX_STORAGE: usize = 256;
const AP_ADDR: &str = "192.168.2.1";
const SSID_LEN: usize = 32;
const PASSWORD_LEN: usize = 128;
const MAX_STA_FAILS: u8 = 3;

#[derive(Clone, Debug, Default)]
pub struct Data {
    pub ssid: String,
    pub password: String,
    pub fail_counter: u8,
}

impl Data {
    pub fn from_str(buffer: &[u8]) -> Self {
        // Ensure buffer is large enough
        if buffer.len() < SSID_LEN + PASSWORD_LEN + 1 {
            return Self::default();
        }

        // Extract and trim SSID and password (remove trailing zeroes)
        let ssid_bytes = &buffer[0..SSID_LEN];
        let password_bytes = &buffer[SSID_LEN..SSID_LEN + PASSWORD_LEN];

        let ssid = ssid_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .cloned()
            .collect::<Vec<u8>>();
        let password = password_bytes
            .iter()
            .take_while(|&&b| b != 0)
            .cloned()
            .collect::<Vec<u8>>();

        let ssid_string = String::from_utf8_lossy(&ssid).into();
        let password_string = String::from_utf8_lossy(&password).into();

        let fail_counter = buffer[SSID_LEN + PASSWORD_LEN];

        Self {
            ssid: ssid_string,
            password: password_string,
            fail_counter,
        }
    }

    pub fn to_bytes(&self) -> [u8; MAX_STORAGE] {
        let mut bytes = [0u8; MAX_STORAGE];
        let ssid_bytes = self.ssid.as_bytes();
        let password_bytes = self.password.as_bytes();

        // Copy SSID
        bytes[..ssid_bytes.len()].copy_from_slice(ssid_bytes);
        // Null-terminate SSID
        if ssid_bytes.len() < SSID_LEN {
            bytes[ssid_bytes.len()] = 0;
        }

        // Copy Password
        bytes[SSID_LEN..SSID_LEN + password_bytes.len()].copy_from_slice(password_bytes);
        // Null-terminate Password
        if password_bytes.len() < PASSWORD_LEN {
            bytes[SSID_LEN + password_bytes.len()] = 0;
        }

        // Store fail counter
        bytes[SSID_LEN + PASSWORD_LEN] = self.fail_counter;

        bytes
    }

    pub fn is_valid(&self) -> bool {
        !self.ssid.is_empty() && !self.password.is_empty() && self.fail_counter <= MAX_STA_FAILS
    }

    pub fn incr_fail_counter(&self) -> Self {
        let mut new_data = self.clone();
        if new_data.fail_counter < u8::MAX {
            new_data.fail_counter += 1;
        }
        new_data
    }

    fn new(ssid: &str, password: &str) -> Self {
        Self {
            ssid: ssid.into(),
            password: password.into(),
            fail_counter: 0,
        }
    }
}

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 48 * 1024);

    // FLASH STORAGE CONFIGURATION
    let mut flash = FlashStorage::new();

    let mut pt_mem = [0u8; partitions::PARTITION_TABLE_MAX_LEN];
    let pt = partitions::read_partition_table(&mut flash, &mut pt_mem).unwrap();

    let nvs = pt
        .find_partition(partitions::PartitionType::Data(
            partitions::DataPartitionSubType::Nvs,
        ))
        .unwrap()
        .unwrap();
    let mut nvs_partition = nvs.as_embedded_storage(&mut flash);

    let mut bytes = [0u8; MAX_STORAGE];
    nvs_partition.read(0, &mut bytes).unwrap();

    let data = Data::from_str(&bytes);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let mut rng = Rng::new(peripherals.RNG);

    let esp_wifi_ctrl = &*mk_static!(
        EspWifiController<'static>,
        init(timg0.timer0, rng.clone(), peripherals.RADIO_CLK).unwrap()
    );

    let (mut controller, interfaces) =
        esp_wifi::wifi::new(&esp_wifi_ctrl, peripherals.WIFI).unwrap();

    let ap_config = AccessPointConfiguration {
        ssid: "flapper".try_into().unwrap(),
        ..Default::default()
    };

    let config = Configuration::AccessPoint(ap_config.clone());
    controller.set_configuration(&config).unwrap();
    controller.start_async().await.unwrap(); // AP ONLY
    println!("Started control panel AP");

    let device = interfaces.ap;

    let timg1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timg1.timer0);

    let ap_ip_addr = Ipv4Addr::from_str(AP_ADDR).expect("failed to parse gateway ip");

    let ap_stack_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(ap_ip_addr, 24),
        gateway: Some(ap_ip_addr),
        dns_servers: Default::default(),
    });

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // Init network stack
    let (ap_stack, ap_runner) = embassy_net::new(
        device,
        ap_stack_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    if data.is_valid() {
        println!(
            "Connecting to SSID: {}, Password: {}, Try: {}",
            data.ssid, data.password, data.fail_counter
        );
        let sta_connection_result = connect_sta_task(
            ap_config,
            controller,
            data.ssid.clone(),
            data.password.clone(),
        )
        .await;

        match sta_connection_result {
            Ok(_) => {
                println!("Connected to STA successfully");
            }
            Err(_) => {
                println!("Failed to connect to STA, saving to memory and restarting");

                let u_data = data.incr_fail_counter();

                nvs_partition.write(0, &u_data.to_bytes()).unwrap();
                println!("Failure saved to NVS");
                println!("Restarting...");
                esp_hal::system::software_reset();
            }
        }
    }

    spawner.spawn(net_task(ap_runner)).ok();
    spawner.spawn(run_dhcp(ap_stack, AP_ADDR)).ok();

    let mut rx_buffer = [0; 512];
    let mut tx_buffer = [0; 512];

    loop {
        if ap_stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
    while !ap_stack.is_config_up() {
        Timer::after(Duration::from_millis(100)).await
    }
    ap_stack
        .config_v4()
        .inspect(|c| println!("ipv4 config: {c:?}"));

    let mut socket = TcpSocket::new(ap_stack, &mut rx_buffer, &mut tx_buffer);
    socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));

    loop {
        println!("Wait for connection...");
        let r = socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 80,
            })
            .await;
        println!("Connected...");

        if let Err(e) = r {
            println!("connect error: {:?}", e);
            continue;
        }

        use embedded_io_async::Write;

        let mut buffer = [0u8; 1024];
        let mut total_len = 0;
        let mut headers_end = None;

        while total_len < buffer.len() {
            match socket.read(&mut buffer[total_len..]).await {
                Ok(0) => break,
                Ok(n) => {
                    total_len += n;
                    if total_len >= 4 {
                        for i in 0..=total_len - 4 {
                            if &buffer[i..i + 4] == b"\r\n\r\n" {
                                headers_end = Some(i + 4);
                                break;
                            }
                        }
                    }
                    if headers_end.is_some() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let headers_end = match headers_end {
            Some(pos) => pos,
            None => {
                println!("No end of headers found");
                continue;
            }
        };
        let request_str = core::str::from_utf8(&buffer[..headers_end]).unwrap_or("");
        let is_post = request_str.starts_with("POST");
        let mut content_length = 0;
        for line in request_str.lines() {
            if line.to_ascii_lowercase().starts_with("content-length:") {
                if let Some(val) = line.split(':').nth(1) {
                    content_length = val.trim().parse::<usize>().unwrap_or(0);
                }
            }
        }

        let body_start = headers_end;
        while is_post && (total_len - body_start) < content_length && total_len < buffer.len() {
            match socket.read(&mut buffer[total_len..]).await {
                Ok(0) => break,
                Ok(n) => {
                    total_len += n;
                }
                Err(_) => break,
            }
        }

        if is_post {
            let body = &buffer[body_start..core::cmp::min(body_start + content_length, total_len)];
            let form_data = core::str::from_utf8(body).unwrap_or("");
            println!("POST form data: {}", form_data);

            let mut ssid = "";
            let mut password = "";
            for pair in form_data.split('&') {
                let mut iter = pair.splitn(2, '=');
                match (iter.next(), iter.next()) {
                    (Some("ssid"), Some(val)) => ssid = val,
                    (Some("password"), Some(val)) => password = val,
                    _ => {}
                }
            }

            // TODO: make this shit readable
            let ssid_from_base64 = base64::decode(ssid).unwrap_or_default();
            ssid = core::str::from_utf8(&ssid_from_base64).unwrap_or_default();
            let password_from_base64 = base64::decode(password).unwrap_or_default();
            password = core::str::from_utf8(&password_from_base64).unwrap_or_default();

            println!("SSID: {}", ssid);
            println!("Password: {}", password);

            // Save to NVS
            let d = Data::new(ssid, password);
            nvs_partition.write(0, &d.to_bytes()).unwrap();
            println!("Credentials saved to NVS");

            // Respond with a confirmation page
            let _ = socket
                .write_all(
                    b"HTTP/1.0 200 OK\r\n\r\n\
                <html>\
                    <body>\
                    RESTARTING NOW!
                    </body>\
                </html>\r\n\
                ",
                )
                .await;

            Timer::after(Duration::from_secs(5)).await;
            esp_hal::system::software_reset();
        } else {
            let _ = socket
                .write_all(
                    b"HTTP/1.0 200 OK\r\n\r\n\
                <html>\
                    <body>\
                        <form action='http://192.168.2.1' method='post' accept-charset='utf-8' onsubmit='encryptFields'>\
                            <label for='ssid'>SSID:</label>\
                            <input type='text' id='ssid' name='ssid'><br><br>\
                            <label for='password'>Password:</label>\
                            <input type='password' id='password' name='password'><br><br>\
                            <input type='submit' value='Submit'>\
                        </form>\
                        <script>\
                            function encryptFields(e) {\
                                const ssidField = document.getElementById('ssid');\
                                const passwordField = document.getElementById('password');\
                                ssidField.value = btoa(ssidField.value);\
                                passwordField.value = btoa(passwordField.value);\
                                e.target.submit();\
                            }\
                        </script>\
                    </body>\
                </html>\r\n\
                ",
                )
                .await;
        }

        let _ = socket.flush().await;
        Timer::after(Duration::from_millis(1000)).await;
        socket.close();
        Timer::after(Duration::from_millis(1000)).await;
        socket.abort();
    }
}

async fn connect_sta_task(
    ap_config: AccessPointConfiguration,
    mut controller: WifiController<'static>,
    ssid: String,
    password: String,
) -> Result<(), ()> {
    println!("Connecting to SSID: {}, Password: {}", ssid, password);

    let sta_cfg = ClientConfiguration {
        ssid: ssid.into(),
        password: password.into(),
        ..Default::default()
    };
    controller
        .set_configuration(&Configuration::Mixed(sta_cfg, ap_config.clone()))
        .unwrap();

    println!("Starting STA mode...");
    with_timeout(
        Duration::from_secs(10),
        controller.wait_for_event(WifiEvent::StaConnected),
    )
    .await
    .map_err(|_| {
        println!("STA connection timed out");
        ()
    })
}

#[embassy_executor::task]
async fn run_dhcp(stack: Stack<'static>, gw_ip_addr: &'static str) {
    use core::net::{Ipv4Addr, SocketAddrV4};

    use edge_dhcp::{
        io::{self, DEFAULT_SERVER_PORT},
        server::{Server, ServerOptions},
    };
    use edge_nal::UdpBind;
    use edge_nal_embassy::{Udp, UdpBuffers};

    let ip = Ipv4Addr::from_str(gw_ip_addr).expect("dhcp task failed to parse gw ip");

    let mut buf = [0u8; 1500];

    let mut gw_buf = [Ipv4Addr::UNSPECIFIED];

    let buffers = UdpBuffers::<3, 1024, 1024, 10>::new();
    let unbound_socket = Udp::new(stack, &buffers);
    let mut bound_socket = unbound_socket
        .bind(core::net::SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            DEFAULT_SERVER_PORT,
        )))
        .await
        .unwrap();

    loop {
        _ = io::server::run(
            &mut Server::<_, 64>::new_with_et(ip),
            &ServerOptions::new(ip, Some(&mut gw_buf)),
            &mut bound_socket,
            &mut buf,
        )
        .await
        .inspect_err(|e| log::warn!("DHCP server error: {e:?}"));
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}
