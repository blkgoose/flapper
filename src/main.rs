#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::net::Ipv4Addr;

use embassy_executor::Spawner;
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Cidr, Runner, StackResources, StaticConfigV4,
};
use embassy_time::{Duration, Timer};
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
        WifiEvent, WifiState,
    },
    EspWifiController,
};

use percent_encoding::percent_decode_str;

esp_bootloader_esp_idf::esp_app_desc!();

const AP_NAME: &str = "flapper";
const SSID_LEN: usize = 32;
const PASSWORD_LEN: usize = 128;
const MAX_STA_FAILS: u8 = 3;
const MAX_STORAGE: usize = SSID_LEN + PASSWORD_LEN + 1;
const BUFFER_SIZE: usize = 256;

// When you are okay with using a nightly compiler it's better to use https://docs.rs/static_cell/2.1.0/static_cell/macro.make_static.html
macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

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

    pub fn incr_fail_counter(&mut self) {
        if self.fail_counter < u8::MAX {
            self.fail_counter += 1;
        }
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

    esp_alloc::heap_allocator!(size: 72 * 1024);

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

    let mut data = Data::from_str(&bytes);

    println!("data: {:?}", data);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let mut rng = Rng::new(peripherals.RNG);

    let esp_wifi_ctrl = &*mk_static!(
        EspWifiController<'static>,
        init(timg0.timer0, rng.clone(), peripherals.RADIO_CLK).unwrap()
    );

    let (mut controller, interfaces) =
        esp_wifi::wifi::new(&esp_wifi_ctrl, peripherals.WIFI).unwrap();

    let wifi_ap_device = interfaces.ap;
    let wifi_sta_device = interfaces.sta;

    let timg1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timg1.timer0);

    let ap_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(Ipv4Addr::new(192, 168, 2, 1), 24),
        gateway: Some(Ipv4Addr::new(192, 168, 2, 1)),
        dns_servers: Default::default(),
    });
    let sta_config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // Init network stacks
    let (ap_stack, ap_runner) = embassy_net::new(
        wifi_ap_device,
        ap_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );
    let (sta_stack, sta_runner) = embassy_net::new(
        wifi_sta_device,
        sta_config,
        mk_static!(StackResources<4>, StackResources::<4>::new()),
        seed,
    );

    let ap_only_mode = !data.is_valid();
    let client_config = if ap_only_mode {
        Configuration::AccessPoint(AccessPointConfiguration {
            ssid: AP_NAME.into(),
            ..Default::default()
        })
    } else {
        Configuration::Mixed(
            ClientConfiguration {
                ssid: data.ssid.clone(),
                password: data.password.clone(),
                ..Default::default()
            },
            AccessPointConfiguration {
                ssid: AP_NAME.into(),
                ..Default::default()
            },
        )
    };

    controller.set_configuration(&client_config).unwrap();

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(ap_runner)).ok();
    if !ap_only_mode {
        spawner.spawn(net_task(sta_runner)).ok();

        let sta_address = loop {
            if !data.is_valid() {
                println!("Cannot connect to STA, restarting in AP mode only");
                nvs_partition.write(0, &data.to_bytes()).unwrap();
                esp_hal::system::software_reset();
            }

            println!(
                "Trying to connect to {} (try #{})",
                data.ssid,
                data.fail_counter + 1
            );
            Timer::after(Duration::from_secs(5)).await;
            if let Some(config) = sta_stack.config_v4() {
                let address = config.address.address();
                println!("Got IP: {}", address);
                break address;
            }
            data.incr_fail_counter();
        };

        println!("Connected to STA with IP: {}", sta_address);
    }

    loop {
        if ap_stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
    let mut ap_server_rx_buffer = [0; BUFFER_SIZE];
    let mut ap_server_tx_buffer = [0; BUFFER_SIZE];
    let mut sta_client_rx_buffer = [0; BUFFER_SIZE];
    let mut sta_client_tx_buffer = [0; BUFFER_SIZE];

    let mut ap_server_socket =
        TcpSocket::new(ap_stack, &mut ap_server_rx_buffer, &mut ap_server_tx_buffer);
    ap_server_socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));

    let mut sta_client_socket = TcpSocket::new(
        sta_stack,
        &mut sta_client_rx_buffer,
        &mut sta_client_tx_buffer,
    );
    sta_client_socket.set_timeout(Some(embassy_time::Duration::from_secs(10)));

    loop {
        println!("Wait for connection...");
        ap_server_socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 8080,
            })
            .await
            .expect("AP accept failed");

        let server_socket = &mut ap_server_socket;
        println!("Connected...");

        use embedded_io_async::Write;
        let mut buffer = [0u8; 1024];

        let mut total_len = 0;
        let mut headers_end = None;

        while total_len < buffer.len() {
            match server_socket.read(&mut buffer[total_len..]).await {
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
            match server_socket.read(&mut buffer[total_len..]).await {
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

            let mut ssid = String::new();
            let mut password = String::new();
            for pair in form_data.split('&') {
                let mut iter = pair.splitn(2, '=');
                match (iter.next(), iter.next()) {
                    (Some("ssid"), Some(val)) => {
                        ssid = percent_decode_str(val)
                            .decode_utf8()
                            .unwrap_or_default()
                            .into_owned()
                    }
                    (Some("password"), Some(val)) => {
                        password = percent_decode_str(val)
                            .decode_utf8()
                            .unwrap_or_default()
                            .into_owned()
                    }
                    _ => {}
                }
            }

            println!("SSID: {}", ssid);
            println!("Password: {}", password);

            // Save to NVS
            let d = Data::new(&ssid, &password);
            nvs_partition.write(0, &d.to_bytes()).unwrap();
            println!("Credentials saved to NVS");

            // Respond with a confirmation page
            let _ = server_socket
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
            let r = server_socket
                .write_all(
                    b"HTTP/1.0 200 OK\r\n\r\n\
                            <html>\
                            <body>\
                                <form method='post'>\
                                    <label for='ssid'>SSID:</label>\
                                    <input type='text' id='ssid' name='ssid'><br><br>\
                                    <label for='password'>Password:</label>\
                                    <input type='password' id='password' name='password'><br><br>\
                                    <input type='submit' value='Submit'>\
                                </form>\
                            </body>\
                            </html>\r\n\
                            ",
                )
                .await;
            if let Err(e) = r {
                println!("AP write error: {:?}", e);
            }

            let r = server_socket.flush().await;
            if let Err(e) = r {
                println!("AP flush error: {:?}", e);
            }
            Timer::after(Duration::from_millis(1000)).await;
            server_socket.close();
            Timer::after(Duration::from_millis(1000)).await;
            server_socket.abort();
        }
    }
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    println!("start connection task");
    println!("Device capabilities: {:?}", controller.capabilities());

    println!("Starting wifi");
    controller.start_async().await.unwrap();
    println!("Wifi started!");

    loop {
        match esp_wifi::wifi::ap_state() {
            WifiState::ApStarted => {
                println!("About to connect...");

                match controller.connect_async().await {
                    Ok(_) => {
                        // wait until we're no longer connected
                        controller.wait_for_event(WifiEvent::StaDisconnected).await;
                        println!("STA disconnected");
                    }
                    Err(e) => {
                        println!("Failed to connect to wifi: {e:?}");
                        Timer::after(Duration::from_millis(5000)).await
                    }
                }
            }
            _ => return,
        }
    }
}

#[embassy_executor::task(pool_size = 2)]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}
