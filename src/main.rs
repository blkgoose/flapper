#![no_std]
#![no_main]

use core::{net::Ipv4Addr, str::FromStr};

use embassy_executor::Spawner;
use embassy_net::{
    tcp::TcpSocket, IpListenEndpoint, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4,
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
        AccessPointConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiState,
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

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    esp_println::logger::init_logger_from_env();
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 48 * 1024);

    // FLASH STORAGE CONFIGURATION
    let mut flash = FlashStorage::new();
    println!("Flash size = {}", flash.capacity());

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
    let sep = bytes.iter().position(|&b| b == 1);
    let end = bytes.iter().position(|&b| b == 0);

    println!(
        "Read {} bytes from NVS partition, sep: {:?}, end: {:?}",
        bytes.len(),
        sep,
        end
    );

    let mut credentials = None;
    match (sep, end) {
        (Some(sep), Some(end)) if sep < end => {
            let ssid_raw = &bytes[..sep];
            let pass_raw = &bytes[sep + 1..end];

            let ssid = core::str::from_utf8(ssid_raw).ok().and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });
            let password = core::str::from_utf8(pass_raw).ok().and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            });

            if let (Some(ssid), Some(password)) = (ssid, password) {
                credentials = Some((ssid, password));
            }
        }
        (Some(sep), Some(end)) if sep >= end => {
            println!("Corrupt memory, cleaning...");
            nvs_partition.write(0, &[0u8; MAX_STORAGE]).unwrap();
            Timer::after(Duration::from_secs(5)).await;
            esp_hal::system::software_reset();
        }
        _ => {
            println!("No credentials found in NVS, open the AP");
        }
    };
    // FLASH STORAGE CONFIGURATION END

    println!("credentials in NVS: {:?}", credentials);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let mut rng = Rng::new(peripherals.RNG);

    let esp_wifi_ctrl = &*mk_static!(
        EspWifiController<'static>,
        init(timg0.timer0, rng.clone(), peripherals.RADIO_CLK).unwrap()
    );

    let (mut controller, interfaces) =
        esp_wifi::wifi::new(&esp_wifi_ctrl, peripherals.WIFI).unwrap();

    let ap_config = Configuration::AccessPoint(AccessPointConfiguration {
        ssid: "esp-wifi".try_into().unwrap(),
        ..Default::default()
    });
    controller.set_configuration(&ap_config).unwrap();

    let device = interfaces.ap;

    let timg1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timg1.timer0);

    let ap_ip_addr = Ipv4Addr::from_str(AP_ADDR).expect("failed to parse gateway ip");

    let ap_config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: Ipv4Cidr::new(ap_ip_addr, 24),
        gateway: Some(ap_ip_addr),
        dns_servers: Default::default(),
    });

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // Init network stack
    let (ap_stack, ap_runner) = embassy_net::new(
        device,
        ap_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    spawner.spawn(connection(controller)).ok();
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
    println!("Connect to the AP `esp-wifi` and point your browser to http://{AP_ADDR}:8080/");
    println!("DHCP is enabled so there's no need to configure a static IP, just in case:");
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
                port: 8080,
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
            println!("SSID: {}", ssid);
            println!("Password: {}", password);

            // Save to NVS
            let mut bytes = [0u8; MAX_STORAGE];
            bytes[..ssid.len()].copy_from_slice(ssid.as_bytes());
            bytes[ssid.len()] = 1; // Separator
            bytes[ssid.len() + 1..ssid.len() + 1 + password.len()]
                .copy_from_slice(password.as_bytes());
            nvs_partition.write(0, &bytes).unwrap();
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
                        <form action='http://192.168.2.1:8080' method='post'>\
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
        }

        let _ = socket.flush().await;
        Timer::after(Duration::from_millis(1000)).await;
        socket.close();
        Timer::after(Duration::from_millis(1000)).await;
        socket.abort();
    }
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
async fn connection(mut controller: WifiController<'static>) {
    println!("start connection task");
    println!("Device capabilities: {:?}", controller.capabilities());
    loop {
        match esp_wifi::wifi::wifi_state() {
            WifiState::ApStarted => {
                // wait until we're no longer connected
                controller.wait_for_event(WifiEvent::ApStop).await;
                Timer::after(Duration::from_millis(5000)).await
            }
            _ => {}
        }
        if !matches!(controller.is_started(), Ok(true)) {
            controller.start_async().await.unwrap();
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}
