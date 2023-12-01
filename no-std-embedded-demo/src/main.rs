#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

extern crate alloc;

use defmt::*;
use embassy_executor::{SpawnError, Spawner};
use embassy_net::tcp::{self, ConnectError, TcpSocket};
use embassy_net::{Ipv4Address, Stack, StackResources};
use embassy_stm32::eth::generic_smi::GenericSMI;
use embassy_stm32::eth::{Ethernet, PacketQueue};
use embassy_stm32::peripherals::ETH;
use embassy_stm32::rng::Rng;
use embassy_stm32::time::Hertz;
use embassy_stm32::{bind_interrupts, eth, peripherals, rng, Config};
use embassy_time::Duration;
use embassy_time::Timer;
use embedded_io_async::Write;
use static_cell::make_static;
use {defmt_rtt as _, panic_probe as _};

bind_interrupts!(struct Irqs {
    ETH => eth::InterruptHandler;
    HASH_RNG => rng::InterruptHandler<peripherals::RNG>;
});

const MAC_ADDR: [u8; 6] = [0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
const TCP_BUFSIZ: usize = 4 * 1024;
const HEAP_SIZE: usize = 4 * 1024;

const SERVER_ADDR: Ipv4Address = Ipv4Address([192, 168, 1, 166]);
const SERVER_PORT: u16 = 1234;

#[embassy_executor::main]
async fn start(spawner: Spawner) -> ! {
    heap::init();

    if let Err(e) = main(&spawner).await {
        match e {
            Error::Connect(e) => error!("{}", e),
            Error::Spawn(e) => error!("{}", e),
            Error::Tcp(e) => error!("{}", e),
        }
    }

    info!("Sleeping...");
    loop {
        Timer::after_secs(1).await;
    }
}

async fn main(spawner: &Spawner) -> Result<()> {
    let stack = set_up_network_stack(spawner).await?;

    let mut rx_buffer = [0; TCP_BUFSIZ];
    let mut tx_buffer = [0; TCP_BUFSIZ];
    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

    socket.set_timeout(Some(Duration::from_secs(5)));

    info!("Connecting...");

    socket
        .connect((SERVER_ADDR, SERVER_PORT))
        .await?;

    info!("Connected to {}", socket.remote_endpoint());

    let message = b"hello\n\r".to_vec();
    info!("allocated {}B", message.capacity());
    socket.write_all(&message).await?;
    socket.flush().await?;

    Ok(())
}

async fn set_up_network_stack(spawner: &Spawner) -> Result<&'static MyStack> {
    let mut config = Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hse = Some(Hse {
            freq: Hertz(8_000_000),
            mode: HseMode::Bypass,
        });
        config.rcc.pll_src = PllSource::HSE;
        config.rcc.pll = Some(Pll {
            prediv: PllPreDiv::DIV4,
            mul: PllMul::MUL180,
            divp: Some(PllPDiv::DIV2), // 8mhz / 4 * 180 / 2 = 180Mhz.
            divq: None,
            divr: None,
        });
        config.rcc.ahb_pre = AHBPrescaler::DIV1;
        config.rcc.apb1_pre = APBPrescaler::DIV4;
        config.rcc.apb2_pre = APBPrescaler::DIV2;
        config.rcc.sys = Sysclk::PLL1_P;
    }
    let p = embassy_stm32::init(config);

    // Generate random seed.
    let mut rng = Rng::new(p.RNG, Irqs);
    let mut seed = [0; 8];
    let _ = rng.async_fill_bytes(&mut seed).await;
    let seed = u64::from_le_bytes(seed);

    let device = Ethernet::new(
        make_static!(PacketQueue::<16, 16>::new()),
        p.ETH,
        Irqs,
        p.PA1,
        p.PA2,
        p.PC1,
        p.PA7,
        p.PC4,
        p.PC5,
        p.PG13,
        p.PB13,
        p.PG11,
        GenericSMI::new(0),
        MAC_ADDR,
    );

    let net_config = embassy_net::Config::dhcpv4(Default::default());

    // Init network stack
    let stack = &*make_static!(Stack::new(
        device,
        net_config,
        make_static!(StackResources::<2>::new()),
        seed
    ));

    // Launch network task
    spawner.spawn(net_task(stack))?;

    info!("Waiting for DHCP...");
    let static_cfg = wait_for_config(stack).await;

    let local_addr = static_cfg.address.address();
    info!("IP address: {:?}", local_addr);

    Ok(stack)
}

type MyStack = Stack<Ethernet<'static, ETH, GenericSMI>>;

async fn wait_for_config(stack: &'static Stack<Device>) -> embassy_net::StaticConfigV4 {
    loop {
        if let Some(config) = stack.config_v4() {
            return config.clone();
        }
        embassy_futures::yield_now().await;
    }
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<Device>) -> ! {
    stack.run().await
}

type Device = Ethernet<'static, ETH, GenericSMI>;

type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
enum Error {
    Connect(ConnectError),
    Spawn(SpawnError),
    Tcp(tcp::Error),
}

impl From<tcp::Error> for Error {
    fn from(v: tcp::Error) -> Self {
        Self::Tcp(v)
    }
}

impl From<ConnectError> for Error {
    fn from(v: ConnectError) -> Self {
        Self::Connect(v)
    }
}

impl From<SpawnError> for Error {
    fn from(v: SpawnError) -> Self {
        Self::Spawn(v)
    }
}

mod heap {
    use linked_list_allocator::LockedHeap;
    use spin::Once;

    pub fn init() {
        static ONCE: Once = Once::new();

        ONCE.call_once(|| unsafe {
            static mut MEMORY: [u8; super::HEAP_SIZE] = [0; super::HEAP_SIZE];

            HEAP.lock()
                .init(MEMORY.as_mut_ptr(), MEMORY.len())
        });
    }

    #[global_allocator]
    static HEAP: LockedHeap = LockedHeap::empty();
}
