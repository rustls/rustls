// based on `$(rustc +1.72.0 --print sysroot)/lib/rustlib/src/rust/library/std/src/sys_common/net.rs`

use core::{ffi::c_int, fmt, mem, ptr};

use alloc::ffi::CString;

use crate::{io, libc, sys};

#[allow(non_camel_case_types)]
type wrlen_t = usize;

pub struct TcpStream {
    inner: Socket,
}

impl TcpStream {
    pub fn connect(addr: &SocketAddr) -> io::Result<Self> {
        let sock = Socket::new(addr, libc::SOCK_STREAM)?;
        let (addr, len) = addr.into_inner();
        sys::cvt_r(|| unsafe { libc::connect(sock.0, addr.as_ptr(), len) })?;
        Ok(TcpStream { inner: sock })
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("TcpStream");

        res.field("fd", &self.inner.0).finish()
    }
}

impl io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv_with_flags(buf, 0)
    }
}

impl io::Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stream: &Self = self;
        stream.write(buf)
    }
}

impl io::Write for &'_ TcpStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(<wrlen_t>::MAX) as wrlen_t;
        let ret = sys::cvt(unsafe {
            libc::send(self.inner.0, buf.as_ptr().cast(), len, libc::MSG_NOSIGNAL)
        })?;
        Ok(ret as usize)
    }
}

#[derive(Clone, Copy)]
pub enum SocketAddr {
    V4(SocketAddrV4),
    // V6(SocketAddrV6),
}

impl SocketAddr {
    fn into_inner(self) -> (SocketAddrCRepr, libc::socklen_t) {
        match self {
            SocketAddr::V4(a) => {
                let sockaddr = SocketAddrCRepr { v4: a.into_inner() };
                (
                    sockaddr,
                    mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
    }
}

impl From<SocketAddrV4> for SocketAddr {
    fn from(v: SocketAddrV4) -> Self {
        Self::V4(v)
    }
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::V4(a) => fmt::Display::fmt(a, f),
        }
    }
}

impl fmt::Debug for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[repr(C)]
struct SocketAddrCRepr {
    v4: libc::sockaddr_in,
}

impl SocketAddrCRepr {
    pub fn as_ptr(&self) -> *const libc::sockaddr {
        (self as *const Self).cast()
    }
}

#[derive(Clone, Copy)]
pub struct SocketAddrV4 {
    ip: Ipv4Addr,
    port: u16,
}

impl SocketAddrV4 {
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip, port }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    fn into_inner(self) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: self.port().to_be(),
            sin_addr: self.ip().into_inner(),
            ..unsafe { mem::zeroed() }
        }
    }

    fn from_inner(addr: libc::sockaddr_in) -> SocketAddrV4 {
        SocketAddrV4::new(
            Ipv4Addr::from_inner(addr.sin_addr),
            u16::from_be(addr.sin_port),
        )
    }
}

impl fmt::Display for SocketAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.ip(), self.port())
    }
}

impl fmt::Debug for SocketAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Copy)]
pub struct Ipv4Addr {
    octets: [u8; 4],
}

impl Ipv4Addr {
    pub fn octets(&self) -> [u8; 4] {
        self.octets
    }

    fn into_inner(self) -> libc::in_addr {
        libc::in_addr {
            s_addr: u32::from_ne_bytes(self.octets()),
        }
    }
}

impl Ipv4Addr {
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self {
            octets: [a, b, c, d],
        }
    }

    fn from_inner(addr: libc::in_addr) -> Ipv4Addr {
        Ipv4Addr::from(addr.s_addr.to_ne_bytes())
    }
}

impl From<[u8; 4]> for Ipv4Addr {
    fn from([a, b, c, d]: [u8; 4]) -> Self {
        Self::new(a, b, c, d)
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

type FileDesc = c_int;

struct Socket(FileDesc);

impl Socket {
    fn new(addr: &SocketAddr, ty: c_int) -> io::Result<Self> {
        let fam = match addr {
            SocketAddr::V4(_) => libc::AF_INET,
        };
        Socket::new_raw(fam, ty)
    }

    fn new_raw(fam: c_int, ty: c_int) -> io::Result<Self> {
        let fd = sys::cvt(unsafe { libc::socket(fam, ty | libc::SOCK_CLOEXEC, 0) })?;
        Ok(Socket(fd))
    }

    fn recv_with_flags(&self, buf: &mut [u8], flags: c_int) -> io::Result<usize> {
        let ret =
            sys::cvt(unsafe { libc::recv(self.0, buf.as_mut_ptr().cast(), buf.len(), flags) })?;
        Ok(ret as usize)
    }
}

pub trait ToSocketAddrs {
    type Iter: Iterator<Item = SocketAddr>;
    fn to_socket_addrs(&self) -> io::Result<Self::Iter>;
}

impl ToSocketAddrs for (&'_ str, u16) {
    type Iter = LookupHost;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        (*self).try_into()
    }
}

pub struct LookupHost {
    original: *mut libc::addrinfo,
    cur: *mut libc::addrinfo,
    port: u16,
}

impl Iterator for LookupHost {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            unsafe {
                let cur = self.cur.as_ref()?;
                self.cur = cur.ai_next;
                match sockaddr_to_addr(cur.ai_addr.as_ref()?, cur.ai_addrlen as usize, self.port) {
                    Ok(addr) => return Some(addr),
                    Err(_) => continue,
                }
            }
        }
    }
}

impl TryFrom<(&'_ str, u16)> for LookupHost {
    type Error = io::Error;

    fn try_from((host, port): (&'_ str, u16)) -> Result<Self, Self::Error> {
        let host_c = CString::new(host.as_bytes()).map_err(|_| io::Error::InvalidInput)?;

        let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res = ptr::null_mut();

        if unsafe { libc::getaddrinfo(host_c.as_ptr(), ptr::null(), &hints, &mut res) } == 0 {
            Ok(LookupHost {
                original: res,
                cur: res,
                port,
            })
        } else {
            Err(io::Error::AddressLookup)
        }
    }
}

unsafe impl Sync for LookupHost {}
unsafe impl Send for LookupHost {}

impl Drop for LookupHost {
    fn drop(&mut self) {
        unsafe { libc::freeaddrinfo(self.original) }
    }
}

fn sockaddr_to_addr(sockaddr: &libc::sockaddr, len: usize, port: u16) -> io::Result<SocketAddr> {
    match sockaddr.sa_family as c_int {
        libc::AF_INET => {
            assert!(len >= mem::size_of::<libc::sockaddr_in>());
            let mut sock_addr = SocketAddrV4::from_inner(unsafe {
                (sockaddr as *const libc::sockaddr)
                    .cast::<libc::sockaddr_in>()
                    .read()
            });
            sock_addr.port = port;
            Ok(SocketAddr::V4(sock_addr))
        }
        // libc::AF_INET6 => unimplemented!(),
        _ => Err(io::Error::InvalidInput),
    }
}
