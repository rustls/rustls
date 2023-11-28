// the `libc` crate (as of version 0.2.149) is empty for the `x86_64-unknown-none` target
// all these values / types are only valid on x86_64 Linux + GNU libc
// this code is based on libc v0.2.149

#![allow(non_camel_case_types)]

use core::ffi::{c_char, c_int, c_uint, c_void};

pub const AF_INET: c_int = 2;
pub const EINTR: c_int = 4;
pub const GRND_RANDOM: c_uint = 0x0002;
pub const MSG_NOSIGNAL: c_int = 0x4000;
pub const O_CLOEXEC: c_int = 0x80000;
pub const O_RDONLY: c_int = 0;
pub const SOCK_CLOEXEC: c_int = O_CLOEXEC;
pub const SOCK_STREAM: c_int = 1;
pub const SOL_SOCKET: c_int = 1;
pub const SO_REUSEADDR: c_int = 2;

type size_t = usize;
type ssize_t = isize;

pub type sa_family_t = u16;
pub type socklen_t = u32;
type in_addr_t = u32;
type in_port_t = u16;
type suseconds_t = i64;
type time_t = i64;

#[repr(C)]
pub struct addrinfo {
    pub ai_flags: c_int,
    pub ai_family: c_int,
    pub ai_socktype: c_int,
    pub ai_protocol: c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut c_char,
    pub ai_next: *mut addrinfo,
}

#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}

#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [c_char; 14],
}

#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [u8; 8],
}

#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    #[cfg(target_pointer_width = "32")]
    __ss_pad2: [u8; 128 - 2 - 4],
    #[cfg(target_pointer_width = "64")]
    __ss_pad2: [u8; 128 - 2 - 8],
    __ss_align: size_t,
}

#[repr(C)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

pub enum timezone {}

extern "C" {
    #[must_use]
    pub fn __errno_location() -> *mut c_int;
    pub fn abort() -> !;
    #[must_use]
    pub fn accept4(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t, flag: c_int) -> c_int;
    #[must_use]
    pub fn bind(socket: c_int, address: *const sockaddr, address_len: socklen_t) -> c_int;
    #[must_use]
    pub fn calloc(nmemb: size_t, size: size_t) -> *mut c_void;
    #[must_use]
    pub fn connect(socket: c_int, address: *const sockaddr, address_len: socklen_t) -> c_int;
    pub fn exit(status: c_int) -> !;
    pub fn free(ptr: *mut c_void);
    pub fn freeaddrinfo(rest: *mut addrinfo);
    #[must_use]
    pub fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> c_int;
    #[must_use]
    pub fn getrandom(buf: *mut c_void, buflen: size_t, flags: c_uint) -> ssize_t;
    #[must_use]
    pub fn gettimeofday(tp: *mut timeval, tzp: *mut timezone) -> c_int;
    #[must_use]
    pub fn listen(socket: c_int, backlog: c_int) -> c_int;
    #[must_use]
    pub fn malloc(size: size_t) -> *mut c_void;
    #[must_use]
    pub fn open64(path: *const c_char, oflag: c_int) -> c_int;
    #[must_use]
    pub fn posix_memalign(memptr: *mut *mut c_void, alignment: size_t, size: size_t) -> c_int;
    #[must_use]
    pub fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t;
    #[must_use]
    pub fn realloc(ptr: *mut c_void, size: size_t) -> *mut c_void;
    #[must_use]
    pub fn recv(socket: c_int, buffer: *mut c_void, length: size_t, flags: c_int) -> ssize_t;
    #[must_use]
    pub fn send(socket: c_int, buffer: *const c_void, length: size_t, flags: c_int) -> ssize_t;
    #[must_use]
    pub fn setsockopt(
        socket: c_int,
        level: c_int,
        name: c_int,
        value: *const c_void,
        option_len: socklen_t,
    ) -> c_int;
    #[must_use]
    pub fn socket(domain: c_int, type_: c_int, protocol: c_int) -> c_int;
    #[must_use]
    pub fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t;
}
