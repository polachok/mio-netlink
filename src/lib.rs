extern crate mio;
extern crate libc;
use std::io;
use std::os::unix::io::{AsRawFd,IntoRawFd,RawFd};
use libc::{socket, bind, send, recv};
use libc::{SOCK_DGRAM, SOCK_CLOEXEC, SOCK_NONBLOCK};

use mio::unix::EventedFd;
use mio::{Evented, Poll, Token, Ready, PollOpt};

/// supported protocols
pub enum NetlinkProtocol {
	Route = 0,
	//Unused = 1,
	Usersock = 2,
	Firewall = 3,
	InetDiag = 4,
	NFlog = 5,
	Xfrm = 6,
	SELinux = 7,
	ISCSI = 8,
	Audit = 9,
	FibLookup = 10,
	Connector = 11,
	Netfilter = 12,
	IP6Fw = 13,
	Dnrtmsg = 14,
	KObjectUevent = 15,
	Generic = 16,
	SCSItransport = 18,
	Ecryptfs = 19,
	Rdma = 20,
	Crypto = 21,
}

fn cvt(i: libc::c_int) -> io::Result<libc::c_int> {
    if i == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(i)
    }
}

struct Socket {
    fd: libc::c_int,
}

impl Socket {
    pub fn new(proto: NetlinkProtocol) -> io::Result<Socket> {
        let fd = unsafe {
            try!(cvt(socket(libc::AF_NETLINK,
                            SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                            proto as i32)))
		};
        Ok(Socket { fd: fd })
    }

	pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
		use libc::c_void;
		let len = buf.len();
		let res = unsafe {
			send(self.fd, buf.as_ptr() as *const c_void, len, 0)
		};
		if res == -1 {
			return Err(io::Error::last_os_error());
		}
		Ok(res as usize)
	}

	pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
		use libc::c_void;

		let len = buf.len();
		let res = unsafe {
			recv(self.fd, buf.as_mut_ptr() as *mut c_void, len, 0)
		};
		if res < 0 {
			return Err(io::Error::last_os_error());
		}
		Ok(res as usize)
	}
}

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.fd);
        }
    }
}

impl AsRawFd for Socket {
	fn as_raw_fd(&self) -> RawFd {
		self.fd
	}
}

impl IntoRawFd for Socket {
    fn into_raw_fd(self) -> RawFd {
        self.fd
    }
}

pub struct NetlinkDatagram {
    sock: Socket,
}

impl NetlinkDatagram {
    pub fn bind(proto: NetlinkProtocol, groups: u32) -> io::Result<NetlinkDatagram> {
		use std::mem::{self,size_of,transmute};
		use libc::getpid;
        let sock = try!(Socket::new(proto));
        let mut sockaddr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        sockaddr.nl_family = libc::AF_NETLINK as u16;
        sockaddr.nl_pid = unsafe { getpid() } as u32;
        sockaddr.nl_groups = groups;
        unsafe {
            try!(cvt(bind(sock.fd, transmute(&mut sockaddr), size_of::<libc::sockaddr_nl>() as u32)));
        }
        Ok(NetlinkDatagram { sock: sock })
    }

    /// Receives data from the socket.
    ///
    /// On success, returns the number of bytes read.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.sock.recv(buf)
    }

    /// Sends data on the socket to the socket's peer.
    ///
    /// The peer address may be set by the `bind` method, and this method
    /// will return an error if the socket has not already been connected.
    ///
    /// On success, returns the number of bytes written.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        self.sock.send(buf)
    }
}

impl AsRawFd for NetlinkDatagram {
    fn as_raw_fd(&self) -> i32 {
        self.sock.as_raw_fd()
    }
}

impl IntoRawFd for NetlinkDatagram {
    fn into_raw_fd(self) -> i32 {
        self.sock.into_raw_fd()
    }
}

impl Evented for NetlinkDatagram {
    fn register(&self,
                poll: &Poll,
                token: Token,
                events: Ready,
                opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).register(poll, token, events, opts)
    }

    fn reregister(&self,
                  poll: &Poll,
                  token: Token,
                  events: Ready,
                  opts: PollOpt) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).reregister(poll, token, events, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}
