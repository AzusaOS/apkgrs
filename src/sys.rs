//! The handful of Linux syscalls std does not wrap (mount, signals, rlimit,
//! fd passing), issued directly with inline assembly so no libc is needed.
//! This works identically on `*-linux-gnu`, `*-linux-musl` and the libc-free
//! `x86_64-unknown-linux-fullrust` target.

#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;

#[cfg(all(
    any(target_os = "linux", target_os = "fullrust"),
    target_arch = "x86_64"
))]
mod arch {
    pub const MOUNT: usize = 165;
    pub const UMOUNT2: usize = 166;
    pub const GETUID: usize = 102;
    pub const GETGID: usize = 104;
    pub const GETEUID: usize = 107;
    pub const RT_SIGPROCMASK: usize = 14;
    pub const SIGNALFD4: usize = 289;
    pub const FCNTL: usize = 72;
    pub const RECVMSG: usize = 47;
    pub const PRLIMIT64: usize = 302;
    pub const IOCTL: usize = 16;

    #[inline]
    pub unsafe fn syscall6(n: usize, a: [usize; 6]) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") n as isize => ret,
                in("rdi") a[0], in("rsi") a[1], in("rdx") a[2],
                in("r10") a[3], in("r8") a[4], in("r9") a[5],
                lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        ret
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "fullrust"),
    target_arch = "aarch64"
))]
mod arch {
    pub const MOUNT: usize = 40;
    pub const UMOUNT2: usize = 39;
    pub const GETUID: usize = 174;
    pub const GETGID: usize = 176;
    pub const GETEUID: usize = 175;
    pub const RT_SIGPROCMASK: usize = 135;
    pub const SIGNALFD4: usize = 74;
    pub const FCNTL: usize = 25;
    pub const RECVMSG: usize = 212;
    pub const PRLIMIT64: usize = 261;
    pub const IOCTL: usize = 29;

    #[inline]
    pub unsafe fn syscall6(n: usize, a: [usize; 6]) -> isize {
        let ret: isize;
        unsafe {
            core::arch::asm!(
                "svc 0",
                inlateout("x0") a[0] as isize => ret,
                in("x1") a[1], in("x2") a[2], in("x3") a[3], in("x4") a[4], in("x5") a[5],
                in("x8") n,
                options(nostack),
            );
        }
        ret
    }
}

#[cfg(not(all(
    any(target_os = "linux", target_os = "fullrust"),
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod arch {
    pub const MOUNT: usize = 0;
    pub const UMOUNT2: usize = 0;
    pub const GETUID: usize = 0;
    pub const GETGID: usize = 0;
    pub const GETEUID: usize = 0;
    pub const RT_SIGPROCMASK: usize = 0;
    pub const SIGNALFD4: usize = 0;
    pub const FCNTL: usize = 0;
    pub const RECVMSG: usize = 0;
    pub const PRLIMIT64: usize = 0;
    pub const IOCTL: usize = 0;

    pub unsafe fn syscall6(_: usize, _: [usize; 6]) -> isize {
        -38 // ENOSYS
    }
}

fn check(r: isize) -> io::Result<usize> {
    if (-4095..0).contains(&r) {
        Err(io::Error::from_raw_os_error(-r as i32))
    } else {
        Ok(r as usize)
    }
}

/// Raw syscall with up to six arguments; negative returns become errors.
///
/// # Safety
/// The caller must pass arguments valid for syscall `n`.
pub unsafe fn syscall(n: usize, a: [usize; 6]) -> io::Result<usize> {
    check(unsafe { arch::syscall6(n, a) })
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in string"))
}

pub const MS_RDONLY: usize = 1;
pub const MS_NOSUID: usize = 2;
pub const MS_NODEV: usize = 4;
pub const MS_NOATIME: usize = 1024;
pub const MNT_DETACH: usize = 2;

/// mount(2).
pub fn mount(source: &str, target: &str, fstype: &str, flags: usize, data: &str) -> io::Result<()> {
    let (s, t, f, d) = (cstr(source)?, cstr(target)?, cstr(fstype)?, cstr(data)?);
    unsafe {
        syscall(
            arch::MOUNT,
            [
                s.as_ptr() as usize,
                t.as_ptr() as usize,
                f.as_ptr() as usize,
                flags,
                d.as_ptr() as usize,
                0,
            ],
        )
    }?;
    Ok(())
}

/// umount2(2).
pub fn umount(target: &str, flags: usize) -> io::Result<()> {
    let t = cstr(target)?;
    unsafe { syscall(arch::UMOUNT2, [t.as_ptr() as usize, flags, 0, 0, 0, 0]) }?;
    Ok(())
}

pub fn getuid() -> u32 {
    unsafe { syscall(arch::GETUID, [0; 6]) }.unwrap_or(u32::MAX as usize) as u32
}

pub fn geteuid() -> u32 {
    unsafe { syscall(arch::GETEUID, [0; 6]) }.unwrap_or(u32::MAX as usize) as u32
}

pub fn getgid() -> u32 {
    unsafe { syscall(arch::GETGID, [0; 6]) }.unwrap_or(u32::MAX as usize) as u32
}

/// Raise RLIMIT_NOFILE to `n` (soft and hard). Without the privilege to
/// raise the hard limit, the soft limit is raised as far as the hard limit
/// allows. Returns the resulting soft limit.
pub fn set_nofile_limit(n: u64) -> io::Result<u64> {
    const RLIMIT_NOFILE: usize = 7;
    let want = [n, n];
    match unsafe {
        syscall(
            arch::PRLIMIT64,
            [0, RLIMIT_NOFILE, want.as_ptr() as usize, 0, 0, 0],
        )
    } {
        Ok(_) => Ok(n),
        Err(e) if e.raw_os_error() == Some(1) => {
            let mut cur = [0u64; 2];
            unsafe {
                syscall(
                    arch::PRLIMIT64,
                    [0, RLIMIT_NOFILE, 0, cur.as_mut_ptr() as usize, 0, 0],
                )
            }?;
            let soft = n.min(cur[1]);
            let new = [soft, cur[1]];
            unsafe {
                syscall(
                    arch::PRLIMIT64,
                    [0, RLIMIT_NOFILE, new.as_ptr() as usize, 0, 0, 0],
                )
            }?;
            Ok(soft)
        }
        Err(e) => Err(e),
    }
}

/// Set FD_CLOEXEC on `fd`.
pub fn set_cloexec(fd: i32) -> io::Result<()> {
    const F_SETFD: usize = 2;
    const FD_CLOEXEC: usize = 1;
    unsafe { syscall(arch::FCNTL, [fd as usize, F_SETFD, FD_CLOEXEC, 0, 0, 0]) }?;
    Ok(())
}

/// Clear FD_CLOEXEC so `fd` survives exec.
pub fn clear_cloexec(fd: i32) -> io::Result<()> {
    const F_SETFD: usize = 2;
    unsafe { syscall(arch::FCNTL, [fd as usize, F_SETFD, 0, 0, 0, 0]) }?;
    Ok(())
}

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGUSR2: u32 = 12;
pub const SIGTERM: u32 = 15;

/// Block `signals` for the calling thread (threads spawned afterwards
/// inherit the mask) and return a signalfd delivering them.
pub fn signalfd(signals: &[u32]) -> io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    const SIG_BLOCK: usize = 0;
    const SFD_CLOEXEC: usize = 0o2000000;
    let mut mask: u64 = 0;
    for &s in signals {
        mask |= 1 << (s - 1);
    }
    unsafe {
        syscall(
            arch::RT_SIGPROCMASK,
            [SIG_BLOCK, &mask as *const u64 as usize, 0, 8, 0, 0],
        )?;
        let fd = syscall(
            arch::SIGNALFD4,
            [
                usize::MAX, /* -1 */
                &mask as *const u64 as usize,
                8,
                SFD_CLOEXEC,
                0,
                0,
            ],
        )?;
        Ok(std::fs::File::from_raw_fd(fd as i32))
    }
}

/// Read one signal number from a signalfd.
pub fn read_signal(f: &mut std::fs::File) -> io::Result<u32> {
    use std::io::Read;
    let mut info = [0u8; 128]; // struct signalfd_siginfo
    f.read_exact(&mut info)?;
    Ok(u32::from_ne_bytes(info[..4].try_into().unwrap()))
}

/// Receive one file descriptor passed with SCM_RIGHTS over a unix socket.
pub fn recv_fd(sock: i32) -> io::Result<i32> {
    #[repr(C)]
    struct IoVec {
        base: *mut u8,
        len: usize,
    }
    #[repr(C)]
    struct MsgHdr {
        name: *mut u8,
        namelen: u32,
        iov: *mut IoVec,
        iovlen: usize,
        control: *mut u8,
        controllen: usize,
        flags: i32,
    }
    const SOL_SOCKET: i32 = 1;
    const SCM_RIGHTS: i32 = 1;
    const MSG_CMSG_CLOEXEC: usize = 0x4000_0000;

    let mut data = [0u8; 1];
    let mut iov = IoVec {
        base: data.as_mut_ptr(),
        len: 1,
    };
    // cmsghdr { size_t len; int level; int type; } + int, 8-aligned
    let mut ctl = [0u64; 4];
    let mut msg = MsgHdr {
        name: std::ptr::null_mut(),
        namelen: 0,
        iov: &mut iov,
        iovlen: 1,
        control: ctl.as_mut_ptr() as *mut u8,
        controllen: std::mem::size_of_val(&ctl),
        flags: 0,
    };
    let n = loop {
        match unsafe {
            syscall(
                arch::RECVMSG,
                [
                    sock as usize,
                    &mut msg as *mut MsgHdr as usize,
                    MSG_CMSG_CLOEXEC,
                    0,
                    0,
                    0,
                ],
            )
        } {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => break r?,
        }
    };
    if n == 0 || msg.controllen < 16 + 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "no file descriptor received",
        ));
    }
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(ctl.as_ptr() as *const u8, 32) };
    let level = i32::from_ne_bytes(bytes[8..12].try_into().unwrap());
    let typ = i32::from_ne_bytes(bytes[12..16].try_into().unwrap());
    if level != SOL_SOCKET || typ != SCM_RIGHTS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected control message",
        ));
    }
    Ok(i32::from_ne_bytes(bytes[16..20].try_into().unwrap()))
}

/// Read a line from the terminal on `fd` with echo turned off (for
/// passphrases). The trailing newline is removed.
pub fn read_password(fd: i32) -> io::Result<String> {
    const TCGETS: usize = 0x5401;
    const TCSETS: usize = 0x5402;
    const ECHO: u32 = 0o10;
    // struct termios: c_iflag, c_oflag, c_cflag, c_lflag (u32 each), then
    // c_line and c_cc; 60 bytes is more than the kernel copies.
    let mut t = [0u8; 60];
    unsafe {
        syscall(
            arch::IOCTL,
            [fd as usize, TCGETS, t.as_mut_ptr() as usize, 0, 0, 0],
        )
    }?;
    let saved = t;
    let lflag = u32::from_ne_bytes(t[12..16].try_into().unwrap()) & !ECHO;
    t[12..16].copy_from_slice(&lflag.to_ne_bytes());
    unsafe {
        syscall(
            arch::IOCTL,
            [fd as usize, TCSETS, t.as_ptr() as usize, 0, 0, 0],
        )
    }?;
    let mut line = Vec::new();
    let res = (|| -> io::Result<()> {
        let mut b = [0u8; 1];
        loop {
            let n = unsafe {
                syscall(
                    arch_read(),
                    [fd as usize, b.as_mut_ptr() as usize, 1, 0, 0, 0],
                )
            }?;
            if n == 0 || b[0] == b'\n' {
                return Ok(());
            }
            line.push(b[0]);
        }
    })();
    let _ = unsafe {
        syscall(
            arch::IOCTL,
            [fd as usize, TCSETS, saved.as_ptr() as usize, 0, 0, 0],
        )
    };
    res?;
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "passphrase is not UTF-8"))
}

fn arch_read() -> usize {
    if cfg!(target_arch = "aarch64") { 63 } else { 0 }
}
