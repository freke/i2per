//! `i2per_tun_nif` — the Rust NIF that owns the Linux TUN device file
//! descriptor (spike for epiq `D3750BZ`).
//!
//! One resource object wraps one `/dev/net/tun` descriptor opened with
//! `TUNSETIFF` (`IFF_TUN | IFF_NO_PI`), kept **non-blocking**. Read readiness
//! is delivered to an Erlang process through `enif_select` with a custom
//! message, so no scheduler — regular or dirty — ever blocks on the device.
//!
//! Rust is the crash story the maintainer asked for on `D3750BZ`: every entry
//! point runs inside `catch_unwind`, so a panic in this crate surfaces as
//! `{error, nif_panic}` instead of undefined behaviour in the VM. That
//! containment only holds because the crate stays on the default unwind
//! panic strategy (see `Cargo.toml`).
//!
//! Spike grade, said plainly: this is the fd-mechanics probe, not the
//! production device layer. The destructor closes the fd without a guaranteed
//! stop-before-close, which leaves a small fd-reuse window if a resource is
//! GC'd while still selected; the production pass must close only from the
//! stop callback (`ERL_NIF_SELECT_STOP`) and deselect explicitly on every
//! other path.

#![allow(non_snake_case)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use libc::{c_char, c_int, c_uint, c_ulong, c_void};
// `enif_make_tuple!` is a #[macro_export] macro at the crate root, so it does
// not ride along with the `rustler_sys_api` glob.
use rustler_sys::enif_make_tuple;
use rustler_sys::rustler_sys_api::*;

// ---- Linux UAPI the libc crate does not carry (/usr/include/linux/if_tun.h) ----

const TUNSETIFF: c_ulong = 0x4004_54CA;
const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
/// IFNAMSIZ: device-name buffer including the terminating NUL.
const IFNAMSIZ: usize = 16;
/// Generous single-read buffer: TUN delivers one IP packet per read, and the
/// spike does not assume an MTU.
const MAX_PKT: usize = 65_536;

/// `struct ifreq` as the TUNSETIFF ioctl needs it: 16-byte name, then the
/// 24-byte `ifr_ifru` union whose first member is the flags short.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: i16,
    pad: [u8; 22],
}

// ---- enif_select request flags and return bits, OTP 27/28 ----
//
// rustler_sys_api's hand-written constants predate the OTP 27 change that
// moved these, so they are re-declared here from the headers the NIF actually
// builds against: request flags from erl_drv_nif.h, return bits from
// erl_nif.h ("Return bits from enif_select").

const SEL_READ: ErlNifSelectFlags = 1; // ERL_NIF_SELECT_READ
const SEL_STOP: ErlNifSelectFlags = 4; // ERL_NIF_SELECT_STOP
const SEL_CUSTOM_MSG: ErlNifSelectFlags = 16; // ERL_NIF_SELECT_CUSTOM_MSG
const RET_INVALID_EVENT: ErlNifSelectFlags = 4;
const RET_FAILED: ErlNifSelectFlags = 8;
const RET_NOTSUP: ErlNifSelectFlags = 128;

// ---- resource ----

/// The TUN device behind one resource object. The fd is atomic because the
/// stop callback may run on a dirty scheduler while the owning process is in
/// `read`/`write`.
struct TunDev {
    fd: AtomicI32,
}

static RES_TYPE: AtomicPtr<ErlNifResourceType> = AtomicPtr::new(std::ptr::null_mut());

fn res_type() -> *mut ErlNifResourceType {
    RES_TYPE.load(Ordering::Acquire)
}

/// `ErlNifEntry` as OTP 27/28 define it, 13 fields ending in `min_erts`.
/// rustler_sys's own struct predates `min_erts` (added in NIF API 2.14), and a
/// short entry struct would be read past by the VM — hence a local copy
/// instead.
#[repr(C)]
pub struct NifEntry {
    major: c_int,
    minor: c_int,
    name: *const c_char,
    num_of_funcs: c_int,
    funcs: *mut ErlNifFunc,
    load: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut *mut c_void, ERL_NIF_TERM) -> c_int>,
    reload: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut *mut c_void, ERL_NIF_TERM) -> c_int>,
    upgrade:
        Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut *mut c_void, *mut *mut c_void, ERL_NIF_TERM) -> c_int>,
    unload: Option<unsafe extern "C" fn(*mut ErlNifEnv, *mut c_void)>,
    vm_variant: *const c_char,
    options: c_uint,
    sizeof_ErlNifResourceTypeInit: usize,
    min_erts: *const c_char,
}

// ---- NIF entry point ----

/// The symbol OTP's dynamic loader resolves (the `ERL_NIF_INIT` macro's
/// non-Windows, non-static expansion). `Box::leak` gives the entry a
/// `'static` funcs table; a plain static would need a manual `Sync` impl for
/// the raw pointers inside `ErlNifFunc`.
///
/// The entry's `name` is `i2per_tun_tun`, not this crate: OTP 26+ checks the
/// library name against the *calling module* — the one whose `on_load` runs
/// `erlang:load_nif/2` — and that module is the facade.
#[no_mangle]
pub extern "C" fn nif_init() -> *mut NifEntry {
    let funcs: &'static mut [ErlNifFunc; 6] = Box::leak(Box::new([
        ErlNifFunc {
            name: b"version\0".as_ptr() as *const c_char,
            arity: 0,
            function: nif_version,
            flags: 0,
        },
        ErlNifFunc {
            name: b"open\0".as_ptr() as *const c_char,
            arity: 1,
            function: nif_open,
            flags: 0,
        },
        ErlNifFunc {
            name: b"read\0".as_ptr() as *const c_char,
            arity: 1,
            function: nif_read,
            flags: 0,
        },
        ErlNifFunc {
            name: b"write\0".as_ptr() as *const c_char,
            arity: 2,
            function: nif_write,
            flags: 0,
        },
        ErlNifFunc {
            name: b"arm\0".as_ptr() as *const c_char,
            arity: 2,
            function: nif_arm,
            flags: 0,
        },
        ErlNifFunc {
            name: b"stop\0".as_ptr() as *const c_char,
            arity: 1,
            function: nif_stop,
            flags: 0,
        },
    ]));
    Box::into_raw(Box::new(NifEntry {
        major: 2,
        minor: 17,
        name: b"i2per_tun_tun\0".as_ptr() as *const c_char,
        num_of_funcs: funcs.len() as c_int,
        funcs: funcs.as_mut_ptr(),
        load: Some(nif_load),
        reload: None,
        upgrade: None,
        unload: None,
        vm_variant: b"beam.vanilla\0".as_ptr() as *const c_char,
        options: 1, // ERL_NIF_DIRTY_NIF_OPTION: this NIF may use dirty schedulers
        sizeof_ErlNifResourceTypeInit: std::mem::size_of::<ErlNifResourceTypeInit>(),
        min_erts: b"erts-14.0\0".as_ptr() as *const c_char,
    }))
}

/// `members: 2` = dtor + stop are used; `stop` is where `ERL_NIF_SELECT_STOP`
/// lands on this OTP line (the separate `select` member is gone in OTP 27+).
unsafe extern "C" fn nif_load(
    env: *mut ErlNifEnv,
    _priv_data: *mut *mut c_void,
    _load_info: ERL_NIF_TERM,
) -> c_int {
    let init = ErlNifResourceTypeInit {
        dtor: res_dtor as *const ErlNifResourceDtor,
        stop: res_stop as *const ErlNifResourceStop,
        down: std::ptr::null(),
        members: 2,
        dyncall: std::ptr::null(),
    };
    let ty = enif_open_resource_type_x(
        env,
        b"i2per_tun_dev\0".as_ptr() as *const c_char,
        &init,
        ErlNifResourceFlags::ERL_NIF_RT_CREATE,
        std::ptr::null_mut(),
    );
    if ty.is_null() {
        return -1;
    }
    RES_TYPE.store(ty as *mut ErlNifResourceType, Ordering::Release);
    0
}

// ---- lifecycle callbacks ----

/// Spike-grade close (see the crate doc): the fd-reuse window is known and
/// deferred to the production pass.
unsafe extern "C" fn res_dtor(_env: *mut ErlNifEnv, obj: *mut c_void) {
    let dev = &*(obj as *mut TunDev);
    let fd = dev.fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        libc::close(fd);
    }
}

/// Stop delivery for `enif_select`. Runs on a dirty scheduler when the runtime
/// tears the monitor down; the fd close happens here so a selected fd is never
/// silently leaked.
unsafe extern "C" fn res_stop(
    _env: *mut ErlNifEnv,
    obj: *mut c_void,
    _event: ErlNifEvent,
    _is_direct_call: c_int,
) {
    let dev = &*(obj as *mut TunDev);
    let fd = dev.fd.swap(-1, Ordering::AcqRel);
    if fd >= 0 {
        libc::close(fd);
    }
}

// ---- panic containment ----

/// Every exported entry point goes through here: a panic becomes
/// `{error, nif_panic}` rather than an abort inside the VM.
unsafe fn guard<F>(env: *mut ErlNifEnv, f: F) -> ERL_NIF_TERM
where
    F: FnOnce() -> ERL_NIF_TERM,
{
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(term) => term,
        Err(_) => {
            let err = make_atom(env, "error");
            let atom = make_atom(env, "nif_panic");
            enif_make_tuple!(env, 2, err, atom)
        }
    }
}

// ---- term helpers ----

unsafe fn make_atom(env: *mut ErlNifEnv, name: &str) -> ERL_NIF_TERM {
    let c = std::ffi::CString::new(name).unwrap_or_default();
    enif_make_atom(env, c.as_ptr() as *const u8)
}

unsafe fn make_ok(env: *mut ErlNifEnv) -> ERL_NIF_TERM {
    make_atom(env, "ok")
}

unsafe fn make_error(env: *mut ErlNifEnv, reason: ERL_NIF_TERM) -> ERL_NIF_TERM {
    let err = make_atom(env, "error");
    enif_make_tuple!(env, 2, err, reason)
}

/// Map the C errno to an Erlang posix atom where a stable name exists, else
/// `{errno, N}`.
unsafe fn errno_term(env: *mut ErlNifEnv) -> ERL_NIF_TERM {
    let e = *libc::__errno_location();
    let name = match e {
        libc::EACCES => "eacces",
        libc::EPERM => "eperm",
        libc::EAGAIN => "eagain",
        libc::EBUSY => "ebusy",
        libc::EINVAL => "einval",
        libc::ENODEV => "enodev",
        libc::ENOENT => "enoent",
        libc::EMFILE | libc::ENFILE => "emfile",
        libc::ENXIO => "enxio",
        libc::ENOTTY => "enotty",
        _ => {
            let tag = make_atom(env, "errno");
            let n = enif_make_int(env, e);
            return make_error(env, enif_make_tuple!(env, 2, tag, n));
        }
    };
    make_error(env, make_atom(env, name))
}

// ---- resource access ----

/// The device behind a resource term, or `None` for junk (→ badarg).
unsafe fn dev_of(env: *mut ErlNifEnv, term: ERL_NIF_TERM) -> Option<*mut TunDev> {
    let ty = res_type();
    if ty.is_null() {
        return None;
    }
    let mut obj: *const c_void = std::ptr::null();
    if enif_get_resource(env, term, ty as *const ErlNifResourceType, &mut obj) == 0 {
        return None;
    }
    Some(obj as *mut TunDev)
}

unsafe fn live_fd(dev: &TunDev) -> Option<c_int> {
    let fd = dev.fd.load(Ordering::Acquire);
    if fd < 0 {
        None
    } else {
        Some(fd)
    }
}

// ---- exported functions ----

unsafe extern "C" fn nif_version(
    env: *mut ErlNifEnv,
    _argc: c_int,
    _argv: *const ERL_NIF_TERM,
) -> ERL_NIF_TERM {
    guard(env, || {
        let text = b"i2per_tun_nif 0.1.0 spike\0";
        let n = text.len() - 1;
        let mut term: ERL_NIF_TERM = 0;
        let out = enif_make_new_binary(env, n, &mut term);
        std::ptr::copy_nonoverlapping(text.as_ptr(), out, n);
        term
    })
}

/// `open(Name) -> {ok, Dev} | {error, Reason}`.
///
/// Opens `/dev/net/tun`, claims the interface `Name` with TUNSETIFF and leaves
/// it non-blocking. Needs CAP_NET_ADMIN; without it the errno surfaces as
/// `eacces`/`eperm` and the caller decides what a failed start means.
unsafe extern "C" fn nif_open(
    env: *mut ErlNifEnv,
    _argc: c_int,
    argv: *const ERL_NIF_TERM,
) -> ERL_NIF_TERM {
    guard(env, || {
        let mut name: ErlNifBinary = std::mem::zeroed();
        if enif_inspect_binary(env, *argv, &mut name) == 0 {
            return enif_make_badarg(env);
        }
        if name.size == 0 || name.size as usize >= IFNAMSIZ {
            return make_error(env, make_atom(env, "einval"));
        }

        let fd = libc::open(
            b"/dev/net/tun\0".as_ptr() as *const c_char,
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
        );
        if fd < 0 {
            return errno_term(env);
        }

        let mut req = IfReq {
            name: [0; IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            pad: [0; 22],
        };
        std::ptr::copy_nonoverlapping(name.data, req.name.as_mut_ptr(), name.size);
        if libc::ioctl(fd, TUNSETIFF, &mut req as *mut IfReq) < 0 {
            // `close` overwrites errno, so keep the ioctl's for the report.
            let saved = *libc::__errno_location();
            libc::close(fd);
            *libc::__errno_location() = saved;
            return errno_term(env);
        }

        let ty = res_type();
        if ty.is_null() {
            libc::close(fd);
            return make_error(env, make_atom(env, "enoload"));
        }
        let obj = enif_alloc_resource(ty as *const ErlNifResourceType, std::mem::size_of::<TunDev>())
            as *mut TunDev;
        if obj.is_null() {
            libc::close(fd);
            return make_error(env, make_atom(env, "enomem"));
        }
        std::ptr::write(
            obj,
            TunDev {
                fd: AtomicI32::new(fd),
            },
        );
        let term = enif_make_resource(env, obj as *const c_void);
        enif_release_resource(obj as *const c_void);
        let ok = make_atom(env, "ok");
        enif_make_tuple!(env, 2, ok, term)
    })
}

/// `read(Dev) -> {ok, Packet} | {error, Reason}`.
///
/// One TUN read, non-blocking: `eagain` simply means the queue drained and the
/// caller re-arms.
unsafe extern "C" fn nif_read(
    env: *mut ErlNifEnv,
    _argc: c_int,
    argv: *const ERL_NIF_TERM,
) -> ERL_NIF_TERM {
    guard(env, || {
        let Some(dev_ptr) = dev_of(env, *argv) else {
            return enif_make_badarg(env);
        };
        let dev = &*dev_ptr;
        let Some(fd) = live_fd(dev) else {
            return make_error(env, make_atom(env, "eclosed"));
        };
        let mut buf = [0u8; MAX_PKT];
        let n = libc::read(fd, buf.as_mut_ptr() as *mut c_void, buf.len());
        if n < 0 {
            return errno_term(env);
        }
        let n = n as usize;
        let mut term: ERL_NIF_TERM = 0;
        let out = enif_make_new_binary(env, n, &mut term);
        if n > 0 {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), out, n);
        }
        let ok = make_atom(env, "ok");
        enif_make_tuple!(env, 2, ok, term)
    })
}

/// `write(Dev, Packet) -> ok | {error, Reason}`.
///
/// TUN writes are packet-atomic; a short write cannot carry half a packet, so
/// anything short of a full write is reported rather than retried here.
unsafe extern "C" fn nif_write(
    env: *mut ErlNifEnv,
    _argc: c_int,
    argv: *const ERL_NIF_TERM,
) -> ERL_NIF_TERM {
    guard(env, || {
        let Some(dev_ptr) = dev_of(env, *argv) else {
            return enif_make_badarg(env);
        };
        let dev = &*dev_ptr;
        let mut pkt: ErlNifBinary = std::mem::zeroed();
        if enif_inspect_binary(env, *argv.add(1), &mut pkt) == 0 {
            return enif_make_badarg(env);
        }
        let Some(fd) = live_fd(dev) else {
            return make_error(env, make_atom(env, "eclosed"));
        };
        let n = libc::write(fd, pkt.data as *const c_void, pkt.size);
        if n < 0 {
            return errno_term(env);
        }
        if n as usize != pkt.size {
            return make_error(env, make_atom(env, "eshortwrite"));
        }
        make_ok(env)
    })
}

/// `arm(Dev, Pid) -> ok | {error, Reason}`.
///
/// Arms one read-readiness notification: when the fd becomes readable, the
/// runtime sends `Pid` the custom message `{i2per_tun_ready, Dev}`. One shot
/// per call — the Erlang side re-arms after draining.
unsafe extern "C" fn nif_arm(
    env: *mut ErlNifEnv,
    _argc: c_int,
    argv: *const ERL_NIF_TERM,
) -> ERL_NIF_TERM {
    guard(env, || {
        let Some(dev_ptr) = dev_of(env, *argv) else {
            return enif_make_badarg(env);
        };
        let mut pid: ErlNifPid = std::mem::zeroed();
        if enif_get_local_pid(env, *argv.add(1), &mut pid) == 0 {
            return enif_make_badarg(env);
        }
        let Some(fd) = live_fd(&*dev_ptr) else {
            return make_error(env, make_atom(env, "eclosed"));
        };

        // The message is built in the calling env; with SEL_CUSTOM_MSG the
        // runtime copies it when it fires, so nothing here outlives the call.
        let res_term = enif_make_resource(env, dev_ptr as *const c_void);
        let tag = make_atom(env, "i2per_tun_ready");
        let msg = enif_make_tuple!(env, 2, tag, res_term);
        let rc = enif_select(
            env,
            fd,
            SEL_READ | SEL_CUSTOM_MSG,
            dev_ptr as *const c_void,
            &pid,
            msg,
        );
        if rc == 0 {
            make_ok(env)
        } else if rc & (RET_INVALID_EVENT | RET_FAILED | RET_NOTSUP) != 0 {
            make_error(env, make_atom(env, "eselect"))
        } else {
            // STOP_CALLED / STOP_SCHEDULED mean the fd was already being torn
            // down; the caller sees a closed device on its next read.
            make_error(env, make_atom(env, "eclosed"))
        }
    })
}

/// `stop(Dev) -> ok | {error, Reason}`.
///
/// Requests the select stop; the actual close happens in the stop callback,
/// possibly deferred to a dirty scheduler.
unsafe extern "C" fn nif_stop(
    env: *mut ErlNifEnv,
    _argc: c_int,
    argv: *const ERL_NIF_TERM,
) -> ERL_NIF_TERM {
    guard(env, || {
        let Some(dev_ptr) = dev_of(env, *argv) else {
            return enif_make_badarg(env);
        };
        let dev = &*dev_ptr;
        let Some(fd) = live_fd(dev) else {
            return make_ok(env); // already closed
        };
        let rc = enif_select(
            env,
            fd,
            SEL_STOP,
            dev_ptr as *const c_void,
            std::ptr::null(),
            0,
        );
        if rc & (RET_FAILED | RET_NOTSUP) != 0 {
            make_error(env, make_atom(env, "eselect"))
        } else {
            make_ok(env)
        }
    })
}
