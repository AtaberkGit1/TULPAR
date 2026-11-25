//! Panic-safe Android JNI bridge (`org.yolac.app.YolacNative`) using `jni` crate.
//!
//! v0.4.0 Upgrades:
//! - RAII `OwnedFd` closes TUN fd deterministically on any early error (zero kernel FD leaks)
//! - Zero-overhead `protect_fd()` fast-path when `self_app_excluded && !is_lockdown` (0 µs!)
//! - Permanent Tokio worker JVM attachment (`attach_current_thread_permanently`) when protect IS needed
//! - Non-initializing `try_get_holder()` keeps cold-start Main Thread instant
//! - `nativeStop` swaps out engine to immediately release `YolacVpnService` GlobalRef
//! - Live Rust -> Kotlin state callback (`onNativeStateChanged`) + `nativeRunDiagnosticsJson`

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex};

use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use yolac_core::{
    forge_status_to_json, health_reports_to_json, ErrorCode, YolacConfig, YolacEngine,
};
use yolac_net::SocketProtector;

struct JniVpnProtector {
    jvm: JavaVM,
    vpn_service: GlobalRef,
    self_app_excluded: bool,
    is_lockdown: bool,
}

impl SocketProtector for JniVpnProtector {
    fn protect_fd(&self, fd: i32) -> io::Result<()> {
        // Fast path: when Android UID exclusion (`addDisallowedApplication(packageName)`) succeeded
        // and VPN Lockdown is NOT active, Android's netd kernel routing ALREADY bypasses the VPN
        // for every socket owned by TULPAR -> 0 µs overhead, zero Binder IPC!
        if self.self_app_excluded && !self.is_lockdown {
            return Ok(());
        }

        // Permanent thread attachment avoids repeated JVM attach/detach overhead on Tokio workers
        let mut env = match self.jvm.attach_current_thread_permanently() {
            Ok(e) => e,
            Err(e) => {
                if self.self_app_excluded {
                    return Ok(());
                }
                return Err(io::Error::other(format!("JNI attach failed: {e}")));
            }
        };
        let res = env.call_method(
            self.vpn_service.as_obj(),
            "protect",
            "(I)Z",
            &[JValue::Int(fd)],
        );
        match res {
            Ok(v) => match v.z() {
                Ok(true) => Ok(()),
                Ok(false) if self.self_app_excluded => Ok(()),
                Ok(false) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "VpnService.protect returned false",
                )),
                Err(e) if !self.self_app_excluded => {
                    Err(io::Error::other(format!("invalid boolean return: {e}")))
                }
                Err(_) => Ok(()),
            },
            Err(e) => {
                let _ = env.exception_clear();
                if self.self_app_excluded {
                    Ok(())
                } else {
                    Err(io::Error::other(format!("VpnService.protect call failed: {e}")))
                }
            }
        }
    }
}

struct AndroidRuntimeHolder {
    rt: tokio::runtime::Runtime,
    engine: Mutex<Arc<YolacEngine>>,
}

static GLOBAL_ANDROID_RUNTIME: Mutex<Option<Arc<AndroidRuntimeHolder>>> = Mutex::new(None);

fn try_get_holder() -> Option<Arc<AndroidRuntimeHolder>> {
    let guard = GLOBAL_ANDROID_RUNTIME.lock().ok()?;
    guard.as_ref().map(Arc::clone)
}

fn get_or_init_holder() -> Option<Arc<AndroidRuntimeHolder>> {
    let mut guard = GLOBAL_ANDROID_RUNTIME.lock().ok()?;
    if let Some(h) = guard.as_ref() {
        return Some(Arc::clone(h));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .ok()?;
    let initial = Arc::new(YolacEngine::new(YolacConfig::mobile_android(), None));
    let holder = Arc::new(AndroidRuntimeHolder {
        rt,
        engine: Mutex::new(initial),
    });
    *guard = Some(Arc::clone(&holder));
    Some(holder)
}

fn new_jstring_or_empty(env: &JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .or_else(|_| env.new_string(""))
        .map(|js| js.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeStartTun(
    env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    tun_fd: jint,
    block_unprotected_ipv6: jboolean,
    self_app_excluded: jboolean,
    is_lockdown: jboolean,
) -> jboolean {
    // Take RAII ownership of tun_fd IMMEDIATELY so any early error/panic closes it cleanly!
    if tun_fd < 0 {
        return JNI_FALSE;
    }
    let owned_fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };

    catch_unwind(AssertUnwindSafe(move || {
        let Ok(jvm) = env.get_java_vm() else {
            return JNI_FALSE;
        };
        let Ok(service_ref) = env.new_global_ref(vpn_service) else {
            return JNI_FALSE;
        };
        let Some(holder) = get_or_init_holder() else {
            return JNI_FALSE;
        };

        let mut cfg = YolacConfig::mobile_android();
        if block_unprotected_ipv6 == JNI_TRUE {
            cfg.ipv6_mode = yolac_net::Ipv6LeakMode::BlockUnprotectedIpv6;
        }

        let state_service_ref = service_ref.clone();
        let state_jvm = env.get_java_vm().ok();

        let protector = Arc::new(JniVpnProtector {
            jvm,
            vpn_service: service_ref,
            self_app_excluded: self_app_excluded == JNI_TRUE,
            is_lockdown: is_lockdown == JNI_TRUE,
        });
        let engine = Arc::new(YolacEngine::new(cfg, Some(protector)));

        let _rt_guard = holder.rt.enter();
        let Ok(dev) = crate::UnixTunFdDevice::from_owned_fd(owned_fd) else {
            return JNI_FALSE;
        };
        let dev = Arc::new(dev);

        // Swap new engine into holder FIRST so stale forwarder checks `Arc::ptr_eq` accurately
        let prev_engine = holder
            .engine
            .lock()
            .ok()
            .map(|mut g| std::mem::replace(&mut *g, Arc::clone(&engine)));
        if let Some(old) = prev_engine {
            engine
                .health_monitor()
                .carry_update_state_from(old.health_monitor());
            holder.rt.block_on(old.stop());
        }

        if holder.rt.block_on(engine.start_tun(dev)).is_err() {
            return JNI_FALSE;
        }

        // Propagate unexpected engine death/state changes back to Kotlin YolacVpnService,
        // ignoring events once this engine has been superseded by a newer `nativeStartTun`!
        if let Some(cb_jvm) = state_jvm {
            let mut rx = engine.subscribe_state();
            let weak_eng = Arc::downgrade(&engine);
            let holder_ref = Arc::clone(&holder);
            holder.rt.spawn(async move {
                while rx.changed().await.is_ok() {
                    let Some(strong_eng) = weak_eng.upgrade() else {
                        break;
                    };
                    let still_current = holder_ref
                        .engine
                        .lock()
                        .map(|g| Arc::ptr_eq(&*g, &strong_eng))
                        .unwrap_or(false);
                    if !still_current {
                        break;
                    }
                    let st = rx.borrow().as_u8() as jint;
                    if let Ok(mut cb_env) = cb_jvm.attach_current_thread_permanently() {
                        let res = cb_env.call_method(
                            state_service_ref.as_obj(),
                            "onNativeStateChanged",
                            "(I)V",
                            &[JValue::Int(st)],
                        );
                        if res.is_err() {
                            let _ = cb_env.exception_clear();
                        }
                    }
                }
            });
        }

        JNI_TRUE
    }))
    .unwrap_or(JNI_FALSE)
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(holder) = try_get_holder() {
            let fresh_inactive = Arc::new(YolacEngine::new(YolacConfig::mobile_android(), None));
            let old_opt = holder.engine.lock().ok().map(|mut g| {
                fresh_inactive
                    .health_monitor()
                    .carry_update_state_from(g.health_monitor());
                std::mem::replace(&mut *g, fresh_inactive)
            });
            if let Some(old_engine) = old_opt {
                // Stopping and dropping `old_engine` immediately releases `YolacVpnService` GlobalRef!
                holder.rt.block_on(old_engine.stop());
            }
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeGetState(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    catch_unwind(AssertUnwindSafe(|| {
        // Never spin up Tokio runtime on cold-start MainActivity.onResume()!
        if let Some(holder) = try_get_holder() {
            if let Ok(guard) = holder.engine.lock() {
                return guard.state().as_u8() as jint;
            }
        }
        0
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeNotifyNetworkChange(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(holder) = try_get_holder() {
            let _rt_guard = holder.rt.enter();
            if let Ok(guard) = holder.engine.lock() {
                guard.notify_network_change();
            }
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeSetDynamicIpv6Block(
    _env: JNIEnv,
    _class: JClass,
    block: jboolean,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(holder) = try_get_holder() {
            if let Ok(guard) = holder.engine.lock() {
                guard.set_dynamic_ipv6_block(block == JNI_TRUE);
            }
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeGetHealthJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        // Never spawn Tokio runtime / parse full blocklist synchronously on Android UI thread before start!
        let json = if let Some(holder) = try_get_holder() {
            if let Ok(guard) = holder.engine.lock() {
                health_reports_to_json(&guard.health_snapshot())
            } else {
                "[]".to_string()
            }
        } else {
            "[{\"id\":0,\"name\":\"Akıllı Koruma\",\"status\":0,\"detail\":\"Koruma kapalı.\"},{\"id\":1,\"name\":\"DNS Koruması\",\"status\":0,\"detail\":\"Beklemede.\"},{\"id\":2,\"name\":\"Reklam ve Takip Engelleme\",\"status\":0,\"detail\":\"Beklemede.\"},{\"id\":3,\"name\":\"Gelişmiş Sansür Aşma\",\"status\":0,\"detail\":\"Beklemede.\"},{\"id\":4,\"name\":\"Bağlantı Güvenliği\",\"status\":0,\"detail\":\"Beklemede.\"},{\"id\":5,\"name\":\"Performans\",\"status\":0,\"detail\":\"Beklemede.\"},{\"id\":6,\"name\":\"Güncellemeler\",\"status\":0,\"detail\":\"Henüz kontrol edilmedi.\"}]".to_string()
        };
        new_jstring_or_empty(&env, &json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeCheckUpdatesJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = if let Some(holder) = get_or_init_holder() {
            let eng = holder.engine.lock().ok().map(|g| Arc::clone(&g));
            if let Some(engine) = eng {
                holder.rt.block_on(engine.check_updates_manual(None)).to_json()
            } else {
                "{\"status\":\"error\",\"message\":\"Motor hazır değil.\",\"release_url\":\"\"}".into()
            }
        } else {
            "{\"status\":\"error\",\"message\":\"Çalışma zamanı başlatılamadı.\",\"release_url\":\"\"}".into()
        };
        new_jstring_or_empty(&env, &json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeRunDiagnosticsJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = if let Some(holder) = get_or_init_holder() {
            let eng = holder.engine.lock().ok().map(|g| Arc::clone(&g));
            if let Some(engine) = eng {
                holder.rt.block_on(engine.run_live_diagnostics()).to_json()
            } else {
                "{\"ok\":false,\"summary\":\"Motor hazır değil.\"}".into()
            }
        } else {
            "{\"ok\":false,\"summary\":\"Çalışma zamanı başlatılamadı.\"}".into()
        };
        new_jstring_or_empty(&env, &json)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeReportPlatformError(
    _env: JNIEnv,
    _class: JClass,
    error_code: jint,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(holder) = get_or_init_holder() {
            if let Ok(guard) = holder.engine.lock() {
                let code = match error_code {
                    1 => ErrorCode::PermissionDenied,
                    2 => ErrorCode::TunSetupFailed,
                    3 => ErrorCode::DriverMissing,
                    4 => ErrorCode::AlreadyRunning,
                    _ => ErrorCode::InternalError,
                };
                guard.record_platform_error(code);
            }
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeLoadForgePackage(
    env: JNIEnv,
    _class: JClass,
    package_bytes: JByteArray,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let ok = if let Ok(bytes) = env.convert_byte_array(&package_bytes) {
            if let Some(holder) = get_or_init_holder() {
                if let Ok(guard) = holder.engine.lock() {
                    match guard.load_forge_package_bytes(&bytes) {
                        Ok(_) => forge_status_to_json(&guard.forge_status()),
                        Err(e) => {
                            let esc = e.replace('\\', "\\\\").replace('"', "\\\"");
                            format!("{{\"status\":\"error\",\"reason\":\"{esc}\"}}")
                        }
                    }
                } else {
                    "{\"status\":\"error\",\"reason\":\"engine_lock_failed\"}".into()
                }
            } else {
                "{\"status\":\"error\",\"reason\":\"runtime_init_failed\"}".into()
            }
        } else {
            "{\"status\":\"error\",\"reason\":\"invalid_byte_array\"}".into()
        };
        new_jstring_or_empty(&env, &ok)
    }))
    .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeUnloadForgePackage(
    _env: JNIEnv,
    _class: JClass,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(holder) = try_get_holder() {
            if let Ok(guard) = holder.engine.lock() {
                guard.unload_forge_package();
            }
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeGetForgeStatusJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    catch_unwind(AssertUnwindSafe(|| {
        let json = if let Some(holder) = try_get_holder() {
            if let Ok(guard) = holder.engine.lock() {
                forge_status_to_json(&guard.forge_status())
            } else {
                "{\"status\":\"baseline\"}".into()
            }
        } else {
            "{\"status\":\"baseline\"}".into()
        };
        new_jstring_or_empty(&env, &json)
    }))
    .unwrap_or(std::ptr::null_mut())
}
