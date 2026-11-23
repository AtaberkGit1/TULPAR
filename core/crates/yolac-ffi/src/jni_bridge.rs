//! Android JNI bridge (`org.yolac.app.YolacNative`) using `jni` crate.

use std::io;
use std::sync::{Arc, Mutex};

use jni::objects::{GlobalRef, JClass, JObject, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};
use yolac_core::{health_reports_to_json, ErrorCode, YolacConfig, YolacEngine};
use yolac_net::SocketProtector;

struct JniVpnProtector {
    jvm: JavaVM,
    vpn_service: GlobalRef,
}

impl SocketProtector for JniVpnProtector {
    fn protect_fd(&self, fd: i32) -> io::Result<()> {
        let mut env = self
            .jvm
            .attach_current_thread()
            .map_err(|e| io::Error::other(format!("JNI attach failed: {e}")))?;
        let res = env
            .call_method(
                self.vpn_service.as_obj(),
                "protect",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .map_err(|e| io::Error::other(format!("VpnService.protect call failed: {e}")))?;
        let ok = res
            .z()
            .map_err(|e| io::Error::other(format!("invalid boolean return: {e}")))?;
        if ok {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "VpnService.protect returned false",
            ))
        }
    }
}

struct AndroidRuntimeHolder {
    rt: tokio::runtime::Runtime,
    engine: Mutex<Arc<YolacEngine>>,
}

static GLOBAL_ANDROID_RUNTIME: Mutex<Option<Arc<AndroidRuntimeHolder>>> = Mutex::new(None);

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

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeStartTun(
    env: JNIEnv,
    _class: JClass,
    vpn_service: JObject,
    tun_fd: jint,
    block_unprotected_ipv6: jboolean,
) -> jboolean {
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

    let protector = Arc::new(JniVpnProtector {
        jvm,
        vpn_service: service_ref,
    });
    let engine = Arc::new(YolacEngine::new(cfg, Some(protector)));
    let dev = Arc::new(crate::UnixTunFdDevice::new(tun_fd));

    let res = holder.rt.block_on(engine.start_tun(dev));
    if res.is_err() {
        return JNI_FALSE;
    }
    if let Ok(mut eng_guard) = holder.engine.lock() {
        *eng_guard = engine;
    }
    JNI_TRUE
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeStop(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Some(holder) = get_or_init_holder() {
        let eng = holder.engine.lock().ok().map(|g| Arc::clone(&g));
        if let Some(engine) = eng {
            holder.rt.block_on(engine.stop());
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeGetState(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    if let Some(holder) = get_or_init_holder() {
        if let Ok(guard) = holder.engine.lock() {
            return guard.state().as_u8() as jint;
        }
    }
    0
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeNotifyNetworkChange(
    _env: JNIEnv,
    _class: JClass,
) {
    if let Some(holder) = get_or_init_holder() {
        if let Ok(guard) = holder.engine.lock() {
            guard.notify_network_change();
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeGetHealthJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let json = if let Some(holder) = get_or_init_holder() {
        if let Ok(guard) = holder.engine.lock() {
            health_reports_to_json(&guard.health_snapshot())
        } else {
            "[]".to_string()
        }
    } else {
        "[]".to_string()
    };
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeCheckUpdatesJson(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
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
    env.new_string(json)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_yolac_app_YolacNative_nativeReportPlatformError(
    _env: JNIEnv,
    _class: JClass,
    error_code: jint,
) {
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
}
