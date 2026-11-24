use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=TULPAR_WINDIVERT_DIR");
    println!("cargo::rustc-check-cfg=cfg(has_embedded_windivert)");
    println!("cargo:rerun-if-changed=assets/tulpar.ico");
    println!("cargo:rerun-if-changed=assets/tulpar.rc");
    println!("cargo:rerun-if-changed=app.manifest");

    if let Ok(raw_dir) = std::env::var("TULPAR_WINDIVERT_DIR") {
        let dir = PathBuf::from(raw_dir);
        let dll = dir.join("WinDivert.dll");
        let sys = dir.join("WinDivert64.sys");
        if dll.is_file() && sys.is_file() {
            if let (Ok(abs_dll), Ok(abs_sys)) = (dll.canonicalize(), sys.canonicalize()) {
                println!("cargo:rerun-if-changed={}", abs_dll.display());
                println!("cargo:rerun-if-changed={}", abs_sys.display());
                println!("cargo:rustc-cfg=has_embedded_windivert");
                println!("cargo:rustc-env=TULPAR_EMBED_DLL={}", abs_dll.display());
                println!("cargo:rustc-env=TULPAR_EMBED_SYS={}", abs_sys.display());
            }
        }
    }

    // Compile and link the Windows PE application icon resource (`assets/tulpar.rc`)
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os == "windows" {
        embed_windows_icon_resource();
    }
}

fn embed_windows_icon_resource() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let rc_file = manifest_dir.join("assets").join("tulpar.rc");
    let ico_file = manifest_dir.join("assets").join("tulpar.ico");
    if !rc_file.is_file() || !ico_file.is_file() {
        return;
    }

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    if target_env == "msvc" {
        let res_out = out_dir.join("tulpar_icon.res");
        let status = Command::new("rc.exe")
            .args(["/nologo", "/fo"])
            .arg(&res_out)
            .arg(&rc_file)
            .status()
            .or_else(|_| {
                Command::new("llvm-rc")
                    .args(["/fo"])
                    .arg(&res_out)
                    .arg(&rc_file)
                    .status()
            });
        if let Ok(st) = status {
            if st.success() && res_out.is_file() {
                println!("cargo:rustc-link-arg={}", res_out.display());
            }
        }
    } else {
        // GNU / MinGW cross-compile: compile .rc -> COFF object via llvm-windres or windres
        let obj_out = out_dir.join("tulpar_icon.o");
        let candidates = windres_candidates();
        for tool in candidates {
            let status = Command::new(&tool)
                .args(["--target=pe-x86-64", "-i"])
                .arg(&rc_file)
                .args(["-O", "coff", "-o"])
                .arg(&obj_out)
                .status();
            if let Ok(st) = status {
                if st.success() && obj_out.is_file() {
                    println!("cargo:rustc-link-arg={}", obj_out.display());
                    return;
                }
            }
        }
    }
}

fn windres_candidates() -> Vec<PathBuf> {
    let mut list = vec![
        PathBuf::from("llvm-windres"),
        PathBuf::from("x86_64-w64-mingw32-windres"),
        PathBuf::from("windres"),
    ];
    if let Ok(sdk) = std::env::var("ANDROID_HOME") {
        let p = Path::new(&sdk).join("ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-windres");
        if p.is_file() {
            list.insert(0, p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = Path::new(&home).join(".local/android-sdk/ndk/27.2.12479018/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-windres");
        if p.is_file() {
            list.insert(0, p);
        }
    }
    list
}
