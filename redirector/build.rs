use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent()
        .expect("redirector is a workspace member");
    let vendor_dir = workspace_root.join("vendor").join("windivert");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR has fewer than 3 ancestors")
        .to_path_buf();

    for name in ["WinDivert.dll", "WinDivert64.sys"] {
        let src = vendor_dir.join(name);
        let dst = target_dir.join(name);
        println!("cargo:rerun-if-changed={}", src.display());
        // Refresh incremental outputs after vendor changes, without touching
        // an identical (and potentially loaded) DLL.
        if fs::read(&src).expect("read vendored WinDivert file")
            == fs::read(&dst).unwrap_or_default()
        {
            continue;
        }
        if let Err(e) = fs::copy(&src, &dst) {
            panic!(
                "failed to copy {} -> {}: {}",
                src.display(),
                dst.display(),
                e
            );
        }
    }
}
