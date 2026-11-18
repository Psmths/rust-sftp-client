//! Berkeley Mono is a commercial font, so it is not in the repository (see
//! .gitignore). When assets/fonts/BerkeleyMonoVariable-Regular.ttf is present,
//! it is built in for the file listings; otherwise they use JetBrains Mono.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(berkeley_mono)");
    // Re-check when a font is added to or removed from the folder.
    println!("cargo::rerun-if-changed=assets/fonts");
    if std::path::Path::new("assets/fonts/BerkeleyMonoVariable-Regular.ttf").exists() {
        println!("cargo::rustc-cfg=berkeley_mono");
    }
}
