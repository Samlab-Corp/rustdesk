// Console subsystem is intentional: this binary never opens Flutter or Sciter.
#[cfg(target_os = "windows")]
fn main() {
    std::process::exit(librustdesk::headless_terminal::run());
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("samlab-terminal currently supports Windows only");
    std::process::exit(2);
}
