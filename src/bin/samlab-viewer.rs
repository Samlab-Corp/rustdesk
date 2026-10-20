#[cfg(windows)]
fn main() {
    std::process::exit(librustdesk::headless_viewer::run());
}
#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}
