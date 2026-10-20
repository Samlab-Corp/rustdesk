#[cfg(windows)]
fn main() {
    std::process::exit(librustdesk::headless_management::run());
}
#[cfg(not(windows))]
fn main() {
    std::process::exit(2);
}
