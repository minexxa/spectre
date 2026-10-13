pub mod mixed;
pub mod target;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod tproxy;

pub use target::Target;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub mod tproxy {
    use crate::app::router::Router;
    use crate::config::Config;
    use anyhow::{bail, Result};
    use std::sync::Arc;

    pub async fn run_tproxy(_cfg: Arc<Config>, _router: Arc<Router>) -> Result<()> {
        bail!("tproxy is only supported on Linux/Android");
    }
}
