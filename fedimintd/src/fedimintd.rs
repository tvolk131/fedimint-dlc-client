use fedimint_core::fedimint_build_code_version_env;
use fedimintd::Fedimintd;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    unsafe { std::env::set_var("FM_ENABLE_MODULE_LNV2_ENV", "true") };

    Fedimintd::new(fedimint_build_code_version_env!(), None)?
        .with_default_modules()?
        .run()
        .await
}
