use std::{ffi, iter};

use clap::Parser;
use serde::Serialize;
use serde_json::Value;

use crate::LightningClientModule;

#[derive(Parser, Serialize)]
enum Opts {
    GetPublicKey,
}

pub(crate) async fn handle_cli_command(
    lightning: &LightningClientModule,
    args: &[ffi::OsString],
) -> anyhow::Result<serde_json::Value> {
    let opts = Opts::parse_from(iter::once(&ffi::OsString::from("lnv2-remote")).chain(args.iter()));

    let value = match opts {
        Opts::GetPublicKey => json(unimplemented!()),
    };

    Ok(value)
}

fn json<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).expect("JSON serialization failed")
}
