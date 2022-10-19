use clap::{App, Arg};
use std::{path::PathBuf, str::FromStr};
use vaas::{error::VResult, CancellationToken, Vaas, VaasVerdict};

#[tokio::main]
async fn main() -> VResult<()> {
    let matches = App::new("GDATA command line scanner")
        .version("0.1.0")
        .author("GDATA CyberDefense AG")
        .about("Scan files for malicious content")
        .arg(
            Arg::with_name("files")
                .short("f")
                .long("files")
                .help("List of files to scan spearated by whitepace")
                .takes_value(true)
                .multiple(true)
                .required(true),
        )
        .arg(
            Arg::with_name("token")
                .short("t")
                .long("token")
                .help("Set token with environment variable VAAS_TOKEN or with this flag")
                .takes_value(true),
        )
        .get_matches();

    let files = matches
        .values_of("files")
        .unwrap() // Safe to unwrap, as "files" is required.
        .map(|f| PathBuf::from_str(f).unwrap_or_else(|_| panic!("Not a valid file path: {}", f)))
        .collect::<Vec<PathBuf>>();

    let token = matches.value_of("token");

    let token_env = dotenv::var("VAAS_TOKEN");

    let token = match token {
        Some(token) => token.to_string(),
        None => match token_env {
            Ok(token_env) => token_env,
            Err(_) => panic!("Please set token."),
        },
    };

    let verdicts = scan_files(&files, &token).await?;

    verdicts.iter().for_each(|(f, v)| {
        println!(
            "File: {:?} -> {}",
            f,
            match v {
                Ok(v) => v.Verdict.to_string(),
                Err(e) => e.to_string(),
            }
        )
    });

    Ok(())
}

#[allow(clippy::needless_lifetimes)] // Clippy wants to eliminate the lifetime parameter, but it's not possible.
async fn scan_files<'a>(
    files: &'a [PathBuf],
    token: &str,
) -> VResult<Vec<(&'a PathBuf, VResult<VaasVerdict>)>> {
    let vaas = Vaas::builder(token.into()).build()?.connect().await?;

    let ct = CancellationToken::from_minutes(1);
    let verdicts = vaas.for_file_list(files, &ct).await;
    let results = files.iter().zip(verdicts).collect();

    Ok(results)
}
