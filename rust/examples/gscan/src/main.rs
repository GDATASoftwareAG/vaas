use clap::{Arg, ArgAction, Command};
use std::{path::PathBuf, str::FromStr, collections::HashMap};
use vaas::{error::VResult, CancellationToken, Vaas, VaasVerdict};
use reqwest::Url;

#[tokio::main]
async fn main() -> VResult<()> {
    let matches = Command::new("GDATA command line scanner")
        .version("0.1.0")
        .author("GDATA CyberDefense AG")
        .about("Scan files for malicious content")
        .arg(
            Arg::new("files")
                .short('f')
                .long("files")
                .required_unless_present("urls")
                .action(ArgAction::Append)
                .help("List of files to scan spearated by whitepace"),
        )
        .arg(
            Arg::new("urls")
                .short('u')
                .long("urls")
                .action(ArgAction::Append)
                .required_unless_present("files")
                .help("List of urls to scan spearated by whitepace"),
        )
        .arg(
            Arg::new("client_id")
                .short('i')
                .long("client_id")
                .env("CLIENT_ID")
                .action(ArgAction::Set)
                .help("Set your vaas username"),
        )
        .arg(
            Arg::new("client_secret")
                .short('s')
                .long("client_secret")
                .env("CLIENT_SECRET")
                .action(ArgAction::Set)
                .help("Set your vaas password"),
        )
        .get_matches();

    let files = matches
        .get_many::<String>("files")
        .unwrap_or_default()
        .map(|f| PathBuf::from_str(f).unwrap_or_else(|_| panic!("Not a valid file path: {}", f)))
        .collect::<Vec<PathBuf>>();

    let urls = matches
        .get_many::<String>("urls")
        .unwrap_or_default()
        .map(|f| Url::parse(f).unwrap_or_else(|_| panic!("Not a valid url: {}", f)))
        .collect::<Vec<Url>>();

    let client_id = matches.get_one::<String>("client_id").unwrap();
    let client_secret = matches.get_one::<String>("client_secret").unwrap();

    let token = Vaas::get_token(&client_id, &client_secret).await?;

    let file_verdicts = scan_files(&files, &token).await?;
    let url_verdicts = scan_urls(&urls, &token).await?;

    file_verdicts.iter().for_each(|(f, v)| {
        println!(
            "File: {:?} -> {}",
            f,
            match v {
                Ok(v) => v.verdict.to_string(),
                Err(e) => e.to_string(),
            }
        )
    });

    url_verdicts.iter().for_each(|(u, v)| {
        println!(
            "Url: {:?} -> {}",
            u.to_string(),
            match v {
                Ok(v) => v.verdict.to_string(),
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

#[allow(clippy::needless_lifetimes)] // Clippy wants to eliminate the lifetime parameter, but it's not possible.
async fn scan_urls<'a>(
    urls: &'a [Url],
    token: &str,
) -> VResult<HashMap<Url, Result<VaasVerdict, vaas::error::Error>>> {
    let vaas = Vaas::builder(token.into()).build()?.connect().await?;

    let ct = CancellationToken::from_minutes(1);
    let mut verdicts = HashMap::new();
    for url in urls {
        let verdict = vaas.for_url(url, &ct).await;
        verdicts.insert(url.to_owned(), verdict);
    }

    Ok(verdicts)
}
