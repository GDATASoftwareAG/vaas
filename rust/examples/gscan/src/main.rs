use clap::{command, Parser};
use dotenv::dotenv;
use futures::{stream, Stream, StreamExt};
use reqwest::Url;
use std::{collections::HashMap, path::PathBuf};
use tokio::task::spawn_blocking;
use vaas::{
    auth::authenticators::ClientCredentials, error::VResult, CancellationToken, Connection, Vaas,
    VaasVerdict,
};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(
        short = 'i',
        long = "client_id",
        env = "CLIENT_ID",
        help = "Set your VaaS client ID"
    )]
    client_id: String,

    #[arg(
        short = 's',
        long = "client_secret",
        env = "CLIENT_SECRET",
        help("Set your VaaS client secret")
    )]
    client_secret: String,

    #[arg(long, help = "Lookup the SHA256 hash")]
    use_hash_lookup: bool,

    #[arg(long, help = "Use the cache")]
    use_cache: bool,

    #[arg(
        short = 'f',
        long,
        num_args=1..,
        required_unless_present("urls"),
        help = "List of files to scan separated by whitepace"
    )]
    files: Vec<PathBuf>,

    #[arg(
        short = 'u',
        long,
        num_args=1..,
        required_unless_present("files"),
        help = "List of urls to scan separated by whitepace"
    )]
    urls: Vec<Url>,
}

#[tokio::main]
async fn main() -> VResult<()> {
    console_subscriber::init();

    dotenv().ok();
    let args = Args::parse();

    let files = expand_directories(&args.files);

    let authenticator = ClientCredentials::new(args.client_id.clone(), args.client_secret.clone());
    let vaas_connection = Vaas::builder(authenticator)
        .use_hash_lookup(args.use_hash_lookup)
        .use_cache(args.use_cache)
        .build()?
        .connect()
        .await?;

    let file_verdicts = scan_files(files.into_iter(), &vaas_connection);
    let url_verdicts = scan_urls(args.urls.as_ref(), &vaas_connection).await?;

    file_verdicts
        .for_each_concurrent(8, |(f, v)| async move {
            print_verdicts(f.display().to_string(), &v);
        })
        .await;

    url_verdicts.iter().for_each(|(u, v)| {
        print_verdicts(u, v);
        // ready(())
    });

    Ok(())
}

fn print_verdicts<I: AsRef<str>>(i: I, v: &VResult<VaasVerdict>) {
    print!("{} -> ", i.as_ref());
    match v {
        Ok(v) => {
            println!("{}", v.verdict);
        }
        Err(e) => {
            println!("{}", e);
        }
    };
}

fn scan_files<'a, I>(
    files: I,
    vaas_connection: &'a Connection,
) -> impl Stream<Item = (PathBuf, VResult<VaasVerdict>)> + 'a
where
    I: Iterator<Item = PathBuf> + 'a,
{
    stream::iter(files).then(move |p: PathBuf| async move {
        let ct = CancellationToken::from_minutes(1);
        println!("Start {}", p.display());
        let verdict = vaas_connection.for_file(&p, &ct).await;
        println!("Stop {}", p.display());
        (p, verdict)
    })
}

async fn scan_urls(
    urls: &[Url],
    vaas_connection: &Connection,
) -> VResult<HashMap<Url, Result<VaasVerdict, vaas::error::Error>>> {
    let ct = CancellationToken::from_minutes(1);
    let mut verdicts = HashMap::new();
    for url in urls {
        let verdict = vaas_connection.for_url(url, &ct).await;
        verdicts.insert(url.to_owned(), verdict);
    }

    Ok(verdicts)
}

fn expand_directories(files: &[PathBuf]) -> impl Iterator<Item = PathBuf> + '_ {
    files.iter().flat_map(expand_entry)
}

fn expand_entry(p: &PathBuf) -> Box<dyn Iterator<Item = PathBuf>> {
    if p.is_file() {
        return Box::new(std::iter::once(p.clone()));
    }

    let files_in_directory = WalkDir::new(p)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf());

    Box::new(files_in_directory)
}
