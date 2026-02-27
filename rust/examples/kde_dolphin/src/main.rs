use slint::Model;
use std::{env, path::PathBuf, rc::Rc};
use structopt::StructOpt;
use vaas::{CancellationToken, Vaas};
use vaas::authentication::Password;
use vaas::options::ForFileOptions;

slint::include_modules!();

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let file_items = get_files(&opt.files);
    let file_model = Rc::new(slint::VecModel::<FileItem>::from(file_items.clone()));
    let ui = Ui::new();
    ui.on_close(move || std::process::exit(0));
    ui.set_file_model(slint::ModelRc::from(file_model));

    let handle_weak = ui.as_weak();
    ui.on_scan({
        move || {
            let authenticator = Password::try_new("vaas-customer", opt.client_username, opt.client_password).unwrap();
            let handle_weak = handle_weak.clone();
            let file_items_clone = file_items.clone();
            tokio::spawn(async move {
                let vaas = Vaas::builder(authenticator)
                    .build()
                    .expect("Failed to create VaaS client.");

                let cts = CancellationToken::new();

                let files = file_items_clone
                    .iter()
                    .map(|f| PathBuf::from(f.path.as_str()))
                    .collect::<Vec<_>>();

                let fic = file_items_clone.clone();

                file_items_clone.into_iter().for_each(|f| {
                    update_file_model(
                        handle_weak.clone(),
                        FileItem {
                            state: "scanning...".into(),
                            ..f
                        },
                    )
                });

                let mut verdicts = Vec::new();
                for file in files {
                    let verdict = vaas.for_file(&file, ForFileOptions::new(), &cts).await;
                    verdicts.push(verdict);
                }
                fic.iter().zip(verdicts).for_each(|(f, v)| {
                    update_file_model(
                        handle_weak.clone(),
                        FileItem {
                            state: match v {
                                Ok(v) => v.verdict.to_string().into(),
                                Err(e) => e.to_string().into(),
                            },
                            ..f.clone()
                        },
                    )
                });
            });
        }
    });

    ui.run();
}

fn update_file_model(handle: slint::Weak<Ui>, fi: FileItem) {
    let _ = handle.upgrade_in_event_loop(move |handle| {
        let fm = handle.get_file_model();
        fm.set_row_data((fi.id - 1) as usize, fi)
    });
}

fn get_files(files: &[String]) -> Vec<FileItem> {
    files
        .iter()
        .enumerate()
        .map(|(i, path)| FileItem {
            id: (i + 1) as i32,
            name: get_file_name(path).into(),
            path: path.into(),
            state: "queued for scanning...".into(),
        })
        .collect()
}

fn get_file_name(path: &str) -> String {
    let mut path = PathBuf::from(path);
    path.set_extension("");
    path.file_name().unwrap().to_str().unwrap().to_string()
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "GDATA File Scanner",
    about = "Scan files for malicious content."
)]
struct Opt {
    /// VaaS Username (Email)
    #[structopt(short, long)]
    client_username: String,

    /// VaaS password
    #[structopt(short, long)]
    client_password: String,

    /// Files to scan (full path)
    #[structopt(short, long)]
    files: Vec<String>,
}
