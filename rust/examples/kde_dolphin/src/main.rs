use sixtyfps::Model;
use std::{env, path::PathBuf, rc::Rc, time::Duration};
use structopt::StructOpt;
use vaas::{CancellationTokenSource, Vaas};
sixtyfps::include_modules!();

#[tokio::main]
async fn main() {
    let opt = Opt::from_args();
    let file_items = get_files(&opt.files);
    let file_model = Rc::new(sixtyfps::VecModel::<FileItem>::from(file_items.clone()));
    let ui = Ui::new();
    ui.on_close(move || std::process::exit(0));
    ui.set_file_model(sixtyfps::ModelHandle::new(file_model));

    let handle_weak = ui.as_weak();
    ui.on_scan({
        move || {
            let vaas_token = opt.token.clone();
            let handle_weak = handle_weak.clone();
            let file_items_clone = file_items.clone();
            tokio::spawn(async move {
                let vaas = Vaas::builder(vaas_token)
                    .build()
                    .expect("Failed to create VaaS client.") // TODO: Show error to user.
                    .connect()
                    .await
                    .expect("Failed to connect to VaaS.");

                let cts = CancellationTokenSource::new();
                cts.cancel_after(Duration::from_secs(60 * 5));

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

                let verdicts = vaas.for_file_list(&files, &cts).await;
                fic.iter().zip(verdicts).for_each(|(f, v)| {
                    update_file_model(
                        handle_weak.clone(),
                        FileItem {
                            state: match v {
                                Ok(v) => v.to_string().into(),
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

fn update_file_model(handle: sixtyfps::Weak<Ui>, fi: FileItem) {
    handle.upgrade_in_event_loop(move |handle| {
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
    /// VaaS Token
    #[structopt(short, long)]
    token: String,

    /// Files to scan (full path)
    #[structopt(short, long)]
    files: Vec<String>,
}
