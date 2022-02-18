use futures::future::try_join_all;
use rand::{distributions::Alphanumeric, Rng};
use std::{convert::TryFrom, time::Duration};
use vaas::{message::Verdict, CancellationTokenSource, Connection, Sha256, Vaas};

async fn get_vaas() -> Connection {
    let token = dotenv::var("VAAS_TOKEN")
        .expect("No TOKEN environment variable set to be used in the integration tests!");

    Vaas::builder(token)
        .poll_delay_ms(100)
        .build()
        .unwrap()
        .connect()
        .await
        .unwrap()
}

#[tokio::test]
async fn from_sha256_list_multiple_hashes() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let expected_url = "https://upload-vaas.gdatasecurity.de/upload";
    cts.cancel_after(Duration::from_secs(10));
    let sha256_malicious =
        Sha256::try_from("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();
    let sha256_clean =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_unknown =
        Sha256::try_from("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb")
            .unwrap();
    let sha256_list = vec![
        sha256_malicious.clone(),
        sha256_clean.clone(),
        sha256_unknown.clone(),
    ];

    let results = vaas.for_sha256_list(&sha256_list, &cts).await;

    assert_eq!(&Verdict::Malicious, results[0].as_ref().unwrap());
    assert_eq!(&Verdict::Clean, results[1].as_ref().unwrap());
    if let Verdict::Unknown { upload_url } = results[2].as_ref().unwrap() {
        println!("URL: {}", upload_url);
        assert!(upload_url.starts_with(expected_url));
    } else {
        panic!("Unexpected verdict type.")
    }
}

#[tokio::test]
async fn from_sha256_single_malicious_hash() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let sha256 =
        Sha256::try_from("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();

    let verdict = vaas.for_sha256(&sha256, &cts).await;

    assert_eq!(Verdict::Malicious, verdict.unwrap());
}

#[tokio::test]
async fn from_sha256_multiple_malicious_hash() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let sha256_1 =
        Sha256::try_from("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &cts).await;
    let verdict_2 = vaas.for_sha256(&sha256_2, &cts).await;
    let verdict_3 = vaas.for_sha256(&sha256_3, &cts).await;

    assert_eq!(Verdict::Malicious, verdict_1.unwrap());
    assert_eq!(Verdict::Malicious, verdict_2.unwrap());
    assert_eq!(Verdict::Malicious, verdict_3.unwrap());
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let sha256_1 =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &cts).await;
    let verdict_2 = vaas.for_sha256(&sha256_2, &cts).await;
    let verdict_3 = vaas.for_sha256(&sha256_3, &cts).await;

    assert_eq!(Verdict::Clean, verdict_1.unwrap());
    assert_eq!(Verdict::Clean, verdict_2.unwrap());
    assert_eq!(Verdict::Clean, verdict_3.unwrap());
}

#[tokio::test]
async fn from_sha256_multiple_unknown_hash() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let expected_url = "https://upload-vaas.gdatasecurity.de/upload";
    let sha256_1 =
        Sha256::try_from("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &cts).await.unwrap();
    let verdict_2 = vaas.for_sha256(&sha256_2, &cts).await.unwrap();
    let verdict_3 = vaas.for_sha256(&sha256_3, &cts).await.unwrap();

    if let Verdict::Unknown { upload_url } = verdict_1 {
        assert!(upload_url.starts_with(expected_url));
    } else {
        panic!("Unexpected verdict type.")
    }
    if let Verdict::Unknown { upload_url } = verdict_2 {
        assert!(upload_url.starts_with(expected_url));
    } else {
        panic!("Unexpected verdict type.")
    }
    if let Verdict::Unknown { upload_url } = verdict_3 {
        assert!(upload_url.starts_with(expected_url));
    } else {
        panic!("Unexpected verdict type.")
    }
}

#[tokio::test]
async fn from_file_single_malicious_file() {
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let tmp_file = std::env::temp_dir().join("eicar.txt");
    std::fs::write(&tmp_file, eicar.as_bytes()).unwrap();

    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));

    let verdict = vaas.for_file(&tmp_file, &cts).await;

    std::fs::remove_file(&tmp_file).unwrap();
    assert_eq!(Verdict::Malicious, verdict.unwrap());
}

#[tokio::test]
async fn from_file_single_clean_file() {
    let clean: [u8; 8] = [0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a];
    let tmp_file = std::env::temp_dir().join("clean.txt");
    std::fs::write(&tmp_file, clean).unwrap();

    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));

    let verdict = vaas.for_file(&tmp_file, &cts).await;

    std::fs::remove_file(&tmp_file).unwrap();
    assert_eq!(Verdict::Clean, verdict.unwrap());
}

#[tokio::test]
#[ignore = "Skip this test for now, as the test takes multiple minutes."]
async fn from_file_single_unknown_file() {
    let unknown: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(50)
        .map(char::from)
        .collect();
    let tmp_file = std::env::temp_dir().join("unknown.txt");
    std::fs::write(&tmp_file, unknown.as_bytes()).unwrap();

    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(5 * 60));

    let verdict = vaas.for_file(&tmp_file, &cts).await;

    std::fs::remove_file(&tmp_file).unwrap();
    assert_eq!(Verdict::Clean, verdict.unwrap());
}

#[tokio::test]
#[ignore = "Skip this test for now, as it the takes multiple minutes."]
async fn from_files_unknown_files() {
    let unknown1: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(50)
        .map(char::from)
        .collect();
    let unknown2: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(50)
        .map(char::from)
        .collect();
    let tmp_file1 = std::env::temp_dir().join("unknown1.txt");
    std::fs::write(&tmp_file1, unknown1.as_bytes()).unwrap();
    let tmp_file2 = std::env::temp_dir().join("unknown2.txt");
    std::fs::write(&tmp_file2, unknown2.as_bytes()).unwrap();
    let files = vec![tmp_file1.clone(), tmp_file2.clone()];

    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(5 * 60));

    let verdicts = vaas.for_file_list(&files, &cts).await;

    std::fs::remove_file(tmp_file1).unwrap();
    std::fs::remove_file(tmp_file2).unwrap();
    assert_eq!(&Verdict::Clean, verdicts[0].as_ref().unwrap());
    assert_eq!(&Verdict::Clean, verdicts[1].as_ref().unwrap());
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_on_separate_thread() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let sha256_1 =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783")
            .unwrap();

    let (v1, v2, v3) = tokio::spawn(async move {
        let v1 = vaas.for_sha256(&sha256_1, &cts).await;
        let v2 = vaas.for_sha256(&sha256_2, &cts).await;
        let v3 = vaas.for_sha256(&sha256_3, &cts).await;
        (v1, v2, v3)
    })
    .await
    .unwrap();

    assert_eq!(Verdict::Clean, v1.unwrap());
    assert_eq!(Verdict::Clean, v2.unwrap());
    assert_eq!(Verdict::Clean, v3.unwrap());
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_await_concurrent_fixed_jobs() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let sha256_1 =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783")
            .unwrap();

    let v1 = vaas.for_sha256(&sha256_1, &cts);
    let v2 = vaas.for_sha256(&sha256_2, &cts);
    let v3 = vaas.for_sha256(&sha256_3, &cts);

    let (v1, v2, v3) = tokio::join!(v1, v2, v3);
    assert_eq!(Verdict::Clean, v1.unwrap());
    assert_eq!(Verdict::Clean, v2.unwrap());
    assert_eq!(Verdict::Clean, v3.unwrap());
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_await_concurrent_unknown_jobs() {
    let vaas = get_vaas().await;
    let cts = CancellationTokenSource::new();
    cts.cancel_after(Duration::from_secs(10));
    let sha256_1 =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783")
            .unwrap();

    let handles = vec![
        vaas.for_sha256(&sha256_1, &cts),
        vaas.for_sha256(&sha256_2, &cts),
        vaas.for_sha256(&sha256_3, &cts),
    ];

    let result = try_join_all(handles).await;
    let verdicts = result.unwrap();

    assert_eq!(Verdict::Clean, verdicts[0]);
    assert_eq!(Verdict::Clean, verdicts[1]);
    assert_eq!(Verdict::Clean, verdicts[2]);
}
