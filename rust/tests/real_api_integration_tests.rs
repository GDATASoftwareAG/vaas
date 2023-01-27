use futures::future::try_join_all;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Url;
use std::convert::TryFrom;
use std::ops::Deref;
use vaas::error::Error::FailedAuthTokenRequest;
use vaas::{message::Verdict, CancellationToken, Connection, Sha256, Vaas};

async fn get_vaas() -> Connection {
    let token_url: Url = dotenv::var("TOKEN_URL")
        .expect("No TOKEN_URL environment variable set to be used in the integration tests")
        .parse()
        .expect("Failed to parse TOKEN_URL environment variable");
    let client_id = dotenv::var("CLIENT_ID")
        .expect("No CLIENT_ID environment variable set to be used in the integration tests");
    let client_secret = dotenv::var("CLIENT_SECRET")
        .expect("No CLIENT_SECRET environment variable set to be used in the integration tests");
    let token = Vaas::get_token_from_url(&client_id, &client_secret, token_url)
        .await
        .unwrap();
    let vaas_url = dotenv::var("VAAS_URL")
        .expect("No VAAS_URL environment variable set to be used in the integration tests");
    Vaas::builder(token)
        .url(Url::parse(&vaas_url).unwrap())
        .build()
        .unwrap()
        .connect()
        .await
        .unwrap()
}

#[tokio::test]
async fn from_sha256_wrong_credentials() {
    let token_url: Url = dotenv::var("TOKEN_URL")
        .expect("No TOKEN_URL environment variable set to be used in the integration tests")
        .parse()
        .expect("Failed to parse TOKEN_URL environment variable");
    let client_id = "invalid";
    let client_secret = "invalid";
    let token = Vaas::get_token_from_url(&client_id, &client_secret, token_url).await;

    assert!(token.is_err());
    assert!(match token {
        Ok(_) => false,
        Err(FailedAuthTokenRequest(_, _)) => true,
        _ => false,
    })
}

#[tokio::test]
async fn from_sha256_list_multiple_hashes() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
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

    let results = vaas.for_sha256_list(&sha256_list, &ct).await;

    assert_eq!(Verdict::Malicious, results[0].as_ref().unwrap().verdict);
    assert_eq!(
        "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8",
        results[0].as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Clean, results[1].as_ref().unwrap().verdict);
    assert_eq!(
        "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23".to_lowercase(),
        results[1].as_ref().unwrap().sha256.deref()
    );
    assert!(matches!(
        results[2].as_ref().unwrap().verdict,
        Verdict::Unknown { .. }
    ));
    assert_eq!(
        "00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fbbb",
        results[2].as_ref().unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_sha256_single_malicious_hash() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256 =
        Sha256::try_from("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();

    let verdict = vaas.for_sha256(&sha256, &ct).await;

    assert_eq!(Verdict::Malicious, verdict.as_ref().unwrap().verdict);
    assert_eq!(
        "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8",
        verdict.unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_sha256_single_pup_hash() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256 =
        Sha256::try_from("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad")
            .unwrap();

    let verdict = vaas.for_sha256(&sha256, &ct).await;

    assert_eq!(Verdict::Pup, verdict.as_ref().unwrap().verdict);
    assert_eq!(
        "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad",
        verdict.unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_sha256_single_empty_file_hash() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256 =
        Sha256::try_from("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            .unwrap();

    let verdict = vaas.for_sha256(&sha256, &ct).await;

    assert_eq!(Verdict::Clean, verdict.as_ref().unwrap().verdict);
    assert_eq!(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        verdict.unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_sha256_multiple_malicious_hash() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &ct).await;
    let verdict_2 = vaas.for_sha256(&sha256_2, &ct).await;
    let verdict_3 = vaas.for_sha256(&sha256_3, &ct).await;

    assert_eq!(
        "000005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8",
        verdict_1.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Malicious, verdict_1.unwrap().verdict);
    assert_eq!(
        "00000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c",
        verdict_2.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Malicious, verdict_2.unwrap().verdict);
    assert_eq!(
        "00000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a",
        verdict_3.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Malicious, verdict_3.unwrap().verdict);
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &ct).await;
    let verdict_2 = vaas.for_sha256(&sha256_2, &ct).await;
    let verdict_3 = vaas.for_sha256(&sha256_3, &ct).await;

    assert_eq!(Verdict::Clean, verdict_1.as_ref().unwrap().verdict);
    assert_eq!(
        "698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23".to_lowercase(),
        verdict_1.unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Clean, verdict_2.as_ref().unwrap().verdict);
    assert_eq!(
        "1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391".to_lowercase(),
        verdict_2.unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Clean, verdict_3.as_ref().unwrap().verdict);
    assert_eq!(
        "4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783".to_lowercase(),
        verdict_3.unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_sha256_multiple_unknown_hash() {
    let vaas = get_vaas().await;
    let t = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &t).await.unwrap();
    let verdict_2 = vaas.for_sha256(&sha256_2, &t).await.unwrap();
    let verdict_3 = vaas.for_sha256(&sha256_3, &t).await.unwrap();

    assert!(matches!(verdict_1.verdict, Verdict::Unknown { .. }));
    assert_eq!(
        verdict_1.sha256.deref(),
        "110005c43196142f01d615a67b7da8a53cb0172f8e9317a2ec9a0a39a1da6fe8"
    );
    assert!(matches!(verdict_2.verdict, Verdict::Unknown { .. }));
    assert_eq!(
        verdict_2.sha256.deref(),
        "11000b68934493af2f5954593fe8127b9dda6d4b520e78265aa5875623b58c9c"
    );
    assert!(matches!(verdict_3.verdict, Verdict::Unknown { .. }));
    assert_eq!(
        verdict_3.sha256.deref(),
        "11000f83e3120f79a21b7b395dd3dd6a9c31ce00857f78d7cf487476ca75fd1a"
    );
}

#[tokio::test]
async fn from_file_single_malicious_file() {
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let tmp_file = std::env::temp_dir().join("eicar.txt");
    std::fs::write(&tmp_file, eicar.as_bytes()).unwrap();

    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(30);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    assert_eq!(Verdict::Malicious, verdict.as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file).unwrap(),
        verdict.unwrap().sha256
    );
    std::fs::remove_file(&tmp_file).unwrap();
}

#[tokio::test]
async fn from_file_single_clean_file() {
    let clean: [u8; 8] = [0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a];
    let tmp_file = std::env::temp_dir().join("clean.txt");
    std::fs::write(&tmp_file, clean).unwrap();

    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    assert_eq!(Verdict::Clean, verdict.as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file).unwrap(),
        verdict.unwrap().sha256
    );
    std::fs::remove_file(&tmp_file).unwrap();
}

#[tokio::test]
//#[ignore = "Skip this test for now, as the test takes multiple minutes."]
async fn from_file_single_unknown_file() {
    let unknown: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(50)
        .map(char::from)
        .collect();
    let tmp_file = std::env::temp_dir().join("unknown.txt");
    std::fs::write(&tmp_file, unknown.as_bytes()).unwrap();

    let vaas = get_vaas().await;
    let ct = CancellationToken::from_minutes(10);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    assert_eq!(Verdict::Clean, verdict.as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file).unwrap(),
        verdict.unwrap().sha256
    );
    std::fs::remove_file(&tmp_file).unwrap();
}

#[tokio::test]
//#[ignore = "Skip this test for now, as it the takes multiple minutes."]
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
    let ct = CancellationToken::from_minutes(10);
    let verdicts = vaas.for_file_list(&files, &ct).await;

    assert_eq!(Verdict::Clean, verdicts[0].as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file1).unwrap(),
        verdicts[0].as_ref().unwrap().sha256
    );
    assert_eq!(Verdict::Clean, verdicts[1].as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file2).unwrap(),
        verdicts[1].as_ref().unwrap().sha256
    );
    std::fs::remove_file(tmp_file1).unwrap();
    std::fs::remove_file(tmp_file2).unwrap();
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_on_separate_thread() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
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
        let v1 = vaas.for_sha256(&sha256_1, &ct).await;
        let v2 = vaas.for_sha256(&sha256_2, &ct).await;
        let v3 = vaas.for_sha256(&sha256_3, &ct).await;
        (v1, v2, v3)
    })
    .await
    .unwrap();

    assert_eq!(Verdict::Clean, v1.unwrap().verdict);
    assert_eq!(Verdict::Clean, v2.unwrap().verdict);
    assert_eq!(Verdict::Clean, v3.unwrap().verdict);
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_await_concurrent_fixed_jobs() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("698CDA840A0B3D4639F0C5DBD5C629A847A27448A9A179CB6B7A648BC1186F23")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("1AFAFE9157FF5670BBEC8CE622F45D1CE51B3EE77B7348D3A237E232F06C5391")
            .unwrap();
    let sha256_3 =
        Sha256::try_from("4447FAACEFABA8F040822101E2A4103031660DE9139E70ECFF9AA3A89455A783")
            .unwrap();

    let v1 = vaas.for_sha256(&sha256_1, &ct);
    let v2 = vaas.for_sha256(&sha256_2, &ct);
    let v3 = vaas.for_sha256(&sha256_3, &ct);

    let (v1, v2, v3) = tokio::join!(v1, v2, v3);
    assert_eq!(Verdict::Clean, v1.unwrap().verdict);
    assert_eq!(Verdict::Clean, v2.unwrap().verdict);
    assert_eq!(Verdict::Clean, v3.unwrap().verdict);
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_await_concurrent_unknown_jobs() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
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
        vaas.for_sha256(&sha256_1, &ct),
        vaas.for_sha256(&sha256_2, &ct),
        vaas.for_sha256(&sha256_3, &ct),
    ];

    let result = try_join_all(handles).await;
    let verdicts = result.unwrap();

    assert_eq!(Verdict::Clean, verdicts[0].verdict);
    assert_eq!(Verdict::Clean, verdicts[1].verdict);
    assert_eq!(Verdict::Clean, verdicts[2].verdict);
}

#[tokio::test]
async fn from_file_single_clean_file_with_credentials() {
    let clean: [u8; 8] = [0x65, 0x0a, 0x67, 0x0a, 0x65, 0x0a, 0x62, 0x0a];
    let tmp_file = std::env::temp_dir().join("clean2.txt");
    std::fs::write(&tmp_file, clean).unwrap();

    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    std::fs::remove_file(&tmp_file).unwrap();
    assert_eq!(Verdict::Clean, verdict.unwrap().verdict);
}

#[tokio::test]
async fn from_file_empty_file() {
    let empty_file: [u8; 0] = [];
    let tmp_file = std::env::temp_dir().join("empty.txt");
    std::fs::write(&tmp_file, empty_file).unwrap();

    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    std::fs::remove_file(&tmp_file).unwrap();
    assert_eq!(Verdict::Clean, verdict.unwrap().verdict);
}

#[tokio::test]
async fn from_url_single_malicious_url() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let url = Url::parse("https://secure.eicar.org/eicar.com").unwrap();

    let verdict = vaas.for_url(&url, &ct).await;

    assert_eq!(Verdict::Malicious, verdict.as_ref().unwrap().verdict);
}

#[tokio::test]
async fn from_url_single_clean_url() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let url = Url::parse("https://www.gdatasoftware.com/oem/verdict-as-a-service").unwrap();

    let verdict = vaas.for_url(&url, &ct).await;

    assert_eq!(Verdict::Clean, verdict.as_ref().unwrap().verdict);
}
