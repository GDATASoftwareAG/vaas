use futures::future::try_join_all;
use rand::{distributions::Alphanumeric, Rng};
use reqwest::Url;
use std::convert::TryFrom;
use std::ops::Deref;
use vaas::auth::authenticators::{ClientCredentials, Password};
use vaas::{message::Verdict, CancellationToken, Connection, Sha256, Vaas};

async fn get_vaas_with_flags(use_cache: bool, use_hash_lookup: bool) -> Connection {
    let token_url: Url = dotenv::var("TOKEN_URL")
        .expect("No TOKEN_URL environment variable set to be used in the integration tests")
        .parse()
        .expect("Failed to parse TOKEN_URL environment variable");
    let client_id = dotenv::var("CLIENT_ID")
        .expect("No CLIENT_ID environment variable set to be used in the integration tests");
    let client_secret = dotenv::var("CLIENT_SECRET")
        .expect("No CLIENT_SECRET environment variable set to be used in the integration tests");
    let authenticator = ClientCredentials::new(client_id, client_secret).with_token_url(token_url);
    let vaas_url = dotenv::var("VAAS_URL")
        .expect("No VAAS_URL environment variable set to be used in the integration tests");
    Vaas::builder(authenticator)
        .use_cache(use_cache)
        .use_hash_lookup(use_hash_lookup)
        .url(Url::parse(&vaas_url).unwrap())
        .build()
        .unwrap()
        .connect()
        .await
        .unwrap()
}

async fn get_vaas() -> Connection {
    get_vaas_with_flags(true, true).await
}

#[tokio::test]
async fn connect_with_username_and_password() {
    let token_url: Url = dotenv::var("TOKEN_URL")
        .expect("No TOKEN_URL environment variable set to be used in the integration tests")
        .parse()
        .expect("Failed to parse TOKEN_URL environment variable");
    let client_id = dotenv::var("VAAS_CLIENT_ID")
        .expect("No CLIENT_ID environment variable set to be used in the integration tests");
    let user_name = dotenv::var("VAAS_USER_NAME")
        .expect("No VAAS_USER_NAME environment variable set to be used in the integration tests");
    let password = dotenv::var("VAAS_PASSWORD")
        .expect("No VAAS_PASSWORD environment variable set to be used in the integration tests");
    let vaas_url = dotenv::var("VAAS_URL")
        .expect("No VAAS_URL environment variable set to be used in the integration tests");
    let authenticator = Password::new(client_id, user_name, password).with_token_url(token_url);
    let connection = Vaas::builder(authenticator)
        .url(Url::parse(&vaas_url).unwrap())
        .build()
        .unwrap()
        .connect()
        .await;

    assert!(connection.is_ok())
}

#[tokio::test]
async fn from_sha256_list_multiple_hashes() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_malicious =
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();
    let sha256_clean =
        Sha256::try_from("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e")
            .unwrap();
    let sha256_unknown =
        Sha256::try_from("1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df")
            .unwrap();
    let sha256_list = vec![
        sha256_malicious.clone(),
        sha256_clean.clone(),
        sha256_unknown.clone(),
    ];

    let results = vaas.for_sha256_list(&sha256_list, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), results[0].as_ref().unwrap().verdict);
    assert_eq!(
        "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
        results[0].as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Clean, results[1].as_ref().unwrap().verdict);
    assert_eq!(
        "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e".to_lowercase(),
        results[1].as_ref().unwrap().sha256.deref()
    );
    assert!(matches!(
        results[2].as_ref().unwrap().verdict,
        Verdict::Unknown { .. }
    ));
    assert_eq!(
        "1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df",
        results[2].as_ref().unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_sha256_single_malicious_hash() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256 =
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();

    let verdict = vaas.for_sha256(&sha256, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), verdict.as_ref().unwrap().verdict);
    assert_eq!(
        "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
        verdict.unwrap().sha256.deref()
    );
}

#[tokio::test]
async fn from_http_response_stream_returns_malicious_verdict() {
    let result = reqwest::get("https://secure.eicar.org/eicar.com.txt").await;
    let vaas = get_vaas().await;

    let ct = CancellationToken::from_seconds(10);
    let response = result.unwrap().error_for_status().unwrap();
    let content_length: usize = response.content_length().unwrap() as usize;
    let byte_stream = response.bytes_stream();
    let verdict = vaas.for_stream(byte_stream, content_length, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.as_ref().unwrap().verdict);
}

#[tokio::test]
async fn from_http_response_stream_no_hash_lookup_no_cache_lookup_returns_malicious_verdict_and_mimetype_and_detection(
) {
    let result = reqwest::get("https://secure.eicar.org/eicar.com.txt").await;
    let vaas = get_vaas_with_flags(false, false).await;

    let ct = CancellationToken::from_seconds(10);
    let response = result.unwrap().error_for_status().unwrap();
    let content_length: usize = response.content_length().unwrap() as usize;
    let byte_stream = response.bytes_stream();
    let verdict = vaas.for_stream(byte_stream, content_length, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.as_ref().unwrap().verdict);
    assert_eq!(
        Some("text/plain"),
        verdict.as_ref().unwrap().mime_type.as_deref()
    );
    assert_eq!(
        Some("EICAR virus test files"),
        verdict.as_ref().unwrap().file_type.as_deref()
    );
    assert_eq!(
        Verdict::Malicious(String::from("EICAR-Test-File")),
        verdict.as_ref().unwrap().verdict
    );
}

#[tokio::test]
async fn from_string_stream_returns_malicious_verdict() {
    let eicar_string = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    let stream: Vec<Result<bytes::Bytes, std::io::Error>> =
        vec![Ok(bytes::Bytes::from(eicar_string))];
    let stream = futures_util::stream::iter(stream);

    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let verdict = vaas.for_stream(stream, eicar_string.len(), &ct).await;

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.as_ref().unwrap().verdict);
}

// #[tokio::test]
// async fn from_sha256_single_pup_hash() {
//     let vaas = get_vaas().await;
//     let ct = CancellationToken::from_seconds(10);
//     let sha256 =
//         Sha256::try_from("d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad")
//             .unwrap();

//     let verdict = vaas.for_sha256(&sha256, &ct).await;

//     assert_eq!(Verdict::Pup, verdict.as_ref().unwrap().verdict);
//     assert_eq!(
//         "d6f6c6b9fde37694e12b12009ad11ab9ec8dd0f193e7319c523933bdad8a50ad",
//         verdict.unwrap().sha256.deref()
//     );
// }

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
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e")
            .unwrap();

    let verdict_1 = vaas.for_sha256(&sha256_1, &ct).await;
    let verdict_2 = vaas.for_sha256(&sha256_2, &ct).await;

    assert_eq!(
        "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
        verdict_1.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), verdict_1.unwrap().verdict);
    assert_eq!(
        "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e",
        verdict_2.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Clean, verdict_2.unwrap().verdict);
}

#[tokio::test]
async fn from_sha256_multiple_malicious_hash_without_cache() {
    let vaas = get_vaas_with_flags(false, true).await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e")
            .unwrap();
    let verdict_1 = vaas.for_sha256(&sha256_1, &ct).await;
    let verdict_2 = vaas.for_sha256(&sha256_2, &ct).await;

    assert_eq!(
        "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
        verdict_1.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), verdict_1.unwrap().verdict);
    assert_eq!(
        "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e",
        verdict_2.as_ref().unwrap().sha256.deref()
    );
    assert_eq!(Verdict::Clean, verdict_2.unwrap().verdict);
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
async fn for_file_single_malicious_file() {
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let tmp_file = std::env::temp_dir().join("eicar.txt");
    std::fs::write(&tmp_file, eicar.as_bytes()).unwrap();

    let vaas = get_vaas_with_flags(false, false).await;
    let ct = CancellationToken::from_seconds(30);

    let verdict = vaas.for_file(&tmp_file, &ct).await.unwrap();

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.verdict);
    assert_eq!(Sha256::try_from(&tmp_file).unwrap(), verdict.sha256);
    assert_eq!(
        "EICAR virus test files".to_string(),
        verdict.file_type.unwrap()
    );
    assert_eq!("text/plain".to_string(), verdict.mime_type.unwrap());

    std::fs::remove_file(&tmp_file).unwrap();
}

#[tokio::test]
async fn from_file_single_malicious_file_without_cache() {
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let tmp_file =
        std::env::temp_dir().join("from_file_single_malicious_file_without_cache_eicar.txt");
    std::fs::write(&tmp_file, eicar.as_bytes()).unwrap();

    let vaas = get_vaas_with_flags(false, true).await;
    let ct = CancellationToken::from_seconds(30);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file).unwrap(),
        verdict.unwrap().sha256
    );
    std::fs::remove_file(&tmp_file).unwrap();
}

#[tokio::test]
async fn from_file_single_malicious_file_without_hash_lookup() {
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let tmp_file =
        std::env::temp_dir().join("from_file_single_malicious_file_without_hash_lookup_eicar.txt");
    std::fs::write(&tmp_file, eicar.as_bytes()).unwrap();

    let vaas = get_vaas_with_flags(true, false).await;
    let ct = CancellationToken::from_seconds(30);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), verdict.as_ref().unwrap().verdict);
    assert_eq!(
        Sha256::try_from(&tmp_file).unwrap(),
        verdict.unwrap().sha256
    );
    std::fs::remove_file(&tmp_file).unwrap();
}

#[tokio::test]
async fn from_file_single_malicious_file_without_cache_and_without_hash_lookup() {
    let eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let tmp_file = std::env::temp_dir()
        .join("from_file_single_malicious_file_without_cache_and_without_hash_lookup_eicar.txt");
    std::fs::write(&tmp_file, eicar.as_bytes()).unwrap();

    let vaas = get_vaas_with_flags(false, false).await;
    let ct = CancellationToken::from_seconds(30);

    let verdict = vaas.for_file(&tmp_file, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.as_ref().unwrap().verdict);
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
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e")
            .unwrap();

    let (v1, v2) = tokio::spawn(async move {
        let v1 = vaas.for_sha256(&sha256_1, &ct).await;
        let v2 = vaas.for_sha256(&sha256_2, &ct).await;
        (v1, v2)
    })
    .await
    .unwrap();

    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), v1.unwrap().verdict);
    assert_eq!(Verdict::Clean, v2.unwrap().verdict);
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_await_concurrent_fixed_jobs() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e")
            .unwrap();

    let v1 = vaas.for_sha256(&sha256_1, &ct);
    let v2 = vaas.for_sha256(&sha256_2, &ct);

    let (v1, v2) = tokio::join!(v1, v2);
    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), v1.unwrap().verdict);
    assert_eq!(Verdict::Clean, v2.unwrap().verdict);
}

#[tokio::test]
async fn from_sha256_multiple_clean_hash_await_concurrent_unknown_jobs() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let sha256_1 =
        Sha256::try_from("ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2")
            .unwrap();
    let sha256_2 =
        Sha256::try_from("cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e")
            .unwrap();

    let handles = vec![
        vaas.for_sha256(&sha256_1, &ct),
        vaas.for_sha256(&sha256_2, &ct),
    ];

    let result = try_join_all(handles).await;
    let verdicts = result.unwrap();

    assert_eq!(Verdict::Malicious(String::from("Generic.Malware")), verdicts[0].verdict);
    assert_eq!(Verdict::Clean, verdicts[1].verdict);
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
    let vaas = get_vaas_with_flags(false, false).await;
    let ct = CancellationToken::from_seconds(10);
    let url = Url::parse("https://secure.eicar.org/eicar.com").unwrap();

    let verdict = vaas.for_url(&url, &ct).await.unwrap();

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict.verdict);
}

#[tokio::test]
async fn from_url_single_clean_url() {
    let vaas = get_vaas().await;
    let ct = CancellationToken::from_seconds(10);
    let url = Url::parse("https://www.gdatasoftware.com/oem/verdict-as-a-service").unwrap();

    let verdict = vaas.for_url(&url, &ct).await.unwrap();

    assert_eq!(Verdict::Clean, verdict.verdict);
}

#[tokio::test]
async fn from_url_multiple_url() {
    let vaas = get_vaas_with_flags(false, false).await;
    let ct = CancellationToken::from_seconds(10);
    let url1 = Url::parse("https://secure.eicar.org/eicar.com").unwrap();
    let url2 = Url::parse("https://secure.eicar.org/eicar.com").unwrap();
    let url3 = Url::parse("https://www.gdatasoftware.com/oem/verdict-as-a-service").unwrap();
    let urls = vec![url1, url2, url3];

    let verdict = vaas.for_url_list(&urls, &ct).await;

    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict[0].as_ref().unwrap().verdict);
    assert_eq!(Verdict::Malicious(String::from("EICAR-Test-File")), verdict[1].as_ref().unwrap().verdict);
    assert_eq!(Verdict::Clean, verdict[2].as_ref().unwrap().verdict);
}
