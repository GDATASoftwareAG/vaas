use reqwest::Url;
use std::io::Write;
use std::str::FromStr;
use std::sync::LazyLock;
use tokio_util::sync::CancellationToken;
use vaas::authentication::{Authenticator, ClientCredentials, Password};
use vaas::error::Error;
use vaas::message::verdict::Verdict;
use vaas::options::{ForFileOptions, ForSha256Options, ForStreamOptions, ForUrlOptions};
use vaas::{Sha256, Vaas};

static EICAR_SHA256: LazyLock<Sha256> = LazyLock::new(|| {
    Sha256::from_str("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f").unwrap()
});
const EICAR_STRING: &str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

fn vaas_with_authenticator(authenticator: impl Authenticator + 'static) -> Vaas {
    let vaas_url = dotenv::var("VAAS_URL")
        .expect("No VAAS_URL environment variable set to be used in the integration tests");
    Vaas::builder(authenticator)
        .url(Url::parse(&vaas_url).unwrap())
        .build()
        .unwrap()
}

#[rstest::fixture]
fn vaas_with_client_credentials() -> Vaas {
    let token_url: Url = dotenv::var("TOKEN_URL")
        .expect("No TOKEN_URL environment variable set to be used in the integration tests")
        .parse()
        .expect("Failed to parse TOKEN_URL environment variable");
    let client_id = dotenv::var("CLIENT_ID")
        .expect("No CLIENT_ID environment variable set to be used in the integration tests");
    let client_secret = dotenv::var("CLIENT_SECRET")
        .expect("No CLIENT_SECRET environment variable set to be used in the integration tests");
    let authenticator = ClientCredentials::try_new(client_id, client_secret)
        .unwrap()
        .with_token_url(token_url);
    vaas_with_authenticator(authenticator)
}

#[rstest::fixture]
fn vaas_with_password() -> Vaas {
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
    let authenticator = Password::try_new(client_id, user_name, password)
        .unwrap()
        .with_token_url(token_url);
    vaas_with_authenticator(authenticator)
}

#[rstest::rstest]
#[case(
    "ab5788279033b0a96f2d342e5f35159f103f69e0191dd391e036a1cd711791a2",
    Verdict::Malicious
)]
#[case(
    "cd617c5c1b1ff1c94a52ab8cf07192654f271a3f8bad49490288131ccb9efc1e",
    Verdict::Clean
)]
#[case(
    "1f72c1111111111111f912e40b7323a0192a300b376186c10f6803dc5efe28df",
    Verdict::Unknown
)]
#[tokio::test]
async fn test_for_sha256(
    vaas_with_client_credentials: Vaas,
    #[case] sha256: Sha256,
    #[case] expected_verdict: Verdict,
) -> Result<(), Error> {
    let options = ForSha256Options::default();
    let ct = CancellationToken::new();

    let verdict = vaas_with_client_credentials
        .for_sha256(&sha256, options, &ct)
        .await?;

    assert_eq!(
        verdict.verdict, expected_verdict,
        "unexpected verdict for {sha256}, expected {expected_verdict} got {}",
        verdict.verdict
    );
    assert_eq!(verdict.sha256, sha256);
    Ok(())
}

#[rstest::rstest]
#[tokio::test]
async fn test_for_sha256_with_username_and_password(vaas_with_password: Vaas) -> Result<(), Error> {
    let verdict = vaas_with_password
        .for_sha256(
            &EICAR_SHA256,
            ForSha256Options::default(),
            &CancellationToken::new(),
        )
        .await?;

    assert_eq!(verdict.verdict, Verdict::Malicious);
    Ok(())
}

#[rstest::rstest]
#[case("", Verdict::Clean)]
#[case("foobar", Verdict::Clean)]
#[case(EICAR_STRING, Verdict::Malicious)]
#[tokio::test]
async fn test_for_file(
    vaas_with_client_credentials: Vaas,
    #[case] file_content: &str,
    #[case] expected_verdict: Verdict,
) -> Result<(), Error> {
    let options = ForFileOptions::default();
    let ct = CancellationToken::new();
    let mut eicar_file = tempfile::NamedTempFile::new()?;
    write!(eicar_file.as_file_mut(), "{file_content}")?;

    let verdict = vaas_with_client_credentials
        .for_file(eicar_file.path(), options, &ct)
        .await?;

    assert_eq!(
        verdict.verdict, expected_verdict,
        "unexpected verdict for {file_content}, expected {expected_verdict} got {}",
        verdict.verdict
    );
    Ok(())
}

#[rstest::rstest]
#[tokio::test]
async fn test_for_stream(vaas_with_client_credentials: Vaas) -> Result<(), Error> {
    let options = ForStreamOptions::default();
    let ct = CancellationToken::new();
    let mut eicar_file = tempfile::NamedTempFile::new()?;
    write!(eicar_file.as_file_mut(), "{EICAR_STRING}")?;
    let tokio_file = tokio::fs::File::open(eicar_file.path()).await?;
    let content_length = tokio_file.metadata().await?.len();
    let stream = tokio_util::io::ReaderStream::new(tokio_file);

    let verdict = vaas_with_client_credentials
        .for_stream(stream, content_length, options, &ct)
        .await?;

    assert_eq!(verdict.verdict, Verdict::Malicious);
    assert_eq!(verdict.sha256, *EICAR_SHA256);
    Ok(())
}

#[rstest::rstest]
#[case(
    "https://www.gdatasoftware.com/oem/verdict-as-a-service",
    Verdict::Clean
)]
#[case("https://secure.eicar.org/eicar.com", Verdict::Malicious)]
#[tokio::test]
async fn test_for_url(
    vaas_with_client_credentials: Vaas,
    #[case] url: Url,
    #[case] expected_veridct: Verdict,
) -> Result<(), Error> {
    let options = ForUrlOptions::default();
    let ct = CancellationToken::new();

    let verdict = vaas_with_client_credentials
        .for_url(&url, options, &ct)
        .await?;

    assert_eq!(
        verdict.verdict, expected_veridct,
        "unexpected verdict for {url}, expected {expected_veridct} got {}",
        verdict.verdict
    );
    Ok(())
}

#[rstest::rstest]
#[case("", Verdict::Clean)]
#[case("foobar", Verdict::Clean)]
#[case(EICAR_STRING, Verdict::Malicious)]
#[tokio::test]
async fn test_for_buf(
    vaas_with_client_credentials: Vaas,
    #[case] data: &str,
    #[case] expected_veridct: Verdict,
) -> Result<(), Error> {
    let options = ForStreamOptions::default();
    let ct = CancellationToken::new();
    let data_buf = data.as_bytes().to_vec();

    let verdict = vaas_with_client_credentials
        .for_buf(data_buf, options, &ct)
        .await?;

    assert_eq!(
        verdict.verdict, expected_veridct,
        "unexpected verdict for {data}, expected {expected_veridct} got {}",
        verdict.verdict
    );
    Ok(())
}

#[rstest::rstest]
#[tokio::test]
async fn test_for_buf_if_canceled_returns_error(
    vaas_with_client_credentials: Vaas,
) -> Result<(), Error> {
    let options = ForStreamOptions::default();
    let ct = CancellationToken::new();
    let data_buf = Vec::default();

    ct.cancel();
    let verdict_result = vaas_with_client_credentials
        .for_buf(data_buf, options, &ct)
        .await;

    assert!(
        matches!(verdict_result, Err(Error::Canceled)),
        "expected cancellation error got {verdict_result:#?}"
    );
    Ok(())
}
