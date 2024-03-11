use crate::vaas::ffi::{VaasVerdict, Verdict};
use async_trait::async_trait;
use std::io;
use std::path::Path;
use std::str::FromStr;
use tokio::runtime;
use tokio::runtime::Runtime;
use url::Url;
use vaas::auth::authenticators;
use vaas::error::VResult;
use vaas::{auth, cancellation, vaas_verdict};

#[cxx::bridge(namespace = "vaas")]
mod ffi {
    pub struct VaasVerdict {
        sha256: String,
        verdict: Verdict,
    }

    pub enum Verdict {
        /// No malicious content found.
        Clean,
        /// Malicious content found.
        Malicious,
        /// Potentially unwanted content found.
        Pup,
        /// Unknown if clean or malicious.
        Unknown,
    }

    // TODO: Documentation for all
    extern "Rust" {
        type ClientCredentials;
        fn with_token_url(self: &mut ClientCredentials, token_url: &str) -> Result<()>;

        type Password;
        fn with_token_url(self: &mut Password, token_url: &str) -> Result<()>;

        type Builder;
        fn url(self: &mut Builder, url: &str) -> Result<()>;
        fn keep_alive(self: &mut Builder, keep_alive: bool);
        fn keep_alive_delay_ms(self: &mut Builder, delay: u64);
        fn channel_capacity(self: &mut Builder, capacity: usize);
        fn build(self: &mut Builder) -> Result<Box<Vaas>>;

        type Vaas;
        fn connect(self: &mut Vaas) -> Result<Box<Connection>>;

        type Connection;
        fn for_file(self: &Connection, file: &str, ct: &CancellationToken) -> Result<VaasVerdict>;
        fn for_url(self: &Connection, url: &str, ct: &CancellationToken) -> Result<VaasVerdict>;
        fn for_sha256(self: &Connection, sha256: &str, ct: &CancellationToken) -> Result<VaasVerdict>;

        type CancellationToken;

        fn new_client_credentials(
            client_id: String,
            client_secret: String,
        ) -> Box<ClientCredentials>;
        fn new_password(client_id: String, user_name: String, password: String) -> Box<Password>;
        fn new_builder_from_client_credentials(auth: &ClientCredentials) -> Box<Builder>;
        fn new_builder_from_password(auth: &Password) -> Box<Builder>;
        fn new_cancellation_token_from_seconds(secs: u64) -> Box<CancellationToken>;
        fn new_cancellation_token_from_minutes(mins: u64) -> Box<CancellationToken>;
    }
}

impl From<vaas_verdict::VaasVerdict> for VaasVerdict {
    fn from(value: vaas::VaasVerdict) -> Self {
        Self {
            sha256: value.sha256.to_string(),
            verdict: value.verdict.into(),
        }
    }
}

impl From<vaas::message::Verdict> for Verdict {
    fn from(value: vaas::message::Verdict) -> Self {
        match value {
            vaas::message::Verdict::Clean => Self::Clean,
            vaas::message::Verdict::Malicious => Self::Malicious,
            vaas::message::Verdict::Pup => Self::Pup,
            vaas::message::Verdict::Unknown { .. } => Self::Unknown,
        }
    }
}

pub struct ClientCredentials {
    inner: authenticators::ClientCredentials,
}

impl ClientCredentials {
    pub fn new(client_id: String, client_secret: String) -> Box<ClientCredentials> {
        Box::new(ClientCredentials {
            inner: authenticators::ClientCredentials::new(client_id, client_secret),
        })
    }

    pub fn with_token_url(&mut self, token_url: &str) -> Result<(), url::ParseError> {
        let token_url = Url::from_str(token_url)?;
        self.inner = self.inner.clone().with_token_url(token_url);
        Ok(())
    }
}

pub struct Password {
    inner: authenticators::Password,
}

impl Password {
    pub fn new(client_id: String, user_name: String, password: String) -> Box<Password> {
        Box::new(Password {
            inner: authenticators::Password::new(client_id, user_name, password),
        })
    }

    pub fn with_token_url(&mut self, token_url: &str) -> Result<(), url::ParseError> {
        let token_url = Url::from_str(token_url)?;
        self.inner = self.inner.clone().with_token_url(token_url);
        Ok(())
    }
}

#[derive(Clone)]
pub enum WrappingAuthenticator {
    ClientCredentials(authenticators::ClientCredentials),
    Password(authenticators::Password),
}

#[async_trait]
impl auth::Authenticator for WrappingAuthenticator {
    async fn get_token(&self) -> VResult<String> {
        match &self {
            WrappingAuthenticator::ClientCredentials(val) => val.get_token(),
            WrappingAuthenticator::Password(val) => val.get_token(),
        }
        .await
    }
}

impl From<authenticators::ClientCredentials> for WrappingAuthenticator {
    fn from(value: authenticators::ClientCredentials) -> Self {
        Self::ClientCredentials(value)
    }
}

impl From<authenticators::Password> for WrappingAuthenticator {
    fn from(value: authenticators::Password) -> Self {
        Self::Password(value)
    }
}

pub struct Builder {
    inner: vaas::Builder<WrappingAuthenticator>,
}

impl Builder {
    pub fn builder<A: auth::Authenticator>(auth: A) -> Box<Self>
    where
        WrappingAuthenticator: From<A>,
    {
        let auth = auth.into();
        Box::new(Self {
            inner: vaas::Vaas::builder(auth),
        })
    }

    pub fn url(&mut self, url: &str) -> Result<(), url::ParseError> {
        let token_url = Url::from_str(url)?;
        self.inner = self.inner.clone().url(token_url);
        Ok(())
    }

    pub fn keep_alive_delay_ms(&mut self, delay: u64) {
        self.inner = self.inner.clone().keep_alive_delay_ms(delay);
    }

    pub fn keep_alive(&mut self, keep_alive: bool) {
        self.inner = self.inner.clone().keep_alive(keep_alive);
    }

    pub fn channel_capacity(&mut self, capacity: usize) {
        self.inner = self.inner.clone().channel_capacity(capacity);
    }

    pub fn build(&mut self) -> VResult<Box<Vaas>> {
        self.inner
            .clone()
            .build()
            .map(|inner| Box::new(Vaas { inner }))
    }
}

pub struct Vaas {
    inner: vaas::Vaas<WrappingAuthenticator>,
}

impl Vaas {
    pub fn connect(&mut self) -> VResult<Box<Connection>> {
        let rt = Self::new_runtime()?;
        let conn = rt.block_on(async { self.inner.clone().connect().await })?;
        Ok(Box::new(Connection { rt, conn }))
    }

    fn new_runtime() -> io::Result<Runtime> {
        runtime::Builder::new_current_thread().enable_all().build()
    }
}

pub struct Connection {
    rt: Runtime,
    conn: vaas::Connection,
}

impl Connection {
    pub fn for_file(&self, file: &str, ct: &CancellationToken) -> VResult<VaasVerdict> {
        self.rt
            .block_on(async {
                let file = Path::new(file);
                self.conn.for_file(file, &ct.0).await
            })
            .map(Into::into)
    }

    pub fn for_url(&self, url: &str, ct: &CancellationToken) -> VResult<VaasVerdict> {
        self.rt
            .block_on(async {
                let url = Url::from_str(url)
                    .map_err(|e| vaas::error::Error::FailedRequest(e.to_string()))?;
                self.conn.for_url(&url, &ct.0).await
            })
            .map(Into::into)
    }
    
    pub fn for_sha256(&self, sha256: &str, ct: &CancellationToken) -> VResult<VaasVerdict> {
        let sha256 = vaas::Sha256::try_from(sha256)?;
        self.rt
            .block_on(async {
                self.conn.for_sha256(&sha256, &ct.0).await
            })
            .map(Into::into)
    }
}

pub struct CancellationToken(cancellation::CancellationToken);

pub fn new_client_credentials(client_id: String, client_secret: String) -> Box<ClientCredentials> {
    ClientCredentials::new(client_id, client_secret)
}

pub fn new_password(client_id: String, user_name: String, password: String) -> Box<Password> {
    Password::new(client_id, user_name, password)
}

pub fn new_builder_from_client_credentials(auth: &ClientCredentials) -> Box<Builder> {
    Builder::builder(auth.inner.clone())
}

pub fn new_builder_from_password(auth: &Password) -> Box<Builder> {
    Builder::builder(auth.inner.clone())
}

pub fn new_cancellation_token_from_seconds(secs: u64) -> Box<CancellationToken> {
    Box::new(CancellationToken(
        cancellation::CancellationToken::from_seconds(secs),
    ))
}

pub fn new_cancellation_token_from_minutes(mins: u64) -> Box<CancellationToken> {
    Box::new(CancellationToken(
        cancellation::CancellationToken::from_minutes(mins),
    ))
}
