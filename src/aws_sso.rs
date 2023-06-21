use crate::config::Config;
use aws_config::SdkConfig;
use aws_sdk_sso::error::SdkError;
use aws_sdk_ssooidc::operation::{
    create_token::{CreateTokenError, CreateTokenOutput},
    register_client::RegisterClientOutput,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::ops::Add;

#[derive(Debug, PartialEq, Clone)]
pub struct Profile {
    sso_session: String,
    sso_account_id: String,
    sso_role_name: String,
    region: Option<String>,
}

impl Profile {
    pub fn new(sso_session_name: String, sso_account_id: String, sso_role_name: String) -> Self {
        Self {
            sso_session: sso_session_name,
            sso_account_id: sso_account_id,
            sso_role_name: sso_role_name,
            region: None,
        }
    }
    pub fn get_session_name(&self) -> &str {
        self.sso_session.as_str()
    }

    pub fn set_region(mut self, value: Option<String>) -> Self {
        self.region = value;
        self
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSOSession {
    start_url: String,
    region: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<String>,
    registration_expires_at: Option<DateTime<Utc>>,
    #[serde(skip)]
    profiles: HashMap<String, Profile>,
    #[serde(flatten)]
    credentials: Option<SSOToken>,
}

impl SSOSession {
    pub fn new(start_url: String) -> Self {
        Self {
            start_url: start_url,
            region: None,
            scopes: None,
            client_id: None,
            client_secret: None,
            registration_expires_at: None,
            profiles: HashMap::new(),
            credentials: None,
        }
    }

    // pub fn get_profile(&self, name: &str) -> Option<&Profile> {
    //     self.profiles.get(name)
    // }

    // pub fn get_mut_profile(&mut self, name: &str) -> Option<&mut Profile> {
    //     self.profiles.get_mut(name)
    // }

    // pub fn get_start_url(&self) -> &str {
    //     &self.start_url
    // }

    // pub fn get_region(&self) -> Option<&str> {
    //     self.region.as_deref()
    // }

    // pub fn get_scopes(&self) -> Option<&str> {
    //     self.scopes.as_deref()
    // }

    pub fn is_expired(&self) -> bool {
        let now: DateTime<Utc> = Utc::now();
        match &self.registration_expires_at {
            Some(expires) => {
                if &now < expires {
                    false
                } else {
                    true
                }
            }
            _ => true,
        }
    }

    pub async fn create_token(&mut self, aws_config: &SdkConfig) {
        let (token, registration_expires_at, client_id, client_secret) =
            SSOToken::build(aws_config)
                .set_start_url(self.start_url.as_str())
                .create_token()
                .await;
        self.client_id = Some(client_id);
        self.client_secret = Some(client_secret);
        self.credentials = Some(token);
        self.registration_expires_at = Some(registration_expires_at);
    }

    pub async fn refresh_token(&mut self, aws_config: &SdkConfig) -> Result<(), ()> {
        let (token, _expires) = self
            .credentials
            .as_ref()
            .unwrap()
            .refresh(
                aws_config,
                self.client_id.as_deref().unwrap(),
                self.client_secret.as_deref().unwrap(),
            )
            .await.or(Err(()))?;
        // self.registration_expires_at = Some(expires);
        self.credentials = Some(token);
        Ok(())
    }

    pub fn merge_from_cache(mut self, cache: SSOSession) -> Self {
        if self.region != cache.region {
            // invalid cache
            return self;
        }
        if self.start_url != cache.start_url {
            // invalid cache
            return self;
        }
        // update values
        self.client_id = cache.client_id;
        self.client_secret = cache.client_secret;
        self.registration_expires_at = cache.registration_expires_at;
        self.credentials = cache.credentials;
        self
    }

    // pub fn set_credentials(mut self, token: Option<SSOToken>) -> Self {
    //     self.credentials = token;
    //     self
    // }

    pub fn set_profile(mut self, name: String, profile: Profile) -> Self {
        self.profiles.insert(name, profile);
        self
    }

    pub fn insert_profile(&mut self, name: String, profile: Profile) {
        self.profiles.insert(name, profile);
    }

    // pub fn get_credentials(&self) -> Option<&SSOToken> {
    //     self.credentials.as_ref()
    // }

    // pub fn get_access_token(&self) -> Option<&str> {
    //     self.credentials.as_ref()?.access_token.as_deref()
    // }

    pub fn set_region(mut self, value: Option<String>) -> Self {
        self.region = value;
        self
    }

    pub fn set_scopes(mut self, value: Option<String>) -> Self {
        self.scopes = value;
        self
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SSOToken {
    access_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    refresh_token: Option<String>,
}

impl From<CreateTokenOutput> for SSOToken {
    fn from(value: CreateTokenOutput) -> Self {
        Self {
            // force access token form api response
            access_token: Some(String::from(value.access_token().unwrap())),
            expires_at: Some(Utc::now().add(Duration::seconds(value.expires_in() as i64))),
            refresh_token: value.refresh_token().and_then(|v| Some(String::from(v))),
        }
    }
}

impl SSOToken {
    fn build(aws_config: &SdkConfig) -> SSOTokenBuilder {
        SSOTokenBuilder::new(aws_config, None, None, None)
    }

    pub async fn refresh(
        &self,
        aws_config: &SdkConfig,
        client_id: &str,
        client_secret: &str,
    ) -> Result<(SSOToken, DateTime<Utc>), SdkError<CreateTokenError>> {
        SSOTokenBuilder::new(aws_config, None, None, None)
            .refresh_token(
                client_id,
                client_secret,
                self.refresh_token
                    .as_deref()
                    .expect("Refresh token is not set"),
            )
            .await
    }

    // pub fn is_expired(&self) -> bool {
    //     todo!();
    // }

    pub fn get_access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }
}

struct SSOTokenBuilder<'a> {
    aws_config: &'a SdkConfig,
    start_url: Option<&'a str>,
    client_name: &'a str,
    scopes: &'a str,
    client_id: Option<&'a str>,
    client_secret: Option<&'a str>,
    // access_token: Option<&'a str>,
    refresh_token: Option<&'a str>,
}

impl<'a> SSOTokenBuilder<'a> {
    pub fn new(
        aws_config: &'a SdkConfig,
        start_url: Option<&'a str>,
        _access_token: Option<&'a str>,
        refresh_token: Option<&'a str>,
    ) -> Self {
        Self {
            aws_config: aws_config,
            start_url: start_url,
            client_name: "example",
            client_id: None,
            client_secret: None,
            scopes: "sso:account:access",
            // access_token: access_token,
            refresh_token: refresh_token,
        }
    }

    pub fn set_start_url(mut self, start_url: &'a str) -> Self {
        self.start_url = Some(start_url);
        self
    }

    pub fn set_client_id(mut self, client_id: &'a str) -> Self {
        self.client_id = Some(client_id);
        self
    }

    pub fn set_client_secret(mut self, client_secret: &'a str) -> Self {
        self.client_secret = Some(client_secret);
        self
    }

    pub fn set_refresh_token(mut self, refresh_token: &'a str) -> Self {
        self.refresh_token = Some(refresh_token);
        self
    }

    async fn register(&self, client: &aws_sdk_ssooidc::Client) -> RegisterClientOutput {
        client
            .register_client()
            .client_name(self.client_name)
            .client_type("public")
            .scopes(self.scopes)
            .send()
            .await
            .unwrap()
    }

    async fn refresh(
        &self,
        client: &aws_sdk_ssooidc::Client,
    ) -> Result<CreateTokenOutput, SdkError<CreateTokenError>> {
        println!("Refreshing token");
        let refresh_token = self.refresh_token.expect("refresh_token is not set");
        let client_id = self.client_id.expect("client_id is not set");
        let client_secret = self.client_secret.expect("client_secret is not set");

        client
            .create_token()
            .client_id(client_id)
            .client_secret(client_secret)
            .grant_type("refresh_token")
            .refresh_token(refresh_token)
            .send()
            .await
    }

    async fn device_auth(&self, client: &aws_sdk_ssooidc::Client) -> CreateTokenOutput {
        let start_url = self.start_url.expect("start_url is not set");
        let client_id = self.client_id.expect("client_id is not set");
        let client_secret = self.client_secret.expect("client_secret is not set");
        let device_auth = client
            .start_device_authorization()
            .client_id(client_id)
            .client_secret(client_secret)
            .start_url(start_url)
            .send()
            .await
            .unwrap();

        println!("{}", device_auth.verification_uri_complete().unwrap());
        let create_token = client
            .create_token()
            .client_id(client_id)
            .client_secret(client_secret)
            .grant_type("urn:ietf:params:oauth:grant-type:device_code")
            .set_device_code(device_auth.device_code);

        let token = loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            match create_token.clone().send().await {
                Ok(value) => break value,
                Err(aws_sdk_sso::error::SdkError::ServiceError(err)) => {
                    let err = err.into_err();
                    if err.is_authorization_pending_exception() {
                        print!(".");
                        std::io::stdout().flush().unwrap();
                        continue;
                    }
                    panic!("{:?}", err);
                }
                err => {
                    err.unwrap();
                }
            }
        };
        println!("");
        token
    }

    async fn create_token(self) -> (SSOToken, DateTime<Utc>, String, String) {
        let client = aws_sdk_ssooidc::Client::new(self.aws_config);

        let register = self.register(&client).await;
        let client_id = register.client_id().unwrap();
        let client_secret = register.client_secret().unwrap();
        let registration_expires_at = Utc
            .timestamp_opt(register.client_secret_expires_at(), 0)
            .unwrap();
        let token = self
            .set_client_id(client_id)
            .set_client_secret(client_secret)
            .device_auth(&client)
            .await;
        (
            SSOToken::from(token),
            registration_expires_at,
            String::from(client_id),
            String::from(client_secret),
        )
    }

    async fn refresh_token(
        self,
        client_id: &str,
        client_secret: &str,
        refresh_token: &str,
    ) -> Result<(SSOToken, DateTime<Utc>), SdkError<CreateTokenError>> {
        let client = aws_sdk_ssooidc::Client::new(self.aws_config);
        let token = self
            .set_client_id(client_id)
            .set_client_secret(client_secret)
            .set_refresh_token(refresh_token)
            .refresh(&client)
            .await?;
        let expires = Utc::now().add(Duration::seconds(token.expires_in() as i64));
        Ok((SSOToken::from(token), expires))
    }
}

pub struct SSO {
    config: Config,
}

impl SSO {
    pub fn new(config: Config) -> Self {
        Self { config: config }
    }

    pub async fn refresh(mut self, sso_session_name: &str) {
        let aws_config = self.config.aws_config.clone();
        let mut session: SSOSession = self
            .config
            .session(sso_session_name)
            .expect(format!("No sso-session found for {}", sso_session_name).as_str());

        if session.is_expired() {
            session.create_token(&aws_config).await;
        } else {
            if session.refresh_token(&aws_config).await.is_err() {
                // create a new token if refresh failed 
                session.create_token(&aws_config).await;
            }
        }
        let _ = self.config.write_sso_cache(sso_session_name, &session);

        let client = aws_sdk_sso::Client::new(&aws_config);
        // let accounts = client
        //     .list_accounts()
        //     .access_token(token.get_access_token().unwrap())
        //     .send()
        //     .await;
        // dbg!(accounts);
        let mut handles = Vec::with_capacity(session.profiles.len());
        for (name, profile) in session.profiles.iter() {
            println!(
                "Fetching credentials for profile: `{}`, account_id: `{}`, role: `{}`",
                name, profile.sso_account_id, profile.sso_role_name
            );
            let cred = client
                .get_role_credentials()
                .access_token(
                    session
                        .credentials
                        .as_ref()
                        .unwrap()
                        .get_access_token()
                        .unwrap(),
                )
                .account_id(profile.sso_account_id.as_str())
                .role_name(profile.sso_role_name.as_str())
                .send();
            handles.push((name, tokio::spawn(cred)));
        }
        for (name, handle) in handles {
            let cred = handle.await.unwrap();
            match cred {
                Ok(cred) => {
                    let cred = cred.role_credentials().unwrap();
                    self.config.set_credentials(
                        name.to_string(),
                        cred.access_key_id.clone().unwrap(),
                        cred.secret_access_key.clone().unwrap(),
                        cred.session_token.clone().unwrap(),
                    );
                }
                Err(err) => eprintln!(
                    "Failed to get credentials for profile: `{}`, error:`{}, {}`",
                    name,
                    err.to_string(),
                    err.into_service_error().to_string()
                ),
            }
        }
        self.config.write_credentials();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sso_token_cache() {
        let cache = serde_json::json!(
        {
            "startUrl": "https://x-abcdef0123.awsapps.com/start",
            "region": "us-east-1",
            "clientId": "FAKE",
            "clientSecret": "FAKE",
            "scopes": "sso:account:access",
            "registrationExpiresAt": "1970-01-01T00:00:00Z",
            "accessToken": "FAKE",
            "expiresAt": "1970-01-01T00:00:00Z",
            "refreshToken": "FAKE"
        });
        let session: SSOSession = serde_json::from_value(cache.clone()).unwrap();
        assert_eq!(serde_json::to_value(session).unwrap(), cache);
    }
}
