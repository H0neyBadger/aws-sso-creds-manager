use crate::aws_sso::{Profile, SSOSession};
use aws_config::SdkConfig;
use ini::Ini;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::fs::{create_dir_all, File};
use std::io::{BufReader, BufWriter, Error};
use std::{collections::HashMap, path::PathBuf, str};

#[derive(Clone)]
pub struct Config {
    pub sessions: HashMap<String, SSOSession>,
    pub aws_config: SdkConfig,
    // aws_config_file: PathBuf,
    aws_sso_cache_path: PathBuf,
    aws_credentials_file: PathBuf,
    credentials: Ini,
}

impl Config {
    pub async fn load_from_env() -> Self {
        let home = std::env::var("HOME")
            .or(std::env::var("USERPROFILE"))
            .unwrap();
        let aws_path = PathBuf::from(home).join(".aws");

        // https://github.com/awslabs/aws-sdk-rust/issues/699
        let old_var = std::env::var("AWS_CONFIG_FILE").ok();
        std::env::set_var("AWS_CONFIG_FILE", "WORKAROUND_ISSUE_699");
        let aws_config = aws_config::load_from_env().await;
        let config_file = if let Some(cfg_file) = old_var {
            std::env::set_var("AWS_CONFIG_FILE", &cfg_file);
            PathBuf::from(cfg_file)
        } else {
            std::env::remove_var("AWS_CONFIG_FILE");
            aws_path.join("config")
        };

        let credentials_file = if let Ok(cfg) = std::env::var("AWS_SHARED_CREDENTIALS_FILE") {
            PathBuf::from(cfg)
        } else {
            aws_path.join("credentials")
        };
        let sso_cache_path = aws_path.join("sso/cache");
        let config = Self::load_config(config_file.to_str().unwrap()).unwrap_or(Ini::new());
        let credentials: Ini =
            Self::load_config(credentials_file.to_str().unwrap()).unwrap_or(Ini::new());

        let sessions = Self::load_session(config);
        let sessions = sessions
            .into_iter()
            .map(|(name, session)| {
                let cached_session: Option<SSOSession> =
                    Self::load_sso_cache(&sso_cache_path, name.as_str());
                // merge from cache
                let session = match cached_session {
                    Some(cache) => session.merge_from_cache(cache),
                    _ => session,
                };
                (name, session)
            })
            .collect();
        Self {
            sessions: sessions,
            aws_config: aws_config,
            // aws_config_file: config_file,
            aws_sso_cache_path: sso_cache_path,
            aws_credentials_file: credentials_file,
            credentials: credentials,
        }
    }

    fn load_config(filename: &str) -> Result<Ini, ini::Error> {
        Ini::load_from_file(filename)
    }

    fn load_sso_cache<T>(sso_path: &PathBuf, name: &str) -> Option<T>
    where
        T: DeserializeOwned,
    {
        let mut hasher = Sha1::new();
        hasher.update(name.as_bytes());
        let name = format!("{:x}.json", hasher.finalize());
        let path = sso_path.join(name);
        let file = File::open(path).ok()?;
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).ok()
    }

    pub fn write_sso_cache<T>(&self, name: &str, data: &T) -> Result<(), Error>
    where
        T: Serialize,
    {
        let mut hasher = Sha1::new();
        hasher.update(name.as_bytes());
        let name = format!("{:x}.json", hasher.finalize());
        let _ = create_dir_all(&self.aws_sso_cache_path);
        let path = self.aws_sso_cache_path.join(name);
        let file = File::create(path)?;
        let write = BufWriter::new(file);
        serde_json::to_writer_pretty(write, data).unwrap();
        Ok(())
    }

    fn load_session(ini: Ini) -> HashMap<String, SSOSession> {
        let mut profiles: HashMap<String, Profile> = HashMap::new();
        let mut sessions: HashMap<String, SSOSession> = HashMap::new();
        let sec_re = Regex::new("^(?P<kind>profile|sso-session) (?P<name>.*)").unwrap();
        for (sec, prop) in ini.iter() {
            // println!("Section: {:?}", sec);
            if sec.is_none() {
                continue;
            }
            let cap = sec_re.captures(sec.unwrap());
            match cap {
                Some(value) if "sso-session".eq(&value["kind"]) => {
                    sessions.insert(
                        String::from(&value["name"]),
                        SSOSession::new(String::from(prop.get("sso_start_url").unwrap()))
                            .set_region(prop.get("sso_region").and_then(|s| Some(String::from(s))))
                            .set_scopes(
                                prop.get("sso_registration_scopes")
                                    .and_then(|s| Some(String::from(s))),
                            ), // fixme .set_credentials()
                    );
                }
                Some(value) if "profile".eq(&value["kind"]) => {
                    profiles.insert(
                        String::from(&value["name"]),
                        Profile::new(
                            String::from(prop.get("sso_session").unwrap()),
                            String::from(prop.get("sso_account_id").unwrap()),
                            String::from(prop.get("sso_role_name").unwrap()),
                        )
                        .set_region(prop.get("region").and_then(|s| Some(String::from(s)))),
                    );
                }
                _ => continue,
            }
        }
        for (name, profile) in profiles.into_iter() {
            let session = profile.get_session_name();
            let session = sessions.get_mut(session);
            if let Some(session) = session {
                session.insert_profile(name, profile);
            }
        }
        sessions
    }

    pub fn session(&mut self, name: &str) -> Option<SSOSession> {
        self.sessions.remove(name)
    }

    // pub fn get_session(&self, name: &str) -> Option<&SSOSession> {
    //     self.sessions.get(name)
    // }

    // pub fn get_mut_session(&mut self, name: &str) -> Option<&mut SSOSession> {
    //     self.sessions.get_mut(name)
    // }

    pub fn set_credentials(
        &mut self,
        name: String,
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    ) {
        self.credentials
            .with_section(Some(name))
            .set("aws_access_key_id", access_key_id)
            .set("aws_secret_access_key", secret_access_key)
            .set("aws_session_token", session_token);
    }

    pub fn write_credentials(&self) {
        self.credentials
            .write_to_file(self.aws_credentials_file.to_str().unwrap())
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_config() {
        let config = r#"
[profile example]
sso_session = default
sso_account_id = 1234567890
sso_role_name = 1234567890.read
region = us-east-1

[sso-session default]
sso_start_url = https://x-abcdef0123.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access
        "#;
        let test = Ini::load_from_str(config).unwrap();
        let ret = Config::load_session(test);
        let expect: HashMap<String, SSOSession> = HashMap::from([(
            String::from("default"),
            SSOSession::new(String::from("https://x-abcdef0123.awsapps.com/start"))
                .set_region(Some(String::from("us-east-1")))
                .set_scopes(Some(String::from("sso:account:access")))
                .set_profile(
                    String::from("example"),
                    Profile::new(
                        String::from("default"),
                        String::from("1234567890"),
                        String::from("1234567890.read"),
                    )
                    .set_region(Some(String::from("us-east-1"))),
                ),
        )]);
        assert_eq!(ret, expect);
    }
}
