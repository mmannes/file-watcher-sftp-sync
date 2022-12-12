use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub debounce_timeout: u64,
    pub remote_server: Option<RemoteServer>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteServer {
    pub address: String,
    pub user: String,
    pub password: Option<String>,
    pub path: String,
    pub allowed_extensions: Option<Vec<String>>,
}
