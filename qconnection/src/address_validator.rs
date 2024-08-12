use std::{
    collections::VecDeque,
    fs::File,
    io::{self, Read, Write},
    path,
    sync::{Arc, Mutex},
    task::Waker,
};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct NewTokenQueue(VecDeque<(Vec<u8>, u64)>);

impl NewTokenQueue {
    fn remove_expired(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        self.0.retain(|(_, exp)| exp > &now);
    }
}

#[derive(Clone)]
pub struct ArcNewTokens {
    path: Arc<String>,
    tokens: Arc<DashMap<String, NewTokenQueue>>,
}

impl ArcNewTokens {
    pub fn new(path: &str) -> Self {
        Self {
            path: Arc::new(path.to_string()),
            tokens: Arc::new(DashMap::new()),
        }
    }

    pub fn contains(&self, name: &str, token: &[u8]) -> bool {
        let tokens = self.tokens.get(name);
        match tokens {
            Some(item) => {
                let tokens = item.value();
                tokens.0.iter().any(|(t, _)| t == token)
            }
            None => {
                if let Ok(tokens) = self.read_token_file(name) {
                    let contains = tokens.0.iter().any(|(t, _)| t == token);
                    self.tokens.insert(name.to_string(), tokens);
                    contains
                } else {
                    false
                }
            }
        }
    }

    pub fn add_token(&self, name: &str, token: Vec<u8>, exp: u64) -> bool {
        //  A server MUST ensure that every NEW_TOKEN frame it sends is unique across all clients.
        if self.contains(name, &token) {
            return false;
        }

        // TODO: TEST IT
        let mut tokens = self
            .tokens
            .entry(name.to_string())
            .or_insert(NewTokenQueue(VecDeque::new()));
        tokens.0.push_back((token, exp));

        self.flush();
        true
    }

    pub fn pop_token(&self, name: &str) -> Option<Vec<u8>> {
        let ret = self
            .tokens
            .get_mut(name)
            .and_then(|mut item| {
                let tokens = item.value_mut();
                tokens.remove_expired();
                tokens.0.pop_front().map(|(token, _)| token)
            })
            .or_else(|| {
                self.read_token_file(name).ok().and_then(|tokens| {
                    let token = tokens.0.front().map(|(token, _)| token.clone());
                    self.tokens.insert(name.to_string(), tokens);
                    token
                })
            });
        self.flush();
        ret
    }

    fn read_token_file(&self, name: &str) -> io::Result<NewTokenQueue> {
        let file_path = format!("{}/{}.json", self.path, name);
        let mut file = File::open(path::Path::new(&file_path))?;
        let mut contents = String::new();

        file.read_to_string(&mut contents)?;
        let mut tokens: NewTokenQueue = serde_json::from_str(&contents).unwrap();

        tokens.remove_expired();
        Ok(tokens)
    }

    fn flush(&self) {
        for mut entry in self.tokens.iter_mut() {
            let key = entry.key().to_string();
            let tokens = entry.value_mut();
            tokens.remove_expired();
            if tokens.0.is_empty() {
                self.tokens.remove(&key);
                continue;
            }
            let file_path = format!("{}/{}.json", self.path, key);
            let mut file = File::create(path::Path::new(&file_path)).unwrap();

            let contents = serde_json::to_string(&tokens).unwrap();
            file.write_all(contents.as_bytes()).unwrap();
        }
    }
}

enum Validator {
    Server,
    Client,
}

struct ArcAddressValidator(Arc<Mutex<Validator>>);

struct ServerVaditor {
    name: String,
    retry_toen: Option<Vec<u8>>,
    new_tokens: ArcNewTokens,
    waker: Option<Waker>,
}

impl ServerVaditor {
    fn new(name: &str, tokens: ArcNewTokens) -> Self {
        Self {
            name: name.to_string(),
            retry_toen: None,
            new_tokens: tokens,
            waker: None,
        }
    }

    fn validate_token(&mut self, token: &[u8]) -> bool {
        if let Some(token) = self.retry_toen.as_ref() {
            if token == token {
                return true;
            }
        }
        self.new_tokens.contains(&self.name, token)
    }

    fn write_retry_token(&mut self, token: Vec<u8>) {
        self.retry_toen = Some(token);
    }
}
