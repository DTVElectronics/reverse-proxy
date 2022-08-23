// Based on https://github.com/jaemk/cached/blob/71b23bf92999e0328df4b72ff2e4005763b20b01/src/stores/redis.rs

use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Display;
use std::marker::PhantomData;

const ENV_KEY: &str = "CACHED_REDIS_CONNECTION_STRING";
const DEFAULT_NAMESPACE: &str = "cached-redis-store:";

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RedisCacheBuildError {
    #[error("redis connection error")]
    Connection(#[from] redis::RedisError),
    #[error("Connection string not specified or invalid in env var {env_key:?}: {error:?}")]
    MissingConnectionString {
        env_key: String,
        error: std::env::VarError,
    },
}

#[derive(Error, Debug)]
pub enum RedisCacheError {
    #[error("redis error")]
    RedisCacheError(#[from] redis::RedisError),
    #[error("Error deserializing cached value {cached_value:?}: {error:?}")]
    CacheDeserializationError {
        cached_value: String,
        error: serde_json::Error,
    },
    #[error("Error serializing cached value: {error:?}")]
    CacheSerializationError { error: serde_json::Error },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CachedRedisValue<V> {
    pub(crate) value: V,
    pub(crate) version: Option<u64>,
}
impl<V> CachedRedisValue<V> {
    fn new(value: V) -> Self {
        Self {
            value,
            version: Some(1),
        }
    }
}

use async_trait::async_trait;
use cached::IOCachedAsync;

pub struct AsyncRedisCacheBuilder<K, V> {
    seconds: u64,
    refresh: bool,
    namespace: String,
    prefix: String,
    connection_string: Option<String>,
    _phantom_k: PhantomData<K>,
    _phantom_v: PhantomData<V>,
}

impl<K, V> AsyncRedisCacheBuilder<K, V>
where
    K: Display,
    V: Serialize + DeserializeOwned,
{
    /// Initialize a `RedisCacheBuilder`
    pub fn new<S: AsRef<str>>(prefix: S, seconds: u64) -> AsyncRedisCacheBuilder<K, V> {
        Self {
            seconds,
            refresh: false,
            namespace: DEFAULT_NAMESPACE.to_string(),
            prefix: prefix.as_ref().to_string(),
            connection_string: None,
            _phantom_k: Default::default(),
            _phantom_v: Default::default(),
        }
    }

    /// Specify the cache TTL/lifespan in seconds
    pub fn set_lifespan(mut self, seconds: u64) -> Self {
        self.seconds = seconds;
        self
    }

    /// Specify whether cache hits refresh the TTL
    pub fn set_refresh(mut self, refresh: bool) -> Self {
        self.refresh = refresh;
        self
    }

    /// Set the namespace for cache keys. Defaults to `cached-redis-store:`.
    /// Used to generate keys formatted as: `{namespace}{prefix}{key}`
    /// Note that no delimiters are implicitly added so you may pass
    /// an empty string if you want there to be no namespace on keys.
    pub fn set_namespace<S: AsRef<str>>(mut self, namespace: S) -> Self {
        self.namespace = namespace.as_ref().to_string();
        self
    }

    /// Set the prefix for cache keys
    /// Used to generate keys formatted as: `{namespace}{prefix}{key}`
    /// Note that no delimiters are implicitly added so you may pass
    /// an empty string if you want there to be no prefix on keys.
    pub fn set_prefix<S: AsRef<str>>(mut self, prefix: S) -> Self {
        self.prefix = prefix.as_ref().to_string();
        self
    }

    /// Set the connection string for redis
    pub fn set_connection_string(mut self, cs: &str) -> Self {
        self.connection_string = Some(cs.to_string());
        self
    }

    /// Return the current connection string or load from the env var: CACHED_REDIS_CONNECTION_STRING
    pub fn connection_string(&self) -> Result<String, RedisCacheBuildError> {
        match self.connection_string {
            Some(ref s) => Ok(s.to_string()),
            None => {
                std::env::var(ENV_KEY).map_err(|e| RedisCacheBuildError::MissingConnectionString {
                    env_key: ENV_KEY.to_string(),
                    error: e,
                })
            }
        }
    }

    async fn create_multiplexed_connection(
        &self,
    ) -> Result<redis::aio::MultiplexedConnection, RedisCacheBuildError> {
        let s = self.connection_string()?;
        let client = redis::Client::open(s)?;
        let conn = client.get_multiplexed_async_connection().await?;
        Ok(conn)
    }

    pub async fn build(self) -> Result<AsyncRedisCache<K, V>, RedisCacheBuildError> {
        Ok(AsyncRedisCache {
            seconds: self.seconds,
            refresh: self.refresh,
            connection_string: self.connection_string()?,
            multiplexed_connection: self.create_multiplexed_connection().await?,
            namespace: self.namespace,
            prefix: self.prefix,
            _phantom_k: self._phantom_k,
            _phantom_v: self._phantom_v,
        })
    }
}

/// Cache store backed by redis
///
/// Values have a ttl applied and enforced by redis.
/// Uses a `redis::aio::MultiplexedConnection` under the hood.
pub struct AsyncRedisCache<K, V> {
    pub(super) seconds: u64,
    pub(super) refresh: bool,
    pub(super) namespace: String,
    pub(super) prefix: String,
    connection_string: String,
    multiplexed_connection: redis::aio::MultiplexedConnection,
    _phantom_k: PhantomData<K>,
    _phantom_v: PhantomData<V>,
}

impl<K, V> AsyncRedisCache<K, V>
where
    K: Display + Send + Sync,
    V: Serialize + DeserializeOwned + Send + Sync,
{
    #[allow(clippy::new_ret_no_self)]
    /// Initialize an `AsyncRedisCacheBuilder`
    pub fn new<S: AsRef<str>>(prefix: S, seconds: u64) -> AsyncRedisCacheBuilder<K, V> {
        AsyncRedisCacheBuilder::new(prefix, seconds)
    }

    fn generate_key(&self, key: &K) -> String {
        format!("{}{}{}", self.namespace, self.prefix, key)
    }

    /// Return the redis connection string used
    pub fn connection_string(&self) -> String {
        self.connection_string.clone()
    }
}

#[async_trait]
impl<K, V> IOCachedAsync<K, V> for AsyncRedisCache<K, V>
where
    K: Display + Send + Sync,
    V: Serialize + DeserializeOwned + Send + Sync,
{
    type Error = RedisCacheError;

    /// Get a cached value
    async fn cache_get(&self, key: &K) -> Result<Option<V>, Self::Error> {
        let mut conn = self.multiplexed_connection.clone();
        let mut pipe = redis::pipe();
        let key = self.generate_key(key);

        pipe.get(key.clone());
        if self.refresh {
            pipe.expire(key, self.seconds as usize).ignore();
        }
        let res: (Option<String>,) = pipe.query_async(&mut conn).await?;
        match res.0 {
            None => Ok(None),
            Some(s) => {
                let v: CachedRedisValue<V> = serde_json::from_str(&s).map_err(|e| {
                    RedisCacheError::CacheDeserializationError {
                        cached_value: s,
                        error: e,
                    }
                })?;
                Ok(Some(v.value))
            }
        }
    }

    /// Set a cached value
    async fn cache_set(&self, key: K, val: V) -> Result<Option<V>, Self::Error> {
        let mut conn = self.multiplexed_connection.clone();
        let mut pipe = redis::pipe();
        let key = self.generate_key(&key);

        let val = CachedRedisValue::new(val);
        pipe.get(key.clone());
        pipe.set_ex::<String, String>(
            key,
            serde_json::to_string(&val)
                .map_err(|e| RedisCacheError::CacheSerializationError { error: e })?,
            self.seconds as usize,
        )
        .ignore();

        let res: (Option<String>,) = pipe.query_async(&mut conn).await?;
        match res.0 {
            None => Ok(None),
            Some(s) => {
                let v: CachedRedisValue<V> = serde_json::from_str(&s).map_err(|e| {
                    RedisCacheError::CacheDeserializationError {
                        cached_value: s,
                        error: e,
                    }
                })?;
                Ok(Some(v.value))
            }
        }
    }

    /// Remove a cached value
    async fn cache_remove(&self, key: &K) -> Result<Option<V>, Self::Error> {
        let mut conn = self.multiplexed_connection.clone();
        let mut pipe = redis::pipe();
        let key = self.generate_key(key);

        pipe.get(key.clone());
        pipe.del::<String>(key).ignore();
        let res: (Option<String>,) = pipe.query_async(&mut conn).await?;
        match res.0 {
            None => Ok(None),
            Some(s) => {
                let v: CachedRedisValue<V> = serde_json::from_str(&s).map_err(|e| {
                    RedisCacheError::CacheDeserializationError {
                        cached_value: s,
                        error: e,
                    }
                })?;
                Ok(Some(v.value))
            }
        }
    }

    /// Set the flag to control whether cache hits refresh the ttl of cached values, returns the old flag value
    fn cache_set_refresh(&mut self, refresh: bool) -> bool {
        let old = self.refresh;
        self.refresh = refresh;
        old
    }

    /// Return the lifespan of cached values (time to eviction)
    fn cache_lifespan(&self) -> Option<u64> {
        Some(self.seconds)
    }

    /// Set the lifespan of cached values, returns the old value
    fn cache_set_lifespan(&mut self, seconds: u64) -> Option<u64> {
        let old = self.seconds;
        self.seconds = seconds;
        Some(old)
    }
}
