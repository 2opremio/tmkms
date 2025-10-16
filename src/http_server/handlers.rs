//! HTTP request handlers

use crate::{
    chain::{self, Chain},
    config::KmsConfig,
    error::Error,
    http_server::models::*,
    prelude::*,
};
use serde_json;
use std::fs;
use std::path::Path;
use warp::{Filter, Rejection, Reply, http::StatusCode, reply};

/// Simple error wrapper for warp rejection
#[derive(Debug)]
#[allow(dead_code)] // Field is used by Debug trait
struct ConfigError(String);

impl ConfigError {
    #[allow(dead_code)]
    fn new(message: String) -> Self {
        Self(message)
    }
}

impl warp::reject::Reject for ConfigError {}

/// Atomic configuration update utility
fn atomic_config_update<F>(update_fn: F) -> Result<(), Error>
where
    F: FnOnce(&mut KmsConfig) -> Result<(), Error>,
{
    // Get the config file path from the HTTP server config or fall back to application
    let config_path = APP
        .config()
        .http_server
        .as_ref()
        .and_then(|http_config| http_config.config_file_path.clone())
        .or_else(|| APP.get_config_file_path())
        .ok_or_else(|| {
            format_err!(
                crate::error::ErrorKind::ConfigError,
                "No config file path available"
            )
        })?;

    info!("HTTP server using config file path: {:?}", config_path);
    info!("Config file exists: {}", config_path.exists());

    let temp_filename = format!("{}.tmp", config_path.file_name().unwrap().to_string_lossy());
    let temp_path = config_path.parent().unwrap().join(&temp_filename);

    // Load current config
    let mut config = load_config_from_file(&config_path)?;

    // Apply updates
    update_fn(&mut config)?;

    // Write to temporary file
    let config_toml = toml::to_string_pretty(&config).map_err(|e| {
        format_err!(
            crate::error::ErrorKind::ConfigError,
            "failed to serialize config: {}",
            e
        )
    })?;

    fs::write(&temp_path, config_toml).map_err(|e| {
        format_err!(
            crate::error::ErrorKind::ConfigError,
            "failed to write temp config: {}",
            e
        )
    })?;

    // Atomic rename - this is the critical operation
    fs::rename(&temp_path, config_path).map_err(|e| {
        format_err!(
            crate::error::ErrorKind::ConfigError,
            "failed to rename config file: {}",
            e
        )
    })?;

    Ok(())
}

/// Load configuration from file
fn load_config_from_file(path: &Path) -> Result<KmsConfig, Error> {
    let config_content = fs::read_to_string(path).map_err(|e| {
        format_err!(
            crate::error::ErrorKind::ConfigError,
            "failed to read config file: {}",
            e
        )
    })?;

    Ok(toml::from_str::<KmsConfig>(&config_content).map_err(|e| {
        format_err!(
            crate::error::ErrorKind::ConfigError,
            "failed to parse config: {}",
            e
        )
    })?)
}

/// Merge provider configuration with existing providers
fn merge_provider_config(
    existing: &mut crate::config::provider::ProviderConfig,
    new: &crate::config::provider::ProviderConfig,
) {
    #[cfg(feature = "softsign")]
    {
        existing.softsign.extend(new.softsign.clone());
    }

    #[cfg(feature = "yubihsm")]
    {
        existing.yubihsm.extend(new.yubihsm.clone());
    }

    #[cfg(feature = "ledger")]
    {
        existing.ledgertm.extend(new.ledgertm.clone());
    }

    #[cfg(feature = "fortanixdsm")]
    {
        existing.fortanixdsm.extend(new.fortanixdsm.clone());
    }
}

/// Validate the add chain request
fn validate_add_chain_request(request: &AddChainRequest) -> Result<(), ErrorResponse> {
    if request.validator.chain_id != request.chain.id {
        return Err(ErrorResponse {
            error: format!(
                "Chain ID mismatch: validator chain_id {} != chain id {}",
                request.validator.chain_id, request.chain.id
            ),
        });
    }
    Ok(())
}

/// Update the configuration file with the new chain
fn update_config_file(request: &AddChainRequest) -> Result<(), Error> {
    atomic_config_update(|config| {
        // Add chain
        config.chain.push(request.chain.clone());

        // Add validator
        config.validator.push(request.validator.clone());

        // Add provider - merge with existing providers
        merge_provider_config(&mut config.providers, &request.provider);

        Ok(())
    })
}

/// Register the chain in the in-memory registry
fn register_chain_in_memory(chain_config: &crate::config::chain::ChainConfig) -> Result<(), Error> {
    let chain = Chain::from_config(chain_config)?;
    chain::REGISTRY.register(chain)?;
    Ok(())
}

/// Create a success response for chain addition
fn create_success_response(chain_id: &str) -> Result<reply::WithStatus<reply::Json>, Rejection> {
    let response = AddChainResponse {
        message: format!("Successfully added chain {}", chain_id),
        chain_id: chain_id.to_string(),
    };
    Ok(reply::with_status(
        reply::json(&response),
        StatusCode::CREATED,
    ))
}

/// Create an error response
fn create_error_response(
    message: &str,
    status: StatusCode,
) -> Result<reply::WithStatus<reply::Json>, Rejection> {
    let error = ErrorResponse {
        error: message.to_string(),
    };
    Ok(reply::with_status(reply::json(&error), status))
}

/// Add a new chain endpoint
pub async fn add_chain(request: AddChainRequest) -> Result<impl Reply, Rejection> {
    info!("Adding new chain: {}", request.chain.id);
    info!("HTTP server received add_chain request");

    let chain_id = request.chain.id.clone();

    // Validate the request
    if let Err(error_response) = validate_add_chain_request(&request) {
        return Ok(reply::with_status(
            reply::json(&error_response),
            StatusCode::BAD_REQUEST,
        ));
    }

    // Update configuration file
    if let Err(e) = update_config_file(&request) {
        error!("Failed to update configuration: {}", e);
        return create_error_response(
            &format!("Failed to update configuration: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    // Register chain in memory
    if let Err(e) = register_chain_in_memory(&request.chain) {
        error!("Failed to register chain in memory: {}", e);
        return create_error_response(
            &format!("Failed to register chain in memory: {}", e),
            StatusCode::INTERNAL_SERVER_ERROR,
        );
    }

    info!("Successfully added chain: {}", chain_id);
    create_success_response(&chain_id.to_string())
}

/// List chains endpoint
pub async fn list_chains() -> Result<impl Reply, Rejection> {
    let registry = chain::REGISTRY.get();
    let chains: Vec<String> = registry
        .get_all_chain_ids()
        .into_iter()
        .map(|id| id.to_string())
        .collect();

    let response = ListChainsResponse { chains };
    Ok(reply::json(&response))
}

/// Health check endpoint
pub async fn health_check() -> Result<impl Reply, Rejection> {
    Ok(reply::json(&serde_json::json!({
        "status": "healthy",
        "service": "tmkms-http-server"
    })))
}

/// Create the API routes
pub fn create_routes() -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let add_chain_route = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("chains"))
        .and(warp::post())
        .and(warp::body::json())
        .and_then(add_chain);

    let list_chains_route = warp::path("api")
        .and(warp::path("v1"))
        .and(warp::path("chains"))
        .and(warp::get())
        .and_then(list_chains);

    let health_route = warp::path("health").and(warp::get()).and_then(health_check);

    add_chain_route.or(list_chains_route).or(health_route).with(
        warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type"])
            .allow_methods(vec!["GET", "POST"]),
    )
}
