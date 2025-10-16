//! HTTP server implementation

use crate::{
    error::Error,
    http_server::{config::HttpServerConfig, handlers::create_routes},
    prelude::*,
};
use std::net::{SocketAddr, TcpListener};
use tokio::task;

/// HTTP server for dynamic chain management
pub struct HttpServer {
    config: HttpServerConfig,
}

impl HttpServer {
    /// Create a new HTTP server
    pub fn new(config: HttpServerConfig) -> Self {
        Self { config }
    }

    /// Start the HTTP server
    pub async fn start(&self) -> Result<(), Error> {
        let addr = if self.config.port == 0 {
            // Dynamic port allocation
            let listener =
                TcpListener::bind(format!("{}:0", self.config.bind_address)).map_err(|e| {
                    format_err!(
                        crate::error::ErrorKind::ConfigError,
                        "failed to bind to dynamic port: {}",
                        e
                    )
                })?;
            let addr = listener.local_addr().map_err(|e| {
                format_err!(
                    crate::error::ErrorKind::ConfigError,
                    "failed to get local address: {}",
                    e
                )
            })?;
            info!(
                "Starting HTTP server on dynamically allocated port: {}",
                addr
            );
            info!("TMKMS_HTTP_PORT={}", addr.port());
            addr
        } else {
            // Fixed port
            let bind_address = format!("{}:{}", self.config.bind_address, self.config.port);
            let addr: SocketAddr = bind_address.parse().map_err(|e| {
                format_err!(
                    crate::error::ErrorKind::ConfigError,
                    "invalid bind address {}: {}",
                    bind_address,
                    e
                )
            })?;
            info!("Starting HTTP server on {}", addr);
            addr
        };

        let routes = create_routes();

        warp::serve(routes).run(addr).await;

        Ok(())
    }

    /// Start the HTTP server in a background task
    pub fn start_background(&self) -> task::JoinHandle<Result<(), Error>> {
        let config = self.config.clone();
        task::spawn(async move {
            let server = HttpServer::new(config);
            server.start().await
        })
    }
}
