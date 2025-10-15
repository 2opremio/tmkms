//! Integration tests for HTTP server functionality

use serde_json;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};
use tmkms::config::chain::ChainConfig;
use tmkms::config::provider::softsign::{SoftPrivateKey, SoftsignConfig};
use tmkms::config::provider::{KeyType, ProviderConfig};
use tmkms::config::validator::ValidatorConfig;
use tmkms::config::{CONFIG_FILE_NAME, KmsConfig};
use tmkms::key_utils;
use tmkms::keyring::format::Format;

/// Test server manager for handling TMKMS process lifecycle
struct TestServerManager {
    process: Child,
    port: u16,
    _stdout_handle: thread::JoinHandle<()>,
    _stderr_handle: thread::JoinHandle<()>,
}

impl TestServerManager {
    /// Start TMKMS with HTTP server and wait for it to be ready
    fn start(config_path: &Path) -> Self {
        let mut process = start_kms_with_http_server(config_path);

        // Shared logs storage
        let logs = Arc::new(Mutex::new(Vec::new()));

        // Capture stdout to parse the port from logs
        let stdout = process.stdout.take().expect("Failed to capture stdout");
        let stderr = process.stderr.take().expect("Failed to capture stderr");

        let logs_clone = logs.clone();
        let (port, stdout_handle) = parse_port_from_logs(stdout, logs_clone);

        // Capture stderr logs
        let logs_clone = logs.clone();
        let stderr_handle = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                if let Ok(line) = line {
                    if let Ok(mut logs) = logs_clone.lock() {
                        logs.push(format!("STDERR: {}", line));
                    }
                }
            }
        });

        println!("Found HTTP server on port: {}", port);

        // Wait for server to be ready
        wait_for_server_ready(port);

        let server_manager = Self {
            process,
            port,
            _stdout_handle: stdout_handle,
            _stderr_handle: stderr_handle,
        };

        // Set up panic hook to print logs on test failure
        let logs_for_panic = logs;
        let original_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |panic_info| {
            // Print logs from the captured logs reference
            if let Ok(logs) = logs_for_panic.lock() {
                if !logs.is_empty() {
                    println!("\n=== TMKMS Server Logs ===");
                    for log in logs.iter() {
                        println!("{}", log);
                    }
                    println!("=== End of Logs ===\n");
                }
            }
            original_hook(panic_info);
        }));

        server_manager
    }

    /// Get the allocated port
    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for TestServerManager {
    fn drop(&mut self) {
        // Clean up - use a more robust approach
        if let Err(e) = self.process.kill() {
            eprintln!("Warning: Failed to kill KMS process: {}", e);
        }
        // Wait a bit for the process to actually terminate
        thread::sleep(Duration::from_millis(100));
        // Force kill if still running
        if let Ok(Some(_)) = self.process.try_wait() {
            // Process already terminated
        } else {
            // Process still running, try to force kill
            if let Err(e) = self.process.kill() {
                eprintln!("Warning: Failed to force kill KMS process: {}", e);
            }
        }
    }
}

/// Wait for the HTTP server to be ready
fn wait_for_server_ready(port: u16) {
    let mut attempts = 0;
    let max_attempts = 10;
    while attempts < max_attempts {
        if let Ok(response) = reqwest::blocking::Client::new()
            .get(&format!("http://127.0.0.1:{}/health", port))
            .timeout(Duration::from_secs(1))
            .send()
        {
            if response.status().is_success() {
                return;
            }
        }
        thread::sleep(Duration::from_millis(500));
        attempts += 1;
    }

    panic!("HTTP server failed to start within timeout");
}

/// Parse the allocated port from the server logs
fn parse_port_from_logs(
    stdout: std::process::ChildStdout,
    logs: Arc<Mutex<Vec<String>>>,
) -> (u16, thread::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel();

    let stdout_handle = thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            if let Ok(line) = line {
                // Store all stdout logs
                if let Ok(mut logs) = logs.lock() {
                    logs.push(format!("STDOUT: {}", line));
                }

                // Check if this line contains the port
                if let Some(port) = extract_port_from_log_line(&line) {
                    let _ = tx.send(port);
                    break;
                }
            }
        }
    });

    // Wait for the port to be parsed (with timeout)
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(port) => (port, stdout_handle),
        Err(_) => panic!("Failed to parse port from server logs within timeout"),
    }
}

/// Extract port from a log line containing "TMKMS_HTTP_PORT="
fn extract_port_from_log_line(line: &str) -> Option<u16> {
    if let Some(start) = line.find("TMKMS_HTTP_PORT=") {
        let port_str = &line[start + 16..]; // Skip "TMKMS_HTTP_PORT="
        if let Some(end) = port_str.find(|c: char| c.is_whitespace() || c == '\n' || c == '\r') {
            port_str[..end].parse().ok()
        } else {
            port_str.parse().ok()
        }
    } else {
        None
    }
}

/// Test that adding a new chain via HTTP preserves existing chains in the config file
#[test]
fn test_add_chain_preserves_existing_config() {
    // Create a temporary directory for this test
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join(CONFIG_FILE_NAME);

    // Create dummy key files for softsign providers
    create_dummy_key_files(&temp_dir);

    // Create initial config with existing chains (using dynamic port)
    let initial_config = create_initial_config(temp_dir.path());
    let initial_config_toml =
        toml::to_string_pretty(&initial_config).expect("Failed to serialize initial config");
    fs::write(&config_path, initial_config_toml).expect("Failed to write initial config");

    // Start TMKMS with HTTP server using the test manager
    let server_manager = TestServerManager::start(&config_path);
    let allocated_port = server_manager.port();

    // Verify initial config is loaded correctly
    let loaded_config = load_config_from_file(&config_path);
    assert_eq!(loaded_config.chain.len(), 2, "Should have 2 initial chains");
    assert_eq!(
        loaded_config.validator.len(),
        2,
        "Should have 2 initial validators"
    );

    // Add a new chain via HTTP
    let new_chain_request = create_new_chain_request(temp_dir.path());
    println!(
        "Sending HTTP request to port {}: {:?}",
        allocated_port, new_chain_request
    );
    let response = add_chain_via_http(&new_chain_request, allocated_port);

    // Verify HTTP response
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .unwrap_or_else(|_| "Failed to read response body".to_string());
        panic!("HTTP request failed with status {}: {}", status, body);
    }

    // Verify config file was updated atomically
    let updated_config = load_config_from_file(&config_path);

    // Check that we now have 3 chains (2 original + 1 new)
    assert_eq!(
        updated_config.chain.len(),
        3,
        "Should have 3 chains after adding one"
    );
    assert_eq!(
        updated_config.validator.len(),
        3,
        "Should have 3 validators after adding one"
    );

    // Verify the first two chains are exactly the same as before
    for i in 0..2 {
        assert_eq!(
            updated_config.chain[i], initial_config.chain[i],
            "Original chain {} should be unchanged",
            i
        );
        assert_eq!(
            updated_config.validator[i], initial_config.validator[i],
            "Original validator {} should be unchanged",
            i
        );
    }

    // Verify that existing provider configurations are preserved
    #[cfg(feature = "softsign")]
    {
        assert_eq!(
            updated_config.providers.softsign.len(),
            3,
            "Should have 3 softsign providers after adding one"
        );
        // Check that the first two softsign providers are unchanged
        for i in 0..2 {
            assert_eq!(
                updated_config.providers.softsign[i], initial_config.providers.softsign[i],
                "Original softsign provider {} should be unchanged",
                i
            );
        }
        // Verify the new provider was added correctly
        let new_provider = &updated_config.providers.softsign[2];
        assert_eq!(
            new_provider.chain_ids,
            vec!["test_chain_3".parse().unwrap()]
        );
        assert_eq!(new_provider.key_type, KeyType::Consensus);
    }

    // Verify the new chain was added correctly
    let new_chain = &updated_config.chain[2];
    assert_eq!(new_chain.id.to_string(), "test_chain_3");
    assert_eq!(new_chain.sign_extensions, false);

    let new_validator = &updated_config.validator[2];
    assert_eq!(new_validator.chain_id.to_string(), "test_chain_3");
    assert_eq!(
        new_validator.addr.to_string(),
        "tcp://deadbeefdeadbeefdeadbeefdeadbeefdeadbeef@localhost:26660"
    );
}

/// Test that config file updates are atomic (no partial writes)
#[test]
fn test_atomic_config_update() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join(CONFIG_FILE_NAME);

    // Create dummy key files for softsign providers
    create_dummy_key_files(&temp_dir);

    // Create initial config
    let initial_config = create_initial_config(temp_dir.path());
    let initial_config_toml =
        toml::to_string_pretty(&initial_config).expect("Failed to serialize initial config");
    fs::write(&config_path, initial_config_toml).expect("Failed to write initial config");

    // Start TMKMS with HTTP server using the test manager
    let server_manager = TestServerManager::start(&config_path);
    let allocated_port = server_manager.port();

    // Verify initial state
    let initial_content = fs::read_to_string(&config_path).expect("Failed to read initial config");
    assert!(initial_content.contains("test_chain_1"));
    assert!(initial_content.contains("test_chain_2"));
    assert!(!initial_content.contains("test_chain_3"));

    // Add new chain
    let new_chain_request = create_new_chain_request(temp_dir.path());
    let response = add_chain_via_http(&new_chain_request, allocated_port);
    if !response.status().is_success() {
        let status = response.status();
        let body = response
            .text()
            .unwrap_or_else(|_| "Failed to read response body".to_string());
        panic!("HTTP request failed with status {}: {}", status, body);
    }

    // Verify final state - should contain all chains
    let final_content = fs::read_to_string(&config_path).expect("Failed to read final config");
    assert!(final_content.contains("test_chain_1"));
    assert!(final_content.contains("test_chain_2"));
    assert!(final_content.contains("test_chain_3"));

    // Verify no temporary files are left behind
    let temp_file = temp_dir.path().join(format!("{}.tmp", CONFIG_FILE_NAME));
    assert!(
        !temp_file.exists(),
        "Temporary config file should not exist"
    );

    // Server cleanup is handled automatically by TestServerManager's Drop trait
}

/// Test that invalid requests don't corrupt the config file
#[test]
fn test_invalid_request_preserves_config() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join(CONFIG_FILE_NAME);

    // Create dummy key files for softsign providers
    create_dummy_key_files(&temp_dir);

    // Create initial config
    let initial_config = create_initial_config(temp_dir.path());
    let initial_config_toml =
        toml::to_string_pretty(&initial_config).expect("Failed to serialize initial config");
    fs::write(&config_path, initial_config_toml).expect("Failed to write initial config");

    // Start TMKMS with HTTP server using the test manager
    let server_manager = TestServerManager::start(&config_path);
    let allocated_port = server_manager.port();

    // Store initial config content
    let initial_content = fs::read_to_string(&config_path).expect("Failed to read initial config");

    // Send invalid request (chain ID mismatch)
    let invalid_request = create_invalid_chain_request(temp_dir.path());
    let response = add_chain_via_http(&invalid_request, allocated_port);

    // Should return error
    if !response.status().is_client_error() {
        let status = response.status();
        let body = response
            .text()
            .unwrap_or_else(|_| "Failed to read response body".to_string());
        panic!("Expected client error but got status {}: {}", status, body);
    }

    // Config file should be unchanged
    let final_content = fs::read_to_string(&config_path).expect("Failed to read final config");
    assert_eq!(
        initial_content, final_content,
        "Config file should be unchanged after invalid request"
    );

    // Server cleanup is handled automatically by TestServerManager's Drop trait
}

/// Test to demonstrate log printing on failure (commented out by default)
#[test]
#[ignore] // Ignore this test by default - uncomment to test log printing on failure
fn test_log_printing_on_failure() {
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join(CONFIG_FILE_NAME);

    // Create dummy key files for softsign providers
    create_dummy_key_files(&temp_dir);

    // Create initial config
    let initial_config = create_initial_config(temp_dir.path());
    let initial_config_toml =
        toml::to_string_pretty(&initial_config).expect("Failed to serialize initial config");
    fs::write(&config_path, initial_config_toml).expect("Failed to write initial config");

    // Start TMKMS with HTTP server using the test manager
    let _server_manager = TestServerManager::start(&config_path);

    // This will cause the test to fail and trigger log printing
    panic!("This test intentionally fails to demonstrate log printing");
}

// Helper functions

fn create_dummy_key_files(temp_dir: &tempfile::TempDir) {
    // Create valid base64-encoded ed25519 key files for softsign providers
    let key_files = ["test-key-1.key", "test-key-2.key", "test-key-3.key"];
    for key_file in &key_files {
        let key_path = temp_dir.path().join(key_file);
        key_utils::generate_key(&key_path).expect("Failed to create key file");
    }

    // Create secret connection keys for validators
    let secret_key_path = temp_dir.path().join("secret_connection.key");
    key_utils::generate_key(&secret_key_path).expect("Failed to create secret connection key");
}

fn create_initial_config(temp_dir_path: &Path) -> KmsConfig {
    KmsConfig {
        chain: vec![
            ChainConfig {
                id: "test_chain_1".parse().unwrap(),
                key_format: Format::Bech32 {
                    account_key_prefix: "testpub".to_string(),
                    consensus_key_prefix: "testvalconspub".to_string(),
                },
                sign_extensions: false,
                state_file: None,
                state_hook: None,
            },
            ChainConfig {
                id: "test_chain_2".parse().unwrap(),
                key_format: Format::Bech32 {
                    account_key_prefix: "testpub2".to_string(),
                    consensus_key_prefix: "testvalconspub2".to_string(),
                },
                sign_extensions: true,
                state_file: None,
                state_hook: None,
            },
        ],
        validator: vec![
            ValidatorConfig {
                addr: "tcp://deadbeefdeadbeefdeadbeefdeadbeefdeadbeef@localhost:26658"
                    .parse()
                    .unwrap(),
                chain_id: "test_chain_1".parse().unwrap(),
                reconnect: true,
                timeout: None,
                secret_key: Some(temp_dir_path.join("secret_connection.key")),
                max_height: None,
                protocol_version: None,
            },
            ValidatorConfig {
                addr: "tcp://deadbeefdeadbeefdeadbeefdeadbeefdeadbeef@localhost:26659"
                    .parse()
                    .unwrap(),
                chain_id: "test_chain_2".parse().unwrap(),
                reconnect: false,
                timeout: Some(30),
                secret_key: Some(temp_dir_path.join("secret_connection.key")),
                max_height: None,
                protocol_version: None,
            },
        ],
        providers: {
            let mut providers = ProviderConfig::default();
            #[cfg(feature = "softsign")]
            {
                providers.softsign = vec![
                    SoftsignConfig {
                        chain_ids: vec!["test_chain_1".parse().unwrap()],
                        key_type: KeyType::Account,
                        key_format: None,
                        path: SoftPrivateKey::new(temp_dir_path.join("test-key-1.key")),
                    },
                    SoftsignConfig {
                        chain_ids: vec!["test_chain_2".parse().unwrap()],
                        key_type: KeyType::Account,
                        key_format: None,
                        path: SoftPrivateKey::new(temp_dir_path.join("test-key-2.key")),
                    },
                ];
            }
            providers
        },
        http_server: Some(tmkms::http_server::HttpServerConfig {
            bind_address: "127.0.0.1".to_string(),
            port: 0, // Use dynamic port allocation
            config_file_path: None,
        }),
    }
}

fn create_new_chain_request(temp_dir_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "chain": {
            "id": "test_chain_3",
            "key_format": {
                "type": "bech32",
                "account_key_prefix": "testpub3",
                "consensus_key_prefix": "testvalconspub3"
            },
            "sign_extensions": false
        },
        "validator": {
            "addr": "tcp://deadbeefdeadbeefdeadbeefdeadbeefdeadbeef@localhost:26660",
            "chain_id": "test_chain_3",
            "reconnect": true,
            "secret_key": temp_dir_path.join("secret_connection.key").to_string_lossy()
        },
        "provider": {
            "softsign": [{
                "chain_ids": ["test_chain_3"],
                "key_type": "consensus",
                "path": temp_dir_path.join("test-key-3.key").to_string_lossy()
            }]
        }
    })
}

fn create_invalid_chain_request(temp_dir_path: &Path) -> serde_json::Value {
    serde_json::json!({
        "chain": {
            "id": "test_chain_3",
            "key_format": {
                "type": "bech32",
                "account_key_prefix": "testpub3",
                "consensus_key_prefix": "testvalconspub3"
            },
            "sign_extensions": false
        },
        "validator": {
            "addr": "tcp://deadbeefdeadbeefdeadbeefdeadbeefdeadbeef@localhost:26660",
            "chain_id": "test_chain_4", // Mismatch with chain ID
            "reconnect": true,
            "secret_key": temp_dir_path.join("secret_connection.key").to_string_lossy()
        },
        "provider": {
            "softsign": [{
                "chain_ids": ["test_chain_3"],
                "key_type": "consensus",
                "path": temp_dir_path.join("test-key-3.key").to_string_lossy()
            }]
        }
    })
}

fn start_kms_with_http_server(config_path: &Path) -> Child {
    // Get the absolute path to the tmkms binary
    let binary_path = std::env::current_dir()
        .expect("Failed to get current directory")
        .join("target/debug/tmkms");

    // Pass the config path explicitly to the TMKMS process
    Command::new(binary_path)
        .args(&[
            "start",
            "--config",
            config_path.to_str().expect("Invalid config path"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start KMS process")
}

fn load_config_from_file(path: &Path) -> KmsConfig {
    let content = fs::read_to_string(path).expect("Failed to read config file");
    toml::from_str(&content).expect("Failed to parse config file")
}

fn add_chain_via_http(request: &serde_json::Value, port: u16) -> reqwest::blocking::Response {
    let client = reqwest::blocking::Client::new();
    let url = format!("http://127.0.0.1:{}/api/v1/chains", port);
    println!("Making HTTP POST request to: {}", url);
    let response = client
        .post(&url)
        .json(request)
        .send()
        .expect("Failed to send HTTP request");
    println!("HTTP response status: {}", response.status());
    response
}
