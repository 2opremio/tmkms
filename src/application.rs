//! Abscissa `Application` for the KMS

use crate::{commands::KmsCommand, config::KmsConfig};
use abscissa_core::{
    Application, FrameworkError, StandardPaths,
    application::{self, AppCell},
    config::{self, CfgCell},
    trace,
};

/// Application state
pub static APP: AppCell<KmsApplication> = AppCell::new();

/// The `tmkms` application
#[derive(Debug, Default)]
pub struct KmsApplication {
    /// Application configuration.
    config: CfgCell<KmsConfig>,

    /// Application state.
    state: application::State<Self>,

    /// Path to the configuration file (set at runtime)
    config_file_path: std::sync::Mutex<Option<std::path::PathBuf>>,
}

impl Application for KmsApplication {
    /// Entrypoint command for this application.
    type Cmd = KmsCommand;

    /// Application configuration.
    type Cfg = KmsConfig;

    /// Paths to resources within the application.
    type Paths = StandardPaths;

    /// Accessor for application configuration.
    fn config(&self) -> config::Reader<KmsConfig> {
        self.config.read()
    }

    /// Borrow the application state immutably.
    fn state(&self) -> &application::State<Self> {
        &self.state
    }

    /// Register all components used by this application.
    ///
    /// If you would like to add additional components to your application
    /// beyond the default ones provided by the framework, this is the place
    /// to do so.
    fn register_components(&mut self, command: &Self::Cmd) -> Result<(), FrameworkError> {
        let components = self.framework_components(command)?;
        let mut component_registry = self.state.components_mut();
        component_registry.register(components)
    }

    /// Post-configuration lifecycle callback.
    ///
    /// Called regardless of whether config is loaded to indicate this is the
    /// time in app lifecycle when configuration would be loaded if
    /// possible.
    fn after_config(&mut self, config: Self::Cfg) -> Result<(), FrameworkError> {
        let mut component_registry = self.state.components_mut();
        component_registry.after_config(&config)?;
        self.config.set_once(config);
        Ok(())
    }

    /// Get tracing configuration from command-line options
    fn tracing_config(&self, command: &KmsCommand) -> trace::Config {
        if command.verbose() {
            trace::Config::verbose()
        } else {
            trace::Config::default()
        }
    }
}

impl KmsApplication {
    /// Set the configuration file path
    pub fn set_config_file_path(&self, path: std::path::PathBuf) {
        if let Ok(mut config_path) = self.config_file_path.lock() {
            *config_path = Some(path);
        }
    }

    /// Get the configuration file path
    pub fn get_config_file_path(&self) -> Option<std::path::PathBuf> {
        self.config_file_path
            .lock()
            .ok()
            .and_then(|path| path.clone())
    }
}
