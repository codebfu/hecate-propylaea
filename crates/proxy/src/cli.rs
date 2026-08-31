//! Copyright (C) 2026 Gaultier HUBERT
//! SPDX-License-Identifier: GPL-3.0-or-later

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "hecate-propylaea", about = "Hecate Propylaea edge proxy for agent traffic")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Run the HTTP proxy (default when no subcommand is provided).
    Serve,
    /// Clear persisted proxy identity and rotate the local signing key.
    Forget,
}

impl Cli {
    pub fn resolved_command(&self) -> Commands {
        self.command.clone().unwrap_or(Commands::Serve)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_command_is_serve() {
        let cli = Cli::try_parse_from(["hecate-propylaea"]).unwrap();
        assert!(matches!(cli.resolved_command(), Commands::Serve));
    }

    #[test]
    fn forget_command_parses() {
        let cli = Cli::try_parse_from(["hecate-propylaea", "forget"]).unwrap();
        assert!(matches!(cli.resolved_command(), Commands::Forget));
    }
}
