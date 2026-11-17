use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser)]
#[command(name = "hfdrive", version, about = "HF Drive provider client")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show the provider's observed account and connection state.
    Status { #[arg(long)] json: bool },
    /// Open system-browser PKCE login; device flow is explicitly opt-in.
    Login {
        #[arg(long)] device: bool,
        #[arg(long, value_enum, default_value = "signin")] purpose: LoginPurpose,
        #[arg(long)] organization_id: Option<String>,
    },
    /// Disable both credential paths while retaining local work.
    Logout,
    Owners,
    Buckets { #[arg(long)] owner: String },
    /// Import selected files/folders into an authorized bucket through the provider.
    Import {
        /// UUID of the shell-written request file (never a credential or raw path).
        #[arg(long)]
        request: Uuid,
    },
    /// Preview a connection, then accept that exact unchanged preview.
    Connect {
        #[arg(long)] owner: Option<String>,
        #[arg(long)] bucket: Option<String>,
        #[arg(long)] prefix: Option<String>,
        #[arg(long)] folder: Option<PathBuf>,
        #[arg(long)] accept_preview: Option<Uuid>,
    },
    /// Run capability checks in an explicitly owned probe prefix.
    Probe {
        #[arg(long)] connection: Uuid,
        #[arg(long)] run_id: Uuid,
    },
    /// Rebind verified publication credentials from a source setup reservation
    /// to an existing connected drive and recheck its storage access.
    RepairStorage {
        #[arg(long)] connection: Uuid,
        #[arg(long)] credentials_from: Uuid,
    },
    Pause(ConnectionArgs),
    Resume(ConnectionArgs),
    Pin(ItemArgs),
    Unpin(ItemArgs),
    FreeSpace(ItemArgs),
    History {
        #[command(flatten)] item: ItemArgs,
        #[arg(long)] cursor: Option<String>,
    },
    /// Publish a retained version as a new operation, without rewinding HEAD.
    Restore {
        #[command(flatten)] item: ItemArgs,
        #[arg(long)] version: Uuid,
    },
    Conflicts {
        #[command(flatten)] connection: ConnectionArgs,
        #[arg(long)] cursor: Option<String>,
    },
    Diagnostics {
        #[command(subcommand)] command: DiagnosticsCommand,
    },
    /// Review required hydration/export before removing a connection.
    Unlink {
        #[command(flatten)] connection: ConnectionArgs,
        #[arg(long)] accept_preview: Option<Uuid>,
        #[arg(long)] export_to: Option<PathBuf>,
        /// Plan a removal that drops placeholders whose bytes cannot be made
        /// resident instead of hydrating/exporting them. Their not-resident
        /// content is then irreversibly lost on this device.
        #[arg(long)]
        remove_unavailable: bool,
        /// Explicit consent to that irreversible local loss. Only meaningful
        /// together with --accept-preview; the provider rejects a lossy
        /// removal without it.
        #[arg(long)]
        accept_online_only_data_loss: bool,
    },
    Provider {
        #[command(subcommand)] command: ProviderCommand,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum LoginPurpose {
    Signin,
    ReadStorage,
    WriteStorage,
    CreateStorage,
}

#[derive(Args)]
pub struct ConnectionArgs {
    #[arg(long)] pub connection: Uuid,
}

#[derive(Args)]
pub struct ItemArgs {
    #[arg(long)] pub connection: Uuid,
    #[arg(long)] pub item: Uuid,
}

#[derive(Subcommand)]
pub enum DiagnosticsCommand {
    Export { #[arg(long)] output: PathBuf },
}

#[derive(Subcommand)]
pub enum ProviderCommand {
    /// Online-only content cannot open while the provider is stopped.
    Exit { #[arg(long)] confirm: bool },
    /// Checkpoint, stop scheduling, acknowledge and exit for a package upgrade.
    PrepareUpgrade { #[arg(long)] json: bool },
}
