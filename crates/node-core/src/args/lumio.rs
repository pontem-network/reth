use clap::Args;
use std::path::PathBuf;

#[derive(Debug, Args, PartialEq, Eq, Default, Clone)]
#[clap(next_help_heading = "Lumio")]
pub struct LumioArgs {
    /// Path to the genesis update transaction
    #[clap(long)]
    pub genesis_update: Option<PathBuf>,
}
