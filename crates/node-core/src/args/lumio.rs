use std::path::PathBuf;
use clap::Args;

#[derive(Debug, Args, PartialEq, Default, Clone)]
#[clap(next_help_heading = "Lumio")]
pub struct LumioArgs {
    /// Path to the genesis update transaction
    #[clap(long)]
    pub genesis_update: Option<PathBuf>,
}
