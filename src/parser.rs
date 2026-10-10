use std::path::PathBuf;
use clap::{Subcommand, Parser};


pub const BANNER: &str = r#"
_____  ______  ___________
__  / / /_  / / /__  ____/
_  / / /_  / / /__  __/   
/ /_/ / / /_/ / _  /___   
\____/  \____/  /_____/   
                                                         
"#;


#[derive(Parser, Debug)]
#[command(
    name = "uue",
    version = "1.0.0",
    about = "File Encryption Utility",
    long_about = None,
    before_help = BANNER,
)]


pub struct Args {
    /// Target path (file or directory) to sweep
    #[arg(short, long, value_name = "PATH")]
    pub target: PathBuf,

    #[command(subcommand)]
    pub action: Action,
}


#[derive(Debug, Clone, Copy, Subcommand)]
pub enum Action {
    /// Encrypt files inside the target path
    Encrypt,
    /// Decrypt files inside the target path
    Decrypt,
}
