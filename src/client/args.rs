use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Configuration file to read.
    #[arg(short, long, default_value = "config.json")]
    config: String,

    /// URL to connect.
    #[arg(short, long)]
    dest: String,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    ignore_cert: bool,
}


impl Args {
    pub fn new() -> Args {
        let args = Args::parse();

        args
    }

    pub fn config(&self) -> &String {
        &self.config
    }

    pub fn dest(&self) -> &String {
       &self.dest
    }

    pub fn ignore_cert(&self) -> bool {
        self.ignore_cert
    }
}
