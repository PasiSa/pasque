use chrono::Duration;
use clap::Parser;
use pasque::jwt::Jwt;
use std::fs;
use std::process;


fn main() {
    let args = Args::parse();

    let secret = match fs::read(&args.secret) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Failed to read secret file: {}", e);
            process::exit(1);
        }
    };

    let permissions: Vec<String> = args
        .permissions
        .split(',')
        .map(str::to_string)
        .collect();

    match Jwt::create_token(args.sub, Duration::minutes(args.lifetime), permissions, &secret) {
        Ok(token) => println!("{}", token),
        Err(e) => {
            eprintln!("Failed to create token: {}", e);
            process::exit(1);
        }
    }
}


#[derive(Parser, Debug)]
#[command(about = "Generate a JWT token", long_about = None)]
struct Args {
    /// Subject (e.g., username)
    #[arg(long)]
    sub: String,

    /// Permissions as a comma-separated list
    #[arg(long)]
    permissions: String,

    /// Lifetime in minutes
    #[arg(long, default_value_t = 60)]
    lifetime: i64,

    /// Path to secret key file
    #[arg(long)]
    secret: String,
}
