mod api;
mod oauth;

use std::{
	fmt::Display,
	path::PathBuf,
	process::Command,
};

use anyhow::{
	anyhow,
	Context,
	Result,
};
use clap::Parser;
use tracing::info;

const GAME_DIR: &str = ".var/app/com.hypixel.HytaleLauncher/data/Hytale";

#[derive(Debug, Clone, clap::ValueEnum)]
enum AuthMode {
	Authenticated,
	Offline,
}

impl Display for AuthMode {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			AuthMode::Authenticated => write!(f, "authenticated"),
			AuthMode::Offline => write!(f, "offline"),
		}
	}
}

#[derive(Clone, clap::Parser)]
#[command(name = "hightale-launcher", about = "A simple launcher for the Hytale client.")]
struct Args {
	/// The base game directory. Defaults to the default flatpak install location: `~/.var/app/com.hypixel.HytaleLauncher/data/Hytale`
	#[arg(long)]
	game_dir: Option<PathBuf>,
	/// The path to the java executable. If not specified, the java installation within the game directory will be used.
	#[arg(long)]
	java_exec: Option<PathBuf>,
	/// The authentication mode to use. Defaults to `authenticated`.
	#[arg(long, default_value_t = AuthMode::Authenticated)]
	auth_mode: AuthMode,
	#[arg(last = true)]
	additional_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt::init();
	let args = Args::parse();
	let game_dir = args.game_dir.unwrap_or_else(|| {
		let home = std::env::var("HOME").expect("HOME environment variable is not set");
		PathBuf::from(home).join(GAME_DIR)
	});
	let app_dir = format!("{}/install/release/package/game/latest", game_dir.display());
	let client_executable = format!("{}/Client/HytaleClient", app_dir);
	let user_dir = format!("{}/UserData", game_dir.display());
	let java_exec = args
		.java_exec
		.unwrap_or_else(|| PathBuf::from(format!("{}/install/release/package/jre/latest/bin/java", game_dir.display())));

	let (auth_url, pending_state, rx_code) = oauth::start_listener().context("Failed to start OAuth callback listener")?;
	info!("Open this URL in your browser:\n{}", auth_url);
	if webbrowser::open(&auth_url).is_ok() {
		info!("(Browser opened automatically)");
	}

	let code = rx_code.await.map_err(|_| anyhow!("OAuth callback listener closed before receiving a code"))?;

	let tokens = oauth::exchange_code(&code, &pending_state).await.context("Failed to exchange OAuth code")?;

	let profiles = api::get_game_profiles(&tokens.access_token).await.context("Failed to fetch game profiles")?;
	let profile = profiles.first().ok_or_else(|| anyhow!("No game profile found for this account"))?;

	let session = api::create_session(&tokens.access_token, profile.uuid).await.context("Failed to create session")?;

	info!("Authenticated profile: {} ({})", profile.username, profile.uuid);

	Command::new(client_executable)
		.args([
			"--uuid",
			&profile.uuid.to_string(),
			"--name",
			&profile.username,
			"--app-dir",
			&app_dir,
			"--user-dir",
			&user_dir,
			"--java-exec",
			java_exec.to_str().unwrap(),
			"--identity-token",
			&session.identity_token,
			"--session-token",
			&session.session_token,
			"--auth-mode",
			&args.auth_mode.to_string(),
		])
		.args(&args.additional_args)
		.spawn()
		.expect("Failed to launch hytale client.")
		.wait()?;

	Ok(())
}
