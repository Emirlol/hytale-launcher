use std::time::Duration;

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Build {
	pub build_version: String,
	pub newest: i32,
}

#[derive(Debug, Deserialize)]
pub struct Patchlines {
	#[serde(rename = "kebab-case")]
	pub pre_release: Build,
	pub release: Build,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GameProfile {
	pub created_at: String,
	pub entitlements: Vec<String>,
	pub next_name_change_at: String,
	pub skin: String,
	pub username: String,
	pub uuid: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct AccountDataResponse {
	// This is explicitly snake-case
	pub eula_accepted_at: String,
	pub owner: Uuid,
	pub patchlines: Option<Patchlines>, // This is null when the arch & os aren't specified in the route.
	pub profiles: Vec<GameProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GameSessionResponse {
	pub expires_at: String,
	pub identity_token: String,
	pub session_token: String
}

const ACCOUNT_URL: &str = "https://account-data.hytale.com/my-account/get-launcher-data";
const SESSION_URL: &str = "https://sessions.hytale.com/game-session/new";

#[inline]
pub async fn get_game_profiles(access_token: &str) -> Result<Vec<GameProfile>> {
	get_account_data(access_token).await.map(|data| data.profiles)
}

pub async fn get_account_data(access_token: &str) -> Result<AccountDataResponse> {
	let client = Client::builder().timeout(Duration::from_secs(10)).build()?;

	let response = client.get(ACCOUNT_URL).bearer_auth(access_token).send().await?;

	let data: AccountDataResponse = response.json().await?;
	Ok(data)
}

pub async fn create_session(access_token: &str, uuid: Uuid) -> Result<GameSessionResponse> {
	let client = Client::builder().timeout(Duration::from_secs(10)).build()?;
	#[derive(serde::Serialize)]
	struct UuidObject {
		uuid: Uuid
	}
	let response = client.post(SESSION_URL).json(&UuidObject { uuid }).bearer_auth(access_token).send().await?;

	let data: GameSessionResponse = response.json().await?;
	Ok(data)
}