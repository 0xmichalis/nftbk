use anyhow::Result;

pub async fn run(server_address: String, backup_id: String) -> Result<()> {
    let client =
        crate::client::Client::new(&server_address, std::env::var("NFTBK_AUTH_TOKEN").ok());
    super::common::delete_backup(&client, &backup_id).await
}
