use anyhow::Result;
use prettytable::{row, Table};

pub async fn run(server_address: String, show_errors: bool) -> Result<()> {
    let client =
        crate::client::Client::new(&server_address, std::env::var("NFTBK_AUTH_TOKEN").ok());
    let mut table = Table::new();
    table.add_row(row!["Backup ID", "Capture", "NFTs", "Archives", "IPFS"]);
    for backup in client.list().await? {
        table.add_row(row![
            backup.id,
            format!("{:?}", backup.state),
            backup.nft_count,
            backup.archives.len(),
            backup.pin_sets.len()
        ]);
        if show_errors {
            for archive in backup.archives {
                if let Some(error) = archive.error {
                    table.add_row(row![archive.id, error.code, error.message, "", ""]);
                }
            }
            for pins in backup.pin_sets {
                if let Some(error) = pins.error {
                    table.add_row(row![pins.id, error.code, error.message, "", ""]);
                }
            }
        }
    }
    table.printstd();
    Ok(())
}
