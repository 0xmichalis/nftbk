use anyhow::Result;

pub async fn delete_backup(client: &crate::client::Client, id: &str) -> Result<()> {
    let operation = client.delete(id).await?;
    println!("Deletion operation: {}", operation.id);
    Ok(())
}
