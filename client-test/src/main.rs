use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a reqwest client. If you’re using self-signed certificates,
    // uncomment the line below to disable certificate verification (not recommended for production).
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .build()?;

    // Define your payload; adjust fields as needed.
    let payload = json!({
        "prompt": "Hello, world!",
    });

    // Send an HTTPS POST request to your public domain.
    let response = client
        .post("https://api.your-domain.com/query")
        .json(&payload)
        .send()
        .await?;

    println!("Status: {}", response.status());
    let body = response.text().await?;
    println!("Response Body: {}", body);

    Ok(())
}
