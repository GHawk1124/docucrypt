use reqwest::Client;
use serde_json::json;

pub async fn send_request(
    payload: serde_json::Value,
) -> Result<String, Box<dyn std::error::Error>> {
    let client = if cfg!(debug_assertions) {
        Client::builder()
            .danger_accept_invalid_certs(true)
            .build()?
    } else {
        Client::builder().build()?
    };

    let api_url: &str = if cfg!(debug_assertions) {
        "http://localhost:3000/query"
    } else {
        "https://api.your-domain.com/query"
    };

    let response = client.post(api_url).json(&payload).send().await?;

    let body = response.text().await?;
    Ok(body)
}
