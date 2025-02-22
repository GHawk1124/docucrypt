use client_requests::send_request;

#[tauri::command]
async fn send_request_command(payload: serde_json::Value) -> Result<String, String> {
    send_request(payload).await.map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![send_request_command])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
