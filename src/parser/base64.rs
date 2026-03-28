use super::ProxyConfig;
use base64::Engine;

pub fn parse(content: &str) -> Vec<ProxyConfig> {
    let trimmed = content.trim();

    // Try to decode entire content as base64
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(trimmed));

    let text = match decoded {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => {
            tracing::debug!("Content is not base64, trying as raw text");
            trimmed.to_string()
        }
    };

    // Parse each line as a V2Ray URI
    super::v2ray::parse(&text)
}
