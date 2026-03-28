use serde_json::json;

pub fn generate_minimal_config(api_addr: &str, api_secret: &str) -> serde_json::Value {
    json!({
        "log": {
            "level": "warn",
            "timestamp": true,
        },
        "experimental": {
            "clash_api": {
                "external_controller": api_addr,
                "secret": api_secret,
            }
        },
        "outbounds": [
            { "tag": "direct", "type": "direct" }
        ],
        "route": {
            "final": "direct"
        }
    })
}
