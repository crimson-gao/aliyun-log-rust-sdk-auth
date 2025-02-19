### Description
This crate is used to generate signature for aliyun log service.

### Usage
Add this crate to your Cargo.toml using the following command:
```bash
cargo add aliyun-log-rust-sdk-auth
```

Use it in your code:
```rust
use aliyun_log_rust_sdk_auth::sign::{sign_v1, SECURITY_TOKEN_NONE, BODY_NONE};
let mut headers = http::HeaderMap::new();
// this will modify headers in place
let signature_result = sign_v1(
    "your_access_key_id",
    "your_access_key_secret",
    SECURITY_TOKEN_NONE,
    &http::Method::GET,
    &http::Uri::from_static("/"),
    &mut headers,
    BODY_NONE,
);
if let Err(err) = signature_result {
    println!("signature error: {}", err);
}
```