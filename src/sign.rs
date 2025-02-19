use base64::{Engine as _, engine::general_purpose};
#[cfg(not(test))]
use chrono::Utc;
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, Uri,
    header::{CONTENT_LENGTH, CONTENT_TYPE, DATE, InvalidHeaderValue, ToStrError},
};
use thiserror::Error;

/// Calculate the signature of http requeust to aliyun log service, using signature version 1.
/// This function modifies the `headers` in place, and should be called just before sending the request.
///
/// # Arguments
///
/// * `access_key_id` - The access key id of your aliyun account.
/// * `access_key_secret` - The access key secret of your aliyun account.
/// * `security_token` - The security token of your aliyun account, which is optional.
/// If you don't have a security token, just use the constant `SECURITY_TOKEN_NONE`.
/// * `method` - The http method of the request.
/// * `uri` - The http uri of the request.
/// * `headers` - The http headers of the request.
/// * `body` - The http body of the request, which is optional.
/// If the request has no body, just use the constant `BODY_NONE`.
///
/// # Returns
///
/// A `Result` which is:
///
/// * `Ok(String)` containing the signature of the request, which has already been added to `headers`, so you don't need to add it again.
/// The returned result can be used for testing or logging.
/// * `Err(Box<dyn std::error::Error>)` if the calculation failed.
///
/// # Errors
///
/// This function will return an error if the calculation failed, the reason can be one of the following:
///
/// * `access_key_id` contains invalid invisible characters which can not be used in http headers.
/// * `security_token` contains invalid invisible characters which can not be used in http headers.
/// * `headers` contains invalid invisible characters, which is not permitted in http headers.
///
/// # Examples
///
/// ```
/// use aliyun_log_rust_sdk_auth::sign::{sign_v1, SECURITY_TOKEN_NONE, BODY_NONE};
/// let mut headers = http::HeaderMap::new();
/// let signature_result = sign_v1(
///     "your_access_key_id",
///     "your_access_key_secret",
///     SECURITY_TOKEN_NONE,
///     &http::Method::GET,
///     &http::Uri::from_static("/"),
///     &mut headers,
///     BODY_NONE,
/// );
/// if let Err(err) = signature_result {
///     println!("signature error: {}", err);
/// }
/// ```
pub fn sign_v1(
    access_key_id: impl AsRef<str>,
    access_key_secret: impl AsRef<str>,
    security_token: Option<impl AsRef<str>>,
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    body: Option<impl AsRef<[u8]>>,
) -> SignatureResult<String> {
    headers
        .entry(LOG_API_VERSION)
        .or_insert(LOG_API_VERSION_0_6_0);
    headers.insert(LOG_SIGNATURE_METHOD, LOG_SIGNATURE_METHOD_HMAC_SHA1);

    if let Some(security_token) = security_token {
        headers.insert(
            LOG_ACS_SECURITY_TOKEN,
            HeaderValue::from_str(security_token.as_ref())?,
        );
    }

    let (content_md5, content_len) = calc_md5(body);
    if content_len > 0 {
        headers.insert(
            LOG_CONTENT_MD5,
            HeaderValue::from_str(&content_md5).expect("md5 should be valid in http header"),
        );
    }
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&content_len.to_string())
            .expect("content_len should be valid in http header"),
    );

    // date
    let date = now_rfc1123();
    headers.insert(
        DATE,
        HeaderValue::from_str(&date).expect("date should be valid in http header"),
    );

    let content_type = get_content_type(headers)?;
    let mut builder = string_builder::Builder::default();
    builder.append(format!(
        "{}\n{}\n{}\n{}\n",
        method, content_md5, content_type, date
    ));

    // headers
    let mut sorted_header: Vec<_> = headers.iter().collect();
    sorted_header.sort_by_key(|x| x.0.as_str());

    for (k, v) in sorted_header {
        let k = k.as_str();
        if !k.starts_with("x-log-") && !k.starts_with("x-acs-") {
            continue;
        }
        if let Ok(v) = v.to_str() {
            builder.append(k);
            builder.append(":");
            builder.append(v);
            builder.append("\n");
        }
    }

    // url & params
    builder.append(uri.path());
    if let Some(query_str) = uri.query() {
        builder.append("?");
        let mut queries = querystring::querify(query_str);
        queries.sort_by_key(|x| x.0);
        let mut sep = "";
        for (k, v) in queries {
            builder.append(sep);
            builder.append(k);
            builder.append("=");
            builder.append(v);
            sep = "&";
        }
    }
    let message = builder
        .string()
        .expect("fail to build message, invalid utf8");
    debug!("signature message: {}", message);

    let signature = general_purpose::STANDARD.encode(hmac_sha1::hmac_sha1(
        access_key_secret.as_ref().as_bytes(),
        message.as_bytes(),
    ));
    let auth = format!("LOG {}:{}", access_key_id.as_ref(), signature);
    headers.insert(LOG_AUTHORIZATION, HeaderValue::from_str(&auth)?);
    Ok(auth)
}

#[derive(Debug, Error)]
#[error("signature error: {0}")]
pub struct SignatureError(String);

pub type SignatureResult<T> = Result<T, SignatureError>;

impl From<InvalidHeaderValue> for SignatureError {
    fn from(err: InvalidHeaderValue) -> Self {
        SignatureError(err.to_string())
    }
}

impl From<ToStrError> for SignatureError {
    fn from(err: ToStrError) -> Self {
        SignatureError(err.to_string())
    }
}

pub const BODY_NONE: Option<Vec<u8>> = None;
pub const SECURITY_TOKEN_NONE: Option<&str> = None;

fn calc_md5(body: Option<impl AsRef<[u8]>>) -> (String, usize) {
    if let Some(content) = body {
        let len = content.as_ref().len();
        if len > 0 {
            let content_md5 = format!("{:X}", md5::compute(content));
            return (content_md5, len);
        }
    }
    return (String::default(), 0);
}

fn get_content_type(headers: &HeaderMap) -> SignatureResult<String> {
    if let Some(content_type) = headers.get(CONTENT_TYPE) {
        Ok(content_type.to_str()?.to_owned())
    } else {
        Ok(String::default())
    }
}

#[cfg(not(test))]
fn now_rfc1123() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

#[cfg(test)]
const TEST_NOW_RFC1123: &str = "Thu, 01 Jan 1970 00:00:00 GMT";

#[cfg(test)]
fn now_rfc1123() -> String {
    String::from(TEST_NOW_RFC1123)
}

const LOG_API_VERSION: HeaderName = HeaderName::from_static("x-log-apiversion");
const LOG_SIGNATURE_METHOD: HeaderName = HeaderName::from_static("x-log-signaturemethod");
const LOG_CONTENT_MD5: HeaderName = HeaderName::from_static("content-md5");
const LOG_AUTHORIZATION: HeaderName = HeaderName::from_static("authorization");
const LOG_ACS_SECURITY_TOKEN: HeaderName = HeaderName::from_static("x-acs-security-token");
const LOG_API_VERSION_0_6_0: HeaderValue = HeaderValue::from_static("0.6.0");
const LOG_SIGNATURE_METHOD_HMAC_SHA1: HeaderValue = HeaderValue::from_static("hmac-sha1");

#[allow(dead_code)]
#[non_exhaustive]
enum SignatureVersion {
    V1,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Debug)
            .try_init();
    }

    #[test]
    fn test_sign_case1() {
        init();

        let mut headers = HeaderMap::new();
        let body: Option<&[u8]> = None;
        let uri = Uri::from_static("/");
        let method = Method::GET;
        let access_key_id = "";
        let access_key_secret = "";
        let security_token: Option<&str> = None;
        let signature = sign_v1(
            access_key_id,
            access_key_secret,
            security_token,
            &method,
            &uri,
            &mut headers,
            body,
        )
        .unwrap();
        assert_eq!(signature, "LOG :SApFTtfTFKHmzdEdaMe5TjNn+RQ=");
        assert!(headers.contains_key(LOG_AUTHORIZATION));
        assert!(headers.contains_key(DATE));
        assert!(headers.contains_key(LOG_API_VERSION));
        assert!(headers.contains_key(LOG_SIGNATURE_METHOD));
        assert!(headers.contains_key(CONTENT_LENGTH));
        assert!(!headers.contains_key(LOG_CONTENT_MD5));
        assert!(!headers.contains_key(LOG_ACS_SECURITY_TOKEN));
    }

    #[test]
    fn test_sign_case2() {
        init();

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = r#"
            {"key": "value"}
        "#;
        let uri = Uri::from_static("/logstores/test-logstore?type=log&offset=0&line=100");
        let method = Method::POST;
        let access_key_id = "test-access-key-id";
        let access_key_secret = "test-access-key";
        let security_token: Option<&str> = None;
        let signature = sign_v1(
            access_key_id,
            access_key_secret,
            security_token,
            &method,
            &uri,
            &mut headers,
            Some(body.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            signature,
            "LOG test-access-key-id:4pL2xZJERC3tPKtRiHh9+nMG3tI="
        );
        assert!(headers.contains_key(LOG_AUTHORIZATION));
        assert!(headers.contains_key(DATE));
        assert!(headers.contains_key(LOG_API_VERSION));
        assert!(headers.contains_key(LOG_SIGNATURE_METHOD));
        assert!(headers.contains_key(CONTENT_LENGTH));
        assert!(headers.contains_key(LOG_CONTENT_MD5));
        assert!(!headers.contains_key(LOG_ACS_SECURITY_TOKEN));
        assert_eq!(
            "CE688F8D1AC3ED309BA9BE0A5ABAFCE5",
            headers.get(LOG_CONTENT_MD5).unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn test_sign_case3() {
        init();

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = r#"
            {"key": "value"}
        "#;
        let uri = Uri::from_static("/logstores/test-logstore?type=log&offset=0&line=100");
        let method = Method::POST;
        let access_key_id = "test-access-key-id";
        let access_key_secret = "test-access-key";
        let security_token = Some("test-security-token");
        let signature = sign_v1(
            access_key_id,
            access_key_secret,
            security_token,
            &method,
            &uri,
            &mut headers,
            Some(body.as_bytes()),
        )
        .unwrap();
        assert_eq!(
            signature,
            "LOG test-access-key-id:ZQt+0wIvpd+O9yIJKeKxZTJ2hv0="
        );
        assert!(headers.contains_key(LOG_AUTHORIZATION));
        assert!(headers.contains_key(DATE));
        assert!(headers.contains_key(LOG_API_VERSION));
        assert!(headers.contains_key(LOG_SIGNATURE_METHOD));
        assert!(headers.contains_key(CONTENT_LENGTH));
        assert!(headers.contains_key(LOG_CONTENT_MD5));
        assert!(headers.contains_key(LOG_ACS_SECURITY_TOKEN));
        assert_eq!(
            "CE688F8D1AC3ED309BA9BE0A5ABAFCE5",
            headers.get(LOG_CONTENT_MD5).unwrap().to_str().unwrap()
        );
        assert_eq!(
            "test-security-token",
            headers
                .get(LOG_ACS_SECURITY_TOKEN)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }
}
