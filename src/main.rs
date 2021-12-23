use base64::{decode};
use serde::{Deserialize};
use url::Url;
use yup_oauth2::{
    ApplicationDefaultCredentialsAuthenticator,
    ApplicationDefaultCredentialsFlowOpts,
};
use yup_oauth2::authenticator::ApplicationDefaultCredentialsTypes;

#[derive(Deserialize)]
struct Payload {
    data: String,
}

#[derive(Deserialize)]
struct SecretPayload {
    name: String,
    payload: Payload,
}

const SECRET_ID: &'static str = "SECRET_ID";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let authn_options = ApplicationDefaultCredentialsFlowOpts::default();
    let authenticator = match ApplicationDefaultCredentialsAuthenticator::builder(authn_options).await {
        ApplicationDefaultCredentialsTypes::InstanceMetadata(auth) => {
            println!("creating instance metadata authenticator...");
            auth.build().await?
        },
        ApplicationDefaultCredentialsTypes::ServiceAccount(auth) => {
            println!("creating service account authenticator...");
            auth.build().await?
        },
    };

    let scopes = ["https://www.googleapis.com/auth/cloud-platform"];
    let access_token = authenticator.token(&scopes).await?;

    // See https://cloud.google.com/secret-manager/docs/reference/rest/v1beta1/projects.secrets.versions/access
    let base_url = "https://secretmanager.googleapis.com";
    let api_version = "v1beta1";
    let secret_id = std::env::var(SECRET_ID)?;
    let endpoint_url = Url::parse(format!("{}/{}/{}:access", base_url, api_version, secret_id).as_str())?;

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        .enable_http1()
        .build();

    let client = hyper::Client::builder().build::<_, hyper::Body>(https);
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(endpoint_url.as_ref())
        .header(hyper::header::AUTHORIZATION, format!("Bearer {}", access_token.as_str()))
        .body(hyper::Body::empty())?;

    let mut res = client.request(req).await?;

    let body = hyper::body::to_bytes(res.body_mut()).await?;
    let data = String::from_utf8(body.to_vec())?;

    let secret_payload: SecretPayload = serde_json::from_str(&data)?;

    println!("{:?}", secret_payload.name);
    println!("{:?}", std::str::from_utf8(&decode(secret_payload.payload.data)?)?);

    Ok(())
}
