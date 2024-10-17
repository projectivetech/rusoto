//! The Credentials Provider for an AWS Resource's IAM Role (using IMDSv2).

use async_trait::async_trait;
use futures::TryFutureExt;
use std::time::Duration;

use crate::{
  AwsCredentials, CredentialsError, ProvideAwsCredentials,
};

const AWS_CREDENTIALS_PROVIDER_IP: &str = "169.254.169.254";
const AWS_CREDENTIALS_PROVIDER_PATH: &str = "latest/meta-data/iam/security-credentials";
const AWS_EC2_METADATA_TOKEN_HEADER: &str = "X-aws-ec2-metadata-token";

/// Provides AWS credentials from a resource's IAM role using IMDSv2.
/// Context:
///   - https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/
///   - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
///
/// Most of this code is adapted from the InstanceMetadataProvider in the
/// rusoto_credential crate:
/// https://docs.rs/rusoto_credential/0.46.0/src/rusoto_credential/instance_metadata.rs.html#44-48
///
/// But updated to use the metadata token flow for IMDSv2.
///
/// The provider has a default timeout of 30 seconds. While it should work well for most setups,
/// you can change the timeout using the `set_timeout` method.
#[derive(Clone, Debug)]
pub struct InstanceMetadataProvider {
    client: reqwest::Client,
    timeout: Duration,
}

impl InstanceMetadataProvider {
    /// Create a new provider with the given handle.
    pub fn new() -> Self {
        InstanceMetadataProvider {
            client: reqwest::Client::new(),
            timeout: Duration::from_secs(30),
        }
    }

    /// Set a new timeout for provider.
    pub fn set_timeout(&mut self, duration: Duration) {
        self.timeout = duration;
    }
}

impl Default for InstanceMetadataProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProvideAwsCredentials for InstanceMetadataProvider {
    async fn credentials(&self) -> Result<AwsCredentials, CredentialsError> {
        let ec2_metadata_token = self
            .client
            .put(&format!(
                "http://{}/latest/api/token",
                AWS_CREDENTIALS_PROVIDER_IP
            ))
            .header("X-aws-ec2-metadata-token-ttl-seconds", "600") // 10 minute TTL
            .send()
            .and_then(|res| res.text())
            .map_err(|e| CredentialsError::new(e.to_string()))
            .await?;

        // Taken from: https://docs.rs/rusoto_credential/0.46.0/src/rusoto_credential/instance_metadata.rs.html#44-48
        let role_name = get_role_name(&self.client, self.timeout, &ec2_metadata_token)
            .await
            .map_err(|err| CredentialsError {
                message: format!("Could not get credentials from iam: {}", err.to_string()),
            })?;

        let cred_str =
            get_credentials_from_role(&self.client, self.timeout, &role_name, &ec2_metadata_token)
                .await
                .map_err(|err| CredentialsError {
                    message: format!("Could not get credentials from iam: {}", err.to_string()),
                })?;

        let creds = serde_json::from_str::<AwsCredentials>(&cred_str)?;
        Ok(creds)
    }
}

/// Gets the role name to get credentials for using the IAM Metadata Service (169.254.169.254).
async fn get_role_name(
    client: &reqwest::Client,
    timeout: Duration,
    ec2_metadata_token: &str,
) -> Result<String, reqwest::Error> {
    Ok(client
        .get(&format!(
            "http://{}/{}/",
            AWS_CREDENTIALS_PROVIDER_IP, AWS_CREDENTIALS_PROVIDER_PATH
        ))
        .timeout(timeout)
        .header(AWS_EC2_METADATA_TOKEN_HEADER, ec2_metadata_token)
        .send()
        .and_then(|res| res.text())
        .await?)
}

/// Gets the credentials for an EC2 Instances IAM Role.
async fn get_credentials_from_role(
    client: &reqwest::Client,
    timeout: Duration,
    role_name: &str,
    ec2_metadata_token: &str,
) -> Result<String, reqwest::Error> {
    Ok(client
        .get(&format!(
            "http://{}/{}/{}",
            AWS_CREDENTIALS_PROVIDER_IP, AWS_CREDENTIALS_PROVIDER_PATH, role_name
        ))
        .timeout(timeout)
        .header(AWS_EC2_METADATA_TOKEN_HEADER, ec2_metadata_token)
        .send()
        .and_then(|res| res.text())
        .await?)
}
