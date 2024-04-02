use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use otp_service::{password_server::Password, OtpRequest, OtpResponse};
use std::collections::HashMap;
use std::time::SystemTime;
use tonic::{Request, Response, Status};
use validator_service::{validator_server::Validator, OtpValidationRequest, OtpValidationResponse};
use rand::{Rng, thread_rng};

pub mod otp_service {
    tonic::include_proto!("otp");
}

pub mod validator_service {
    tonic::include_proto!("otp");
}

const TABLE_NAME: &str = "otp_passwords";

pub struct PasswordService {
    pub(crate) client: Client,
}

impl PasswordService {
    async fn persist_password(&self, password_item: PasswordItem) {
        let request = &self
            .client
            .put_item()
            .table_name(TABLE_NAME)
            .item("Password", AttributeValue::S(password_item.password))
            .item("Username", AttributeValue::S(password_item.username))
            .item(
                "Expiration",
                AttributeValue::N(password_item.expiration_timestamp.to_string()),
            );

        request.clone().send().await.expect("Something broke");
    }
}

#[tonic::async_trait]
impl Password for PasswordService {
    async fn request_password(
        &self,
        request: Request<OtpRequest>,
    ) -> Result<Response<OtpResponse>, Status> {
        let otp_request = request.into_inner();
        let password = generate_password();

        let expiration_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime before UNIX Epoch")
            .as_secs()
            + otp_request.timout_seconds;

        let _ = &self
            .persist_password(PasswordItem {
                username: otp_request.username,
                password: password.clone(),
                expiration_timestamp,
            })
            .await;

        Ok(Response::new(OtpResponse { password }))
    }
}

pub struct ValidatorService {
    pub(crate) client: Client,
}

#[tonic::async_trait]
impl Validator for ValidatorService {
    async fn validate_password(
        &self,
        request: Request<OtpValidationRequest>,
    ) -> Result<Response<OtpValidationResponse>, Status> {
        let current_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime before UNIX Epoch")
            .as_secs();
        let otp_request = request.into_inner();

        let result = &self
            .client
            .query()
            .table_name(TABLE_NAME)
            .key_condition_expression("#Password = :password and #Username = :username")
            .filter_expression("#Expiration > :timestamp")
            .set_expression_attribute_names(Some(HashMap::from([
                ("#Expiration".to_string(), "Expiration".to_string()),
                ("#Username".to_string(), "Username".to_string()),
                ("#Password".to_string(), "Password".to_string()),
            ])))
            .set_expression_attribute_values(Some(HashMap::from([
                (
                    ":timestamp".to_string(),
                    AttributeValue::N(current_timestamp.to_string()),
                ),
                (
                    ":username".to_string(),
                    AttributeValue::S(otp_request.username),
                ),
                (
                    ":password".to_string(),
                    AttributeValue::S(otp_request.password),
                ),
            ])))
            .send()
            .await
            .unwrap();

        let is_valid = match result.items.as_ref() {
            None => false,
            Some(n) => n.len() > 0,
        };

        Ok(Response::new(OtpValidationResponse { is_valid }))
    }
}

// this is not a secure algorithm. will need to implement https://www.ietf.org/rfc/rfc4226.txt and https://www.ietf.org/rfc/rfc6238.txt
fn generate_password() -> String {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() / 30;
    let mut rng = thread_rng();
    let random_number: u32 = rng.gen_range(0..1000000);
    let otp = (now as u32 ^ random_number) % 1000000;

    otp.to_string()
}

pub struct PasswordItem {
    pub username: String,
    pub password: String,
    pub expiration_timestamp: u64,
}
