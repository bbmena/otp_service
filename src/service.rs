use aws_sdk_dynamodb::types::{AttributeValue, KeyType};
use aws_sdk_dynamodb::Client;
use otp_service::{password_server::Password, OtpRequest, OtpResponse};
use std::collections::HashMap;
use std::time::SystemTime;
use tonic::{Request, Response, Status};
use validator_service::{validator_server::Validator, OtpValidationRequest, OtpValidationResponse};

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
            .item(
                "Expiration",
                AttributeValue::N(password_item.expiration_timestamp.to_string()),
            );

        request.clone().send().await.expect("Poop");
    }
}

#[tonic::async_trait]
impl Password for PasswordService {
    async fn request_password(
        &self,
        request: Request<OtpRequest>,
    ) -> Result<Response<OtpResponse>, Status> {
        let password = generate_password();
        let expiration_timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("SystemTime before UNIX Epoch")
            .as_secs()
            + request.into_inner().timout_seconds;

        &self
            .persist_password(PasswordItem {
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
        let password = request.into_inner().password;

        let result = &self
            .client
            .query()
            .table_name(TABLE_NAME)
            .key_condition_expression("#Password = :password")
            .filter_expression("#Expiration > :timestamp")
            .set_expression_attribute_names(Some(HashMap::from([
                ("#Expiration".to_string(), "Expiration".to_string()),
                ("#Password".to_string(), "Password".to_string()),
            ])))
            .set_expression_attribute_values(Some(HashMap::from([
                (
                    ":timestamp".to_string(),
                    AttributeValue::N(current_timestamp.to_string()),
                ),
                (":password".to_string(), AttributeValue::S(password)),
            ])))
            .send()
            .await.unwrap();

        let is_valid = match result.items.as_ref() {
            None => false,
            Some(n) => n.len() > 0,
        };

        Ok(Response::new(OtpValidationResponse { is_valid }))
    }
}

fn generate_password() -> String {
    "1234567".to_string()
}

pub struct PasswordItem {
    pub password: String,
    pub expiration_timestamp: u64,
}
