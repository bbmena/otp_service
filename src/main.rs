mod service;

use aws_sdk_dynamodb::Client;
use service::otp_service::password_server::PasswordServer;
use service::validator_service::validator_server::ValidatorServer;
use service::PasswordService;
use service::ValidatorService;
use tonic::transport::Server;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = aws_config::from_env().await;
    let address = "[::1]:8080".parse().unwrap();
    let password_service = PasswordService {
        client: Client::new(&config),
    };
    let validator_service = ValidatorService {
        client: Client::new(&config),
    };

    Server::builder()
        .add_service(PasswordServer::new(password_service))
        .add_service(ValidatorServer::new(validator_service))
        .serve(address)
        .await?;

    Ok(())
}
