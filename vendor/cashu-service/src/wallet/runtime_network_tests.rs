use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn fresh_connections_escape_a_stale_pooled_socket_without_reopening_the_wallet() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mint: cdk::mint_url::MintUrl = format!("http://{}", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let body = serde_json::to_string(&cdk::nuts::MintInfo::new()).unwrap();
            connections.spawn(async move {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}", body.len(), body).as_bytes()).await.unwrap();
                // The connection remains open but cannot carry another request,
                // like a socket retaining its source IP after a route change.
                std::future::pending::<()>().await;
            });
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let service = CashuWalletService::open_file_backed(directory.path())
        .await
        .unwrap();
    let wallet = service
        .repository
        .create_wallet(mint.clone(), cdk::nuts::CurrencyUnit::Sat, None)
        .await
        .unwrap();
    wallet.mint_connector().get_mint_info().await.unwrap();
    drop(wallet);
    service.refresh_network_connections().await.unwrap();
    let wallet = service
        .repository
        .get_wallet(&mint, &cdk::nuts::CurrencyUnit::Sat)
        .await
        .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        wallet.mint_connector().get_mint_info(),
    )
    .await;
    server.abort();
    result
        .expect("a stale pooled connection delayed the next operation")
        .unwrap();
    assert!(
        CashuWalletService::open_file_backed(directory.path())
            .await
            .is_err(),
        "refreshing connections must retain exclusive wallet ownership"
    );
}
