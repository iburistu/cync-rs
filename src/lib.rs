use serde::Serialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct CyncController {
    api_port: u16,
    tls_acceptor: tokio_native_tls::TlsAcceptor,
}

impl CyncController {
    pub fn new(certificate_path: String, api_port: u16) -> Self {
        let der: &[u8] = &std::fs::read(certificate_path)
            .expect("Unable to read certificate on certificate path!");
        let cert = native_tls::Identity::from_pkcs12(der, "cync-rs")
            .expect("Unable to convert DER to native-tls certificate!");
        let tls_acceptor_builder = native_tls::TlsAcceptor::builder(cert)
            .build()
            .expect("Unable to build TLS acceptor!");
        let tls_acceptor = tokio_native_tls::TlsAcceptor::from(tls_acceptor_builder);
        Self {
            api_port,
            tls_acceptor,
        }
    }

    pub async fn run(self) {
        let state = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

        let tls_listener_task = tokio::spawn({
            let state = state.clone();
            async move {
                let listener = tokio::net::TcpListener::bind("0.0.0.0:23779")
                    .await
                    .expect("Unable to bind to port 23779!");

                loop {
                    match listener.accept().await {
                        Ok((stream, peer_address)) => {
                            tracing::info!("New connection: {}", peer_address.to_string());
                            let acceptor = self.tls_acceptor.clone();
                            let device = CyncActorHandle::new(
                                acceptor
                                    .accept(stream)
                                    .await
                                    .expect("TLS error: acceptor not accepting TCP stream!"),
                            );
                            state.lock().await.insert(peer_address.ip(), device);
                        }
                        Err(e) => panic!("{}", e),
                    }
                }
            }
        });

        let router = axum::Router::new()
            .route("/api/devices", axum::routing::get(get_devices))
            .route(
                "/api/device/:ip",
                axum::routing::get(get_device).post(post_device),
            )
            .with_state(state);

        async fn get_devices(
            axum::extract::State(state): axum::extract::State<
                std::sync::Arc<
                    tokio::sync::Mutex<
                        std::collections::HashMap<std::net::IpAddr, CyncActorHandle>,
                    >,
                >,
            >,
        ) -> axum::response::Json<Value> {
            axum::response::Json(json!(state
                .lock()
                .await
                .keys()
                .collect::<Vec<&std::net::IpAddr>>()))
        }

        #[axum::debug_handler]
        async fn get_device(
            axum::extract::Path(ip): axum::extract::Path<std::net::IpAddr>,
            axum::extract::State(state): axum::extract::State<
                std::sync::Arc<
                    tokio::sync::Mutex<
                        std::collections::HashMap<std::net::IpAddr, CyncActorHandle>,
                    >,
                >,
            >,
        ) -> axum::response::Json<Value> {
            let state = state.lock().await;
            let resp = state.get_key_value(&ip).unwrap().1.get_state().await;
            axum::response::Json(json!(resp))
        }

        #[axum::debug_handler]
        async fn post_device(
            axum::extract::Path(ip): axum::extract::Path<std::net::IpAddr>,
            axum::extract::State(state): axum::extract::State<
                std::sync::Arc<
                    tokio::sync::Mutex<
                        std::collections::HashMap<std::net::IpAddr, CyncActorHandle>,
                    >,
                >,
            >,
            axum::extract::Json(body): axum::extract::Json<Value>,
        ) -> axum::response::Json<Value> {
            let state = state.lock().await;
            let cmd_handle = state.get_key_value(&ip).unwrap().1;
            tracing::trace!("{:?}", body);
            if let Some(state) = body.get("state") {
                cmd_handle
                    .send_command(CyncCommand::State(state.as_bool().unwrap()))
                    .await;
            }

            if let Some(brightness) = body.get("brightness") {
                cmd_handle
                    .send_command(CyncCommand::Brightness(brightness.as_u64().unwrap() as u8))
                    .await;
            }

            if let Some(temperature) = body.get("temperature") {
                cmd_handle
                    .send_command(CyncCommand::Temperature(temperature.as_u64().unwrap() as u8))
                    .await;
            }

            axum::response::Json(json!(cmd_handle.get_state().await))
        }

        let server = axum::Server::bind(
            &format!("0.0.0.0:{}", &self.api_port)
                .parse()
                .expect("Unable to parse API port!"),
        )
        .serve(router.into_make_service());

        let _ = tokio::join!(tls_listener_task, server);
    }
}

#[derive(Clone, Copy, Serialize)]
enum CyncDeviceType {
    Unknown,
    Plug(bool),
    Light {
        state: bool,
        temperature: Option<u8>,
        color: Option<(u8, u8, u8)>,
        brightness: Option<u8>,
    },
}

#[derive(Clone, Copy, Serialize)]
struct CyncState {
    initialized: bool,
    device: Option<CyncDeviceType>,
}

impl Default for CyncState {
    fn default() -> Self {
        Self {
            initialized: false,
            device: None,
        }
    }
}

struct CyncActor {
    receiver: tokio::sync::mpsc::Receiver<CyncActorMessage>,
    command_tx: tokio::sync::mpsc::Sender<(CyncCommand, tokio::sync::oneshot::Sender<usize>)>,
    state: std::sync::Arc<std::sync::Mutex<CyncState>>,
}

enum CyncActorMessage {
    GetState {
        response: tokio::sync::oneshot::Sender<CyncState>,
    },
    SendCommand {
        command: CyncCommand,
        response: tokio::sync::oneshot::Sender<usize>,
    },
}

enum CyncCommand {
    State(bool),
    Brightness(u8),
    Temperature(u8),
    Raw(Vec<u8>),
}

impl CyncActor {
    fn new(
        receiver: tokio::sync::mpsc::Receiver<CyncActorMessage>,
        tls_stream: tokio_native_tls::TlsStream<TcpStream>,
    ) -> Self {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(CyncCommand, tokio::sync::oneshot::Sender<usize>)>(8);

        let (mut rd, mut wr) = tokio::io::split(tls_stream);

        let state = std::sync::Arc::new(std::sync::Mutex::new(CyncState::default()));

        // Reader task
        let _reader_task_handle = tokio::spawn({
            let tx = tx.clone();
            let state = state.clone();
            async move {
                let mut buf: Vec<u8> = vec![0; 128];

                loop {
                    match rd.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(l) => {
                            tracing::trace!("Received {} bytes", l);
                            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel::<usize>();
                            match &buf[..l] {
                                // Client info
                                // Send server ack
                                [0x23, ..] => {
                                    tracing::trace!("Reading {:x?}", buf);
                                    let msg = CyncCommand::Raw(vec![
                                        0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                                    ]);

                                    if let Err(e) = tx.send((msg, resp_tx)).await {
                                        tracing::error!("{}", e);
                                    }
                                    if let Ok(res) = resp_rx.await {
                                        if res != 7 {}
                                    }
                                }
                                // Client connection request
                                // Send server connection response
                                [0xc3, 0x00, 0x00, 0x00, 0x01, 0x0c] => {
                                    tracing::trace!("Reading {:x?}", buf);
                                    let msg = CyncCommand::Raw(vec![
                                        0xc8, 0x00, 0x00, 0x00, 0x0b, 0x0d, 0x07, 0xe6, 0x08, 0x0c,
                                        0x06, 0x15, 0x11, 0x11, 0xfe, 0x0c,
                                    ]);
                                    if let Err(e) = tx.send((msg, resp_tx)).await {
                                        tracing::error!("{}", e);
                                    }
                                    if let Ok(res) = resp_rx.await {
                                        if res != 16 {}
                                    }
                                }
                                // Client iter request
                                // Send iter back
                                [0x83, ..] => {
                                    tracing::trace!("Reading {:x?}", buf);
                                    let msg = CyncCommand::Raw(vec![
                                        0x88, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
                                    ]);
                                    if let Err(e) = tx.send((msg, resp_tx)).await {
                                        tracing::error!("{}", e);
                                    }
                                    if let Ok(res) = resp_rx.await {
                                        if res != 8 {}
                                    }
                                }
                                // Init status
                                [0x43, 0x00, 0x00, 0x00, ..] => {
                                    tracing::trace!("Reading {:x?}", buf);
                                    if buf[5] != 0x1e {
                                        let raw_state: &[u8] = &buf[15..22];
                                        match raw_state {
                                            [0x01, ..] => {
                                                state.lock().unwrap().device =
                                                    Some(CyncDeviceType::Plug(raw_state[1] != 0));
                                            }
                                            [0x02, ..] => {
                                                state.lock().unwrap().device =
                                                    Some(CyncDeviceType::Light {
                                                        state: raw_state[1] != 0,
                                                        temperature: Some(raw_state[3]),
                                                        color: None,
                                                        brightness: Some(raw_state[2]),
                                                    });
                                            }
                                            _ => {
                                                state.lock().unwrap().device =
                                                    Some(CyncDeviceType::Unknown);
                                            }
                                        }
                                    }
                                    let msg = CyncCommand::Raw(vec![
                                        0x48, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00,
                                    ]);
                                    if let Err(e) = tx.send((msg, resp_tx)).await {
                                        tracing::error!("{}", e);
                                    }
                                    if let Ok(res) = resp_rx.await {
                                        if res != 8 {}
                                    }
                                }
                                // Client heartbeat
                                // Send server heartbeat
                                [0xd3, 0x00, 0x00, 0x00, 0x00] => {
                                    tracing::trace!("Reading {:x?}", buf);
                                    let msg = CyncCommand::Raw(vec![0xd8, 0x00, 0x00, 0x00, 0x00]);
                                    if let Err(e) = tx.send((msg, resp_tx)).await {
                                        tracing::error!("{}", e);
                                    } else {
                                        state.lock().unwrap().initialized = true;
                                    }
                                    if let Ok(res) = resp_rx.await {
                                        if res != 5 {}
                                    }
                                }
                                _ => {
                                    tracing::trace!("Reading {:x?}", buf);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                tracing::error!("Reader task exited unexpectedly!");
            }
        });

        // Writer task handle
        let _writer_task_handle = tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    let (msg, resp) = rx.recv().await.unwrap();
                    match msg {
                        CyncCommand::State(s) => {
                            tracing::trace!("Received state command: {}", s);
                            match wr
                                .write(&[
                                    0x73, 0x00, 0x00, 0x00, 0x1f, s as u8, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xd0, 0x0d,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00,
                                    0x00, s as u8, 0x00, 0x00, 0x00, 0x00,
                                ])
                                .await
                            {
                                Ok(size) => {
                                    match state.lock().unwrap().device.unwrap() {
                                        CyncDeviceType::Unknown => {}
                                        CyncDeviceType::Plug(mut state) => state = s,
                                        CyncDeviceType::Light { mut state, .. } => state = s,
                                    }

                                    if size != 36 {}
                                    if resp.send(size).is_err() {}
                                }
                                Err(e) => panic!("{}", e),
                            };
                        }
                        CyncCommand::Brightness(b) => {
                            let device = state.lock().unwrap().device;
                            if let Some(device) = device {
                                // Todo: add filtering based on device type
                                match device {
                                    _ => {
                                        match wr
                                            .write(&[
                                                0x73, 0x00, 0x00, 0x00, 0x1d, 0x02, b, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00,
                                                0xf8, 0xd2, 0x0b, 0x00, 0x00, 0x01, 0x00, 0x00,
                                                0x00, 0x00, 0x00, 0xd2, 0x00, 0x00, b, 0x00, 0x00,
                                            ])
                                            .await
                                        {
                                            Ok(size) => {
                                                // brightness = Some(b);
                                                if size != 34 {}
                                                if resp.send(size).is_err() {}
                                            }
                                            Err(e) => panic!("{}", e),
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        CyncCommand::Temperature(t) => {
                            match wr
                                .write(&[
                                    0x73, 0x00, 0x00, 0x00, 0x1e, 0x03, t, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xe2, 0x0c, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe2, 0x00, 0x00,
                                    0x05, t, 0x00, 0x00,
                                ])
                                .await
                            {
                                Ok(size) => {
                                    if size != 35 {}
                                    if resp.send(size).is_err() {}
                                }
                                Err(e) => panic!("{}", e),
                            }
                        }
                        CyncCommand::Raw(r) => {
                            tracing::trace!("Writing {:x?}", r);
                            match wr.write(&r).await {
                                Ok(size) => {
                                    if size != r.len() {}
                                    if resp.send(size).is_err() {}
                                }
                                Err(e) => panic!("{}", e),
                            };
                        }
                    }
                }
            }
        });

        let command_tx = tx.clone();
        Self {
            receiver,
            command_tx,
            state,
        }
    }

    async fn handle_message(&mut self, msg: CyncActorMessage) {
        match msg {
            CyncActorMessage::GetState { response } => {
                let _ = response.send(self.state.lock().unwrap().clone());
            }
            CyncActorMessage::SendCommand { command, response } => {
                let (tx, rx) = tokio::sync::oneshot::channel();

                let _ = self.command_tx.send((command, tx)).await;

                let _ = response.send(rx.await.unwrap_or(0));
            }
        }
    }

    async fn run(&mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }
}

#[derive(Clone)]
struct CyncActorHandle {
    sender: tokio::sync::mpsc::Sender<CyncActorMessage>,
}

impl CyncActorHandle {
    pub fn new(tls_stream: tokio_native_tls::TlsStream<TcpStream>) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let mut actor = CyncActor::new(rx, tls_stream);

        tokio::spawn(async move { actor.run().await });

        Self { sender: tx }
    }

    pub async fn get_state(&self) -> CyncState {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let msg = CyncActorMessage::GetState { response: tx };

        let _ = self.sender.send(msg).await;

        rx.await.expect("Actor task killed!")
    }

    pub async fn send_command(&self, command: CyncCommand) -> usize {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let msg = CyncActorMessage::SendCommand {
            command,
            response: tx,
        };

        let _ = self.sender.send(msg).await;

        rx.await.expect("Actor task killed!")
    }
}
