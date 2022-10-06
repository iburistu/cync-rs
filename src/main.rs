use clap::Parser;
use log::{debug, info, trace, warn};
use native_tls::Identity;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::fs::read;
use tokio::io::{AsyncReadExt, AsyncWriteExt, Result};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, oneshot};
use warp::Filter;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Clone, Debug)]
enum Command {
    State(bool),
    Brightness(u8),
    Temperature(u8),
    Raw(Vec<u8>),
}

#[derive(Clone, Debug)]
struct Message {
    target: std::net::IpAddr,
    command: Command,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClientState {
    state: bool,
    brightness: Option<u8>,
    temperature: Option<u8>,
}

fn setup_logging(verbosity: u8) -> std::io::Result<()> {
    let mut base_config = fern::Dispatch::new();

    base_config = match verbosity {
        0 => base_config.level(log::LevelFilter::Warn),
        1 => base_config.level(log::LevelFilter::Info),
        2 => base_config.level(log::LevelFilter::Debug),
        _ => base_config.level(log::LevelFilter::Trace),
    };

    let stdout_config = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}] {}",
                chrono::Local::now().to_rfc3339(),
                record.target(),
                record.level(),
                message
            ))
        })
        .chain(std::io::stdout());

    base_config.chain(stdout_config).apply().unwrap();

    Ok(())
}

fn with_tx(
    tx: broadcast::Sender<Message>,
) -> impl Filter<Extract = (broadcast::Sender<Message>,), Error = Infallible> + Clone {
    warp::any().map(move || tx.clone())
}

async fn handle_cmd(
    addr: std::net::IpAddr,
    body: ClientState,
    tx: broadcast::Sender<Message>,
) -> std::result::Result<impl warp::Reply, Infallible> {
    let msg: Message = Message {
        target: addr,
        command: Command::State(body.state),
    };
    tx.send(msg).unwrap();

    match body.brightness {
        Some(b) => {
            let msg: Message = Message {
                target: addr,
                command: Command::Brightness(b),
            };
            tx.send(msg).unwrap();
        }
        None => {}
    }

    match body.temperature {
        Some(t) => {
            let msg: Message = Message {
                target: addr,
                command: Command::Temperature(t),
            };
            tx.send(msg).unwrap();
        }
        None => {}
    }

    Ok(warp::reply())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    setup_logging(cli.verbose)?;

    debug!("Logging setup complete");

    debug!("Initializing the TLS server thread...");

    // Create the TLS acceptor.
    debug!("Attempting to read certificate file...");
    let der: &[u8] = &read("certs/identity.p12").unwrap();
    let cert = Identity::from_pkcs12(der, "cync-rs").unwrap();

    let tls_acceptor_builder = match native_tls::TlsAcceptor::builder(cert).build() {
        Ok(b) => b,
        Err(e) => panic!("{}", e),
    };

    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(tls_acceptor_builder);

    debug!("Certificate file read successfully!");

    debug!("Setting up server broadcast channel...");

    let (bc_tx, _) = broadcast::channel::<Message>(8);

    let server_bc_tx = bc_tx.clone();

    let tls_listener_task = async move {
        debug!("Creating the TCP listener on 0.0.0.0:23779");
        let listener = TcpListener::bind("0.0.0.0:23779")
            .await
            .expect("Unable to bind to port 23779");

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let acceptor = tls_acceptor.clone();
                    let listener_bc_tx = bc_tx.clone();
                    tokio::spawn(async move {
                        let stream = acceptor
                            .accept(stream)
                            .await
                            .expect("TLS error: acceptor not accepting TCP stream!");

                        let (tx, mut rx) = mpsc::channel::<(Message, oneshot::Sender<u8>)>(10);

                        let mut bc_rx = listener_bc_tx.subscribe();
                        let bc_tx = tx.clone();

                        let (mut rd, mut wr) = tokio::io::split(stream);

                        let server_peer_addr = peer_addr.clone();

                        info!("New connection: {}", peer_addr);

                        let read_thread_handle = async move {
                            let mut buf: Vec<u8> = vec![0; 128];

                            loop {
                                match rd.read(&mut buf).await {
                                    Ok(0) => return,
                                    Ok(l) => {
                                        let (resp_tx, resp_rx) = oneshot::channel();
                                        match &buf[..l] {
                                            // Client info
                                            // Send server ack
                                            [0x23, ..] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                debug!("{} sent client info", peer_addr);
                                                let msg: Message = Message {
                                                    target: peer_addr.ip(),
                                                    command: Command::Raw(vec![
                                                        0x28, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
                                                    ]),
                                                };
                                                tx.send((msg, resp_tx)).await.unwrap();
                                                let res: u8 = resp_rx.await.unwrap();
                                                trace!("{}", res);
                                            }
                                            // Client connection request
                                            // Send server connection response
                                            [0xc3, 0x00, 0x00, 0x00, 0x01, 0x0c] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                debug!(
                                                    "{} sent client connection request",
                                                    peer_addr
                                                );
                                                let msg: Message = Message {
                                                    target: peer_addr.ip(),
                                                    command: Command::Raw(vec![
                                                        0xc8, 0x00, 0x00, 0x00, 0x0b, 0x0d, 0x07,
                                                        0xe6, 0x08, 0x0c, 0x06, 0x15, 0x11, 0x11,
                                                        0xfe, 0x0c,
                                                    ]),
                                                };
                                                tx.send((msg, resp_tx)).await.unwrap();
                                                let res = resp_rx.await.unwrap();
                                                trace!("{}", res);
                                            }
                                            // Client iter request
                                            // Send iter back
                                            [0x83, ..] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                debug!("{} sent client inter req", peer_addr);
                                                let msg: Message = Message {
                                                    target: peer_addr.ip(),
                                                    command: Command::Raw(vec![
                                                        0x88, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
                                                        0x00,
                                                    ]),
                                                };
                                                tx.send((msg, resp_tx)).await.unwrap();
                                                let res = resp_rx.await.unwrap();
                                                trace!("{}", res);
                                            }
                                            // Init status
                                            [0x43, 0x00, 0x00, 0x00, ..] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                if buf[5] != 0x1e {
                                                    let raw_state: &[u8] = &buf[15..22];
                                                    match &raw_state[..] {
                                                        [0x01, ..] => {}
                                                        [0x02, ..] => {
                                                            let state: u8 = raw_state[1];
                                                            let brightness: u8 = raw_state[2];
                                                            let temperature: u8 = raw_state[3];

                                                            info!("{} is a smart light that is currently {} and has a brightness of {} and color temperature of {}", peer_addr, state, brightness, temperature);
                                                        }
                                                        _ => {}
                                                    }
                                                } else {
                                                    debug!("{} sent client data ack", peer_addr);
                                                }
                                                let msg: Message = Message {
                                                    target: peer_addr.ip(),
                                                    command: Command::Raw(vec![
                                                        0x48, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01,
                                                        0x00,
                                                    ]),
                                                };
                                                tx.send((msg, resp_tx)).await.unwrap();
                                                let res = resp_rx.await.unwrap();
                                                trace!("{}", res);
                                            }
                                            // Client heartbeat
                                            // Send server heartbeat
                                            [0xd3, 0x00, 0x00, 0x00, 0x00] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                debug!("{} sent client heartbeat", peer_addr);
                                                let msg: Message = Message {
                                                    target: peer_addr.ip(),
                                                    command: Command::Raw(vec![
                                                        0xd8, 0x00, 0x00, 0x00, 0x00,
                                                    ]),
                                                };
                                                tx.send((msg, resp_tx)).await.unwrap();
                                                let res = resp_rx.await.unwrap();
                                                trace!("{}", res);
                                            }
                                            // Client status on
                                            [0x7b, 0x00, 0x00, 0x00, 0x07, 0x01, ..] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                info!("{} is now ON", peer_addr);
                                            }
                                            // Client status off
                                            [0x7b, 0x00, 0x00, 0x00, 0x07, 0x00, ..] => {
                                                trace!("{} sent {:x?}", peer_addr, &buf[..l]);
                                                info!("{} is now OFF", peer_addr);
                                            }
                                            _ => {
                                                trace!("{} sent {:x?}", peer_addr, buf);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        };

                        let write_thread_handle = async move {
                            loop {
                                let (msg, resp) = rx.recv().await.unwrap();
                                let Message { command, .. } = msg;
                                match command {
                                    Command::State(s) => {
                                        trace!("{}", s);
                                        wr.write(&[
                                            0x73, 0x00, 0x00, 0x00, 0x1f, s as u8, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00,
                                            0xf8, 0xd0, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0xd0, 0x00, 0x00, s as u8, 0x00, 0x00,
                                            0x00, 0x00,
                                        ])
                                        .await
                                        .unwrap();
                                        resp.send(s as u8).unwrap();
                                    }
                                    Command::Brightness(b) => {
                                        trace!("{}", b);
                                        wr.write(&[
                                            0x73, 0x00, 0x00, 0x00, 0x1d, 0x02, b, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0xf8,
                                            0xd2, 0x0b, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0xd2, 0x00, 0x00, b, 0x00, 0x00,
                                        ])
                                        .await
                                        .unwrap();
                                        resp.send(b).unwrap();
                                    }
                                    Command::Temperature(t) => {
                                        trace!("{}", t);
                                        wr.write(&[
                                            0x73, 0x00, 0x00, 0x00, 0x1e, 0x03, t, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x7e, 0x00, 0x00, 0x00, 0x00, 0xf8,
                                            0xe2, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                            0x00, 0xe2, 0x00, 0x00, 0x05, t, 0x00, 0x00,
                                        ])
                                        .await
                                        .unwrap();
                                        resp.send(t).unwrap();
                                    }
                                    Command::Raw(r) => {
                                        wr.write(&r).await.unwrap();
                                        resp.send(r.len() as u8).unwrap();
                                    }
                                }
                            }
                        };

                        let server_command_handle = async move {
                            loop {
                                match bc_rx.recv().await {
                                    Ok(msg) => {
                                        if msg.target == server_peer_addr.ip() {
                                            let (resp_tx, resp_rx) = oneshot::channel();
                                            bc_tx.send((msg, resp_tx)).await.unwrap();
                                            let res = resp_rx.await.unwrap();
                                            trace!("{}", res)
                                        }
                                    }
                                    Err(err) => {
                                        warn!("{}", err)
                                    }
                                }
                            }
                        };

                        tokio::join!(
                            read_thread_handle,
                            write_thread_handle,
                            server_command_handle
                        );
                    });
                }
                Err(e) => {
                    warn!("{}", e);
                    panic!();
                }
            }
        }
    };

    let warp_server_task = async move {
        let post = warp::post()
            .and(warp::path("api"))
            .and(warp::path("devices"))
            .and(warp::path::param::<std::net::IpAddr>())
            .and(warp::body::content_length_limit(1024))
            .and(warp::body::json())
            .and(with_tx(server_bc_tx.clone()))
            .and_then(handle_cmd);

        warp::serve(post).run(([0, 0, 0, 0], 8080)).await;
    };

    let _ = tokio::join!(tls_listener_task, warp_server_task);

    Ok(())
}
