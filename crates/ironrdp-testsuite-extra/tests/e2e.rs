// FIXME: tests in this module can probably be rewritten to be much shorter using the ironrdp-client crate.

use core::time::Duration;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context as _, Result};
use ironrdp::connector;
use ironrdp::dvc::DrdynvcClient;
use ironrdp::echo::client::EchoClient;
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::pdu::{self, gcc};
use ironrdp::server::sspi::credssp::CredentialsProxy;
use ironrdp::server::sspi::{AuthIdentity, Username};
use ironrdp::server::{
    self, CredentialDecision, CredentialValidationError, CredentialValidator, DesktopSize, DisplayUpdate,
    KeyboardEvent, MouseEvent, PixelFormat, RdpServer, RdpServerDisplay, RdpServerDisplayUpdates,
    RdpServerInputHandler, ServerEvent, TlsIdentityCtx,
};
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{self, ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use ironrdp_async::{Framed, FramedWrite as _};
use ironrdp_testsuite_extra as _;
use ironrdp_tls::TlsStream;
use ironrdp_tokio::TokioStream;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::sync::{Mutex, oneshot};
use tracing::debug;

const DESKTOP_WIDTH: u16 = 1024;
const DESKTOP_HEIGHT: u16 = 768;
const USERNAME: &str = "";
const PASSWORD: &str = "";

#[tokio::test]
async fn test_client_server() {
    client_server(
        default_client_config(),
        |stage, _activation_factory, framed, _display_tx| async { (stage, framed) },
    )
    .await
}

#[tokio::test]
async fn test_deactivation_reactivation() {
    let client_config = default_client_config();
    let mut image = DecodedImage::new(
        PixelFormat::RgbA32,
        client_config.desktop_size.width,
        client_config.desktop_size.height,
    );
    client_server(
        client_config,
        |mut stage, activation_factory, mut framed, display_tx| async move {
            display_tx
                .send(DisplayUpdate::Resize(DesktopSize {
                    width: 2048,
                    height: 2048,
                }))
                .unwrap();
            {
                let (action, payload) = framed.read_pdu().await.expect("valid PDU");
                let outputs = stage.process(&mut image, action, &payload).expect("stage process");
                let out = outputs.into_iter().next().unwrap();
                match out {
                    ActiveStageOutput::DeactivateAll => {
                        // TODO: factor this out in common client code
                        // Execute the Deactivation-Reactivation Sequence:
                        // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/dfc234ce-481a-4674-9a5d-2a7bafb14432
                        debug!("Received Server Deactivate All PDU, executing Deactivation-Reactivation Sequence");
                        let mut connection_activation = activation_factory.create();
                        let mut buf = pdu::WriteBuf::new();
                        'activation_seq: loop {
                            let written = ironrdp_async::single_sequence_step_read(
                                &mut framed,
                                &mut connection_activation,
                                &mut buf,
                            )
                            .await
                            .map_err(|e| session::custom_err!("read deactivation-reactivation sequence step", e))
                            .unwrap();

                            if written.size().is_some() {
                                framed
                                    .write_all(buf.filled())
                                    .await
                                    .map_err(|e| {
                                        session::custom_err!("write deactivation-reactivation sequence step", e)
                                    })
                                    .unwrap();
                            }

                            if let connector::connection_activation::ConnectionActivationState::Finalized {
                                desktop_size,
                                share_id,
                                enable_server_pointer,
                                pointer_software_rendering,
                            } = connection_activation.connection_activation_state()
                            {
                                debug!(?desktop_size, "Deactivation-Reactivation Sequence completed");
                                // Update image size with the new desktop size.
                                // image = DecodedImage::new(PixelFormat::RgbA32, desktop_size.width, desktop_size.height);
                                // Update the active stage with the new channel IDs and pointer settings.
                                stage.set_fastpath_processor(
                                    session::fast_path::ProcessorBuilder {
                                        io_channel_id: connection_activation.io_channel_id(),
                                        user_channel_id: connection_activation.user_channel_id(),
                                        share_id,
                                        enable_server_pointer,
                                        pointer_software_rendering,
                                        bulk_decompressor: None,
                                    }
                                    .build(),
                                );
                                stage.set_share_id(share_id);
                                stage.set_enable_server_pointer(enable_server_pointer);
                                break 'activation_seq;
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
            (stage, framed)
        },
    )
    .await
}

#[tokio::test]
async fn test_echo_virtual_channel_end_to_end() {
    let payload = b"ironrdp echo e2e".to_vec();
    let echo_payload = payload.clone();

    client_server_with_connector(
        default_client_config(),
        |connector| connector.with_static_channel(DrdynvcClient::new().with_dynamic_channel(EchoClient::new())),
        move |mut stage, _activation_factory, mut framed, display_tx, echo_handle| async move {
            let _display_tx = display_tx;
            let mut image = DecodedImage::new(PixelFormat::RgbA32, DESKTOP_WIDTH, DESKTOP_HEIGHT);

            let deadline = Instant::now() + Duration::from_secs(5);
            let mut matched_measurement = None;

            while Instant::now() < deadline {
                echo_handle
                    .send_request(echo_payload.clone())
                    .expect("send echo request");

                for _ in 0..20 {
                    let measurements = echo_handle.take_measurements();
                    if let Some(measurement) = measurements.into_iter().find(|m| m.payload == echo_payload) {
                        matched_measurement = Some(measurement);
                        break;
                    }

                    let read_result = tokio::time::timeout(Duration::from_millis(150), framed.read_pdu()).await;
                    let Ok(Ok((action, frame))) = read_result else {
                        continue;
                    };

                    let outputs = stage.process(&mut image, action, &frame).expect("stage process");
                    for output in outputs {
                        if let ActiveStageOutput::ResponseFrame(frame) = output {
                            framed.write_all(&frame).await.expect("write response frame");
                        }
                    }
                }

                if matched_measurement.is_some() {
                    break;
                }
            }

            let measurement = matched_measurement.expect("echo RTT measurement was not produced");
            assert_eq!(measurement.payload, echo_payload);

            (stage, framed)
        },
    )
    .await
}

type DisplayUpdatesRx = Arc<Mutex<UnboundedReceiver<DisplayUpdate>>>;

struct TestDisplayUpdates {
    rx: DisplayUpdatesRx,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for TestDisplayUpdates {
    async fn next_update(&mut self) -> Result<Option<DisplayUpdate>> {
        let mut rx = self.rx.lock().await;

        Ok(rx.recv().await)
    }
}

struct TestDisplay {
    rx: DisplayUpdatesRx,
}

#[async_trait::async_trait]
impl RdpServerDisplay for TestDisplay {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: DESKTOP_WIDTH,
            height: DESKTOP_HEIGHT,
        }
    }

    async fn updates(&mut self) -> Result<Box<dyn RdpServerDisplayUpdates>> {
        Ok(Box::new(TestDisplayUpdates {
            rx: Arc::clone(&self.rx),
        }))
    }
}

struct TestInputHandler;
impl RdpServerInputHandler for TestInputHandler {
    fn keyboard(&mut self, _: KeyboardEvent) {}
    fn mouse(&mut self, _: MouseEvent) {}
}

async fn client_server<F, Fut>(client_config: connector::Config, clientfn: F)
where
    F: FnOnce(
            ActiveStage,
            connector::connection_activation::ConnectionActivationFactory,
            Framed<TokioStream<TlsStream<TcpStream>>>,
            UnboundedSender<DisplayUpdate>,
        ) -> Fut
        + 'static,
    Fut: Future<Output = (ActiveStage, Framed<TokioStream<TlsStream<TcpStream>>>)>,
{
    client_server_with_connector(
        client_config,
        |connector| connector,
        move |stage, connection_activation, framed, display_tx, _echo_handle| {
            clientfn(stage, connection_activation, framed, display_tx)
        },
    )
    .await;
}

async fn client_server_with_connector<F, Fut, C>(client_config: connector::Config, connector_factory: C, clientfn: F)
where
    F: FnOnce(
            ActiveStage,
            connector::connection_activation::ConnectionActivationFactory,
            Framed<TokioStream<TlsStream<TcpStream>>>,
            UnboundedSender<DisplayUpdate>,
            server::EchoServerHandle,
        ) -> Fut
        + 'static,
    Fut: Future<Output = (ActiveStage, Framed<TokioStream<TlsStream<TcpStream>>>)>,
    C: FnOnce(connector::ClientConnector) -> connector::ClientConnector + 'static,
{
    // FIXME(@CBenoit): If this is really necessary, we may consider a non-global way of registering the subscriber; otherwise it’s unnecessary to register that.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let cert_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs/server-cert.pem");
    let key_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs/server-key.pem");
    let identity = TlsIdentityCtx::init_from_paths(&cert_path, &key_path).expect("failed to init TLS identity");
    let acceptor = identity.make_acceptor().expect("failed to build TLS acceptor");

    let (display_tx, display_rx) = mpsc::unbounded_channel();
    let mut server = RdpServer::builder()
        .with_addr(([127, 0, 0, 1], 0))
        .with_tls(acceptor)
        .with_input_handler(TestInputHandler)
        .with_display_handler(TestDisplay {
            rx: Arc::new(Mutex::new(display_rx)),
        })
        .build();
    server.set_credentials(Some(server::Credentials {
        username: USERNAME.into(),
        password: PASSWORD.into(),
        domain: None,
    }));
    let ev = server.event_sender().clone();
    let echo_handle = server.echo_handle().clone();

    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let server = tokio::task::spawn_local(async move {
                server.run().await.unwrap();
            });

            let client = tokio::task::spawn_local(async move {
                let (tx, rx) = oneshot::channel();
                ev.send(ServerEvent::GetLocalAddr(tx)).unwrap();
                let server_addr = rx.await.unwrap().unwrap();
                let tcp_stream = TcpStream::connect(server_addr).await.expect("TCP connect");
                let client_addr = tcp_stream.local_addr().expect("local_addr");
                let mut framed = ironrdp_tokio::TokioFramed::new(tcp_stream);
                let connector = connector::ClientConnector::new(client_config, client_addr);
                let mut connector = connector_factory(connector);
                let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector)
                    .await
                    .expect("begin connection");
                let initial_stream = framed.into_inner_no_leftover();
                let (upgraded_stream, tls_cert) = ironrdp_tls::upgrade(initial_stream, "localhost")
                    .await
                    .expect("TLS upgrade");
                let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
                let mut upgraded_framed = ironrdp_tokio::TokioFramed::new(upgraded_stream);
                let server_public_key =
                    ironrdp_tls::extract_tls_server_public_key(&tls_cert).expect("extract server public key");
                let connection_result = ironrdp_async::connect_finalize(
                    upgraded,
                    connector,
                    &mut upgraded_framed,
                    &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
                    "localhost".into(),
                    server_public_key.to_owned(),
                    None,
                )
                .await
                .expect("finalize connection");

                // Retain the connection activation factory so the client closure can drive its own
                // Deactivation-Reactivation Sequence.
                let activation_factory = connection_result.activation_factory;
                let active_stage = ActiveStageBuilder {
                    static_channels: connection_result.static_channels,
                    user_channel_id: connection_result.user_channel_id,
                    io_channel_id: connection_result.io_channel_id,
                    message_channel_id: connection_result.message_channel_id,
                    share_id: connection_result.share_id,
                    compression_type: connection_result.compression_type,
                    enable_server_pointer: connection_result.enable_server_pointer,
                    pointer_software_rendering: connection_result.pointer_software_rendering,
                }
                .build();
                let (active_stage, mut upgraded_framed) = clientfn(
                    active_stage,
                    activation_factory,
                    upgraded_framed,
                    display_tx,
                    echo_handle,
                )
                .await;
                let outputs = active_stage.graceful_shutdown().expect("shutdown");
                for out in outputs {
                    match out {
                        ActiveStageOutput::ResponseFrame(frame) => {
                            upgraded_framed.write_all(&frame).await.expect("write frame");
                        }
                        _ => unimplemented!(),
                    }
                }

                // server should probably send TLS close_notify
                while let Ok(pdu) = upgraded_framed.read_pdu().await {
                    debug!(?pdu);
                }
                ev.send(ServerEvent::Quit("bye".into())).unwrap();
            });

            tokio::try_join!(server, client).expect("join");
        })
        .await;
}

fn default_client_config() -> connector::Config {
    connector::Config {
        desktop_size: DesktopSize {
            width: DESKTOP_WIDTH,
            height: DESKTOP_HEIGHT,
        },
        desktop_scale_factor: 0, // Default to 0 per FreeRDP
        enable_tls: true,
        enable_credssp: true,
        credentials: connector::Credentials::UsernamePassword {
            username: USERNAME.into(),
            password: PASSWORD.into(),
        },
        domain: None,
        client_build: semver::Version::parse(env!("CARGO_PKG_VERSION"))
            .map(|version| version.major * 100 + version.minor * 10 + version.patch)
            .unwrap_or(0)
            .try_into()
            .unwrap(),
        client_name: "ironrdp".into(),
        keyboard_type: gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: "".into(),
        bitmap: None,
        dig_product_id: "".into(),
        // NOTE: hardcode this value like in freerdp
        // https://github.com/FreeRDP/FreeRDP/blob/4e24b966c86fdf494a782f0dfcfc43a057a2ea60/libfreerdp/core/settings.c#LL49C34-L49C70
        client_dir: "C:\\Windows\\System32\\mstscax.dll".into(),
        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(target_os = "ios")]
        platform: MajorPlatformType::IOS,
        #[cfg(target_os = "linux")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "android")]
        platform: MajorPlatformType::ANDROID,
        #[cfg(target_os = "freebsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "dragonfly")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "openbsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "netbsd")]
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: true,
        license_cache: None,
        compression_type: None,
        enable_server_pointer: true,
        pointer_software_rendering: true,
        multitransport_flags: None,
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// The account [`NlaAccounts`] knows, with NTOWFv1("Password") from [MS-NLMP] 4.2.2.1.2.
const NLA_USERNAME: &str = "User";
const NLA_PASSWORD: &str = "Password";
const NLA_NT_HASH: &str = "$NTLM$:a4f49c406510bdcab6824ee7c30fd852";

#[tokio::test]
async fn test_hybrid_lookup_accepts_an_account_and_validates_its_delegated_credentials() {
    let delegated = hybrid_connect(NLA_USERNAME, NLA_PASSWORD)
        .await
        .expect("connection accepted");
    assert!(
        delegated
            == server::Credentials {
                username: NLA_USERNAME.into(),
                password: NLA_PASSWORD.into(),
                domain: None,
            }
    );
}

#[tokio::test]
async fn test_hybrid_lookup_rejects_a_wrong_password() {
    assert!(hybrid_connect(NLA_USERNAME, "wrong").await.is_err());
}

#[tokio::test]
async fn test_hybrid_lookup_rejects_an_unknown_account() {
    assert!(hybrid_connect("Nobody", NLA_PASSWORD).await.is_err());
}

/// One account, stored as its NT hash.
struct NlaAccounts;

impl CredentialsProxy for NlaAccounts {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: &Username) -> std::io::Result<AuthIdentity> {
        if username.account_name() != NLA_USERNAME {
            return Err(std::io::Error::other("unknown account"));
        }
        Ok(AuthIdentity {
            username: username.clone(),
            password: NLA_NT_HASH.to_owned().into(),
        })
    }

    fn auth_data(&mut self) -> std::io::Result<Vec<AuthIdentity>> {
        Ok(Vec::new())
    }
}

struct StopAfterOneConnection;

impl server::ConnectionHandler for StopAfterOneConnection {
    fn on_disconnected(
        &mut self,
        _: core::net::SocketAddr,
        _: Duration,
        _: Option<&anyhow::Error>,
    ) -> server::PostConnectionAction {
        server::PostConnectionAction::Stop
    }
}

/// Accepts any credentials and hands the first ones over.
struct DelegatedCredentials(std::sync::Mutex<Option<oneshot::Sender<server::Credentials>>>);

#[async_trait::async_trait]
impl CredentialValidator for DelegatedCredentials {
    async fn validate(
        &self,
        credentials: &server::Credentials,
    ) -> Result<CredentialDecision, CredentialValidationError> {
        if let Some(tx) = self.0.lock().unwrap().take() {
            let _ = tx.send(credentials.clone());
        }
        Ok(CredentialDecision::Accept)
    }
}

/// Connects to a Hybrid server that verifies clients against [`NlaAccounts`], and returns the
/// credentials the client delegated once the server validates them.
async fn hybrid_connect(username: &str, password: &str) -> Result<server::Credentials> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    let cert_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs/server-cert.pem");
    let key_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs/server-key.pem");
    let identity = TlsIdentityCtx::init_from_paths(&cert_path, &key_path).expect("failed to init TLS identity");
    let acceptor = identity.make_acceptor().expect("failed to build TLS acceptor");

    let (_display_tx, display_rx) = mpsc::unbounded_channel();
    let mut server = RdpServer::builder()
        .with_addr(([127, 0, 0, 1], 0))
        .with_hybrid(acceptor, identity.pub_key.clone())
        .with_input_handler(TestInputHandler)
        .with_display_handler(TestDisplay {
            rx: Arc::new(Mutex::new(display_rx)),
        })
        .with_connection_handler(Some(Box::new(StopAfterOneConnection)))
        .build();
    server.set_credentials_lookup(Some(Box::new(NlaAccounts)));
    let (delegated_tx, delegated_rx) = oneshot::channel();
    server.set_credential_validator(Some(Arc::new(DelegatedCredentials(std::sync::Mutex::new(Some(
        delegated_tx,
    ))))));
    let ev = server.event_sender().clone();

    let mut client_config = default_client_config();
    client_config.credentials = connector::Credentials::UsernamePassword {
        username: username.into(),
        password: password.into(),
    };

    let local = tokio::task::LocalSet::new();
    local
        .run_until(Box::pin(async move {
            let server = tokio::task::spawn_local(async move { server.run().await });
            let (tx, rx) = oneshot::channel();
            ev.send(ServerEvent::GetLocalAddr(tx)).unwrap();
            let server_addr = rx.await.unwrap().unwrap();

            let result = async {
                let tcp_stream = TcpStream::connect(server_addr).await?;
                let client_addr = tcp_stream.local_addr()?;
                let mut framed = ironrdp_tokio::TokioFramed::new(tcp_stream);
                let mut connector = connector::ClientConnector::new(client_config, client_addr);
                let should_upgrade = ironrdp_async::connect_begin(&mut framed, &mut connector).await?;
                let (upgraded_stream, tls_cert) =
                    ironrdp_tls::upgrade(framed.into_inner_no_leftover(), "localhost").await?;
                let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
                let mut upgraded_framed = ironrdp_tokio::TokioFramed::new(upgraded_stream);
                let server_public_key =
                    ironrdp_tls::extract_tls_server_public_key(&tls_cert).context("server public key")?;
                ironrdp_async::connect_finalize(
                    upgraded,
                    connector,
                    &mut upgraded_framed,
                    &mut ironrdp_tokio::reqwest::ReqwestNetworkClient::new(),
                    "localhost".into(),
                    server_public_key.to_owned(),
                    None,
                )
                .await?;
                // The server validates the credentials once the connection sequence is over.
                Ok(tokio::time::timeout(Duration::from_secs(10), delegated_rx).await??)
            }
            .await;

            server.await.unwrap()?;
            result
        }))
        .await
}
