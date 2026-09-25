#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]

use ironrdp_async::{Framed, FramedRead, FramedWrite, NetworkClient, StreamWrapper, single_sequence_step};
use ironrdp_connector::sspi::credssp::{CredentialsProxy, EarlyUserAuthResult};
use ironrdp_connector::sspi::{AuthIdentity, KerberosServerConfig, Username, UsernameParts};
use ironrdp_connector::{ConnectorResult, ServerName, custom_err, general_err};
use ironrdp_core::WriteBuf;
use tracing::{debug, instrument, trace};

mod channel_connection;
mod connection;
pub mod credssp;
mod finalization;
mod util;

pub use ironrdp_connector::DesktopSize;
use ironrdp_pdu::nego;
use ironrdp_pdu::rdp::client_info::Credentials;

pub use self::channel_connection::{ChannelConnectionSequence, ChannelConnectionState};
pub use self::connection::{Acceptor, AcceptorResult, AcceptorState};
pub use self::finalization::{FinalizationSequence, FinalizationState};
use crate::credssp::resolve_generator;

pub enum BeginResult<S>
where
    S: StreamWrapper,
{
    ShouldUpgrade(S::InnerStream),
    Continue(Framed<S>),
}

pub async fn accept_begin<S>(mut framed: Framed<S>, acceptor: &mut Acceptor) -> ConnectorResult<BeginResult<S>>
where
    S: FramedRead + FramedWrite + StreamWrapper,
{
    let mut buf = WriteBuf::new();

    loop {
        if let Some(security) = acceptor.reached_security_upgrade() {
            let result = if security.is_empty() {
                BeginResult::Continue(framed)
            } else {
                BeginResult::ShouldUpgrade(framed.into_inner_no_leftover())
            };

            return Ok(result);
        }

        single_sequence_step(&mut framed, acceptor, &mut buf).await?;
    }
}

pub async fn accept_credssp<S, N>(
    framed: &mut Framed<S>,
    acceptor: &mut Acceptor,
    network_client: &mut N,
    client_computer_name: ServerName,
    public_key: Vec<u8>,
    kerberos_config: Option<KerberosServerConfig>,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    let mut buf = WriteBuf::new();

    if acceptor.should_perform_credssp() {
        perform_credssp_step(
            framed,
            acceptor,
            network_client,
            &mut buf,
            client_computer_name,
            public_key,
            kerberos_config,
            None,
        )
        .await
    } else {
        Ok(())
    }
}

/// Like [`accept_credssp`], but verifies the client against the credentials `lookup` returns for
/// the name the client authenticates as, instead of the single account the acceptor holds.
///
/// See [`credssp::CredsspSequence::init_with_lookup`].
pub async fn accept_credssp_with_lookup<S, N>(
    framed: &mut Framed<S>,
    acceptor: &mut Acceptor,
    network_client: &mut N,
    client_computer_name: ServerName,
    public_key: Vec<u8>,
    kerberos_config: Option<KerberosServerConfig>,
    lookup: &mut (dyn CredentialsProxy<AuthenticationData = AuthIdentity> + Send),
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    let mut buf = WriteBuf::new();

    if acceptor.should_perform_credssp() {
        perform_credssp_step(
            framed,
            acceptor,
            network_client,
            &mut buf,
            client_computer_name,
            public_key,
            kerberos_config,
            Some(lookup),
        )
        .await
    } else {
        Ok(())
    }
}

pub async fn accept_finalize<S>(
    mut framed: Framed<S>,
    acceptor: &mut Acceptor,
) -> ConnectorResult<(Framed<S>, AcceptorResult)>
where
    S: FramedRead + FramedWrite,
{
    let mut buf = WriteBuf::new();

    loop {
        if let Some(result) = acceptor.get_result() {
            return Ok((framed, result));
        }
        single_sequence_step(&mut framed, acceptor, &mut buf).await?;
    }
}

#[instrument(level = "trace", skip_all, ret)]
#[expect(clippy::too_many_arguments)]
async fn perform_credssp_step<S, N>(
    framed: &mut Framed<S>,
    acceptor: &mut Acceptor,
    network_client: &mut N,
    buf: &mut WriteBuf,
    client_computer_name: ServerName,
    public_key: Vec<u8>,
    kerberos_config: Option<KerberosServerConfig>,
    lookup: Option<&mut (dyn CredentialsProxy<AuthenticationData = AuthIdentity> + Send)>,
) -> ConnectorResult<()>
where
    S: FramedRead + FramedWrite,
    N: NetworkClient,
{
    assert!(acceptor.should_perform_credssp());
    let AcceptorState::Credssp { protocol, .. } = acceptor.state else {
        unreachable!()
    };

    let result = credssp_loop(
        framed,
        acceptor,
        network_client,
        buf,
        client_computer_name,
        public_key,
        kerberos_config,
        lookup,
    )
    .await;

    if protocol.intersects(nego::SecurityProtocol::HYBRID_EX) {
        trace!(?result, "HYBRID_EX");

        let result = if result.is_ok() {
            EarlyUserAuthResult::Success
        } else {
            EarlyUserAuthResult::AccessDenied
        };

        buf.clear();
        result
            .to_buffer(&mut *buf)
            .map_err(|e| ironrdp_connector::custom_err!("to_buffer", e))?;
        let response = &buf[..result.buffer_len()];
        framed
            .write_all(response)
            .await
            .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
    }

    result?;

    acceptor.mark_credssp_as_done();

    return Ok(());

    #[expect(clippy::too_many_arguments)]
    async fn credssp_loop<S, N>(
        framed: &mut Framed<S>,
        acceptor: &mut Acceptor,
        network_client: &mut N,
        buf: &mut WriteBuf,
        client_computer_name: ServerName,
        public_key: Vec<u8>,
        kerberos_config: Option<KerberosServerConfig>,
        lookup: Option<&mut (dyn CredentialsProxy<AuthenticationData = AuthIdentity> + Send)>,
    ) -> ConnectorResult<()>
    where
        S: FramedRead + FramedWrite,
        N: NetworkClient,
    {
        let identity;
        let mut sequence = if let Some(lookup) = lookup {
            credssp::CredsspSequence::init_with_lookup(lookup, client_computer_name, public_key, kerberos_config)?
        } else {
            let creds = acceptor
                .creds
                .as_ref()
                .ok_or_else(|| general_err!("no credentials while doing credssp"))?;
            let username = Username::new(&creds.username, None).map_err(|e| custom_err!("invalid username", e))?;
            identity = AuthIdentity {
                username,
                password: creds.password.clone().into(),
            };
            credssp::CredsspSequence::init(&identity, client_computer_name, public_key, kerberos_config)?
        };

        loop {
            let Some(next_pdu_hint) = sequence.next_pdu_hint()? else {
                break;
            };

            debug!(
                acceptor.state = ?acceptor.state,
                hint = ?next_pdu_hint,
                "Wait for PDU"
            );

            let pdu = framed
                .read_by_hint(next_pdu_hint)
                .await
                .map_err(|e| ironrdp_connector::custom_err!("read frame by hint", e))?;

            trace!(length = pdu.len(), "PDU received");

            let Some(ts_request) = sequence.decode_client_message(&pdu)? else {
                break;
            };

            let result = {
                let mut generator = sequence.process_ts_request(ts_request);
                resolve_generator(&mut generator, network_client).await
            }; // drop generator

            buf.clear();
            let written = sequence.handle_process_result(result, buf)?;

            if let Some(response_len) = written.size() {
                let response = &buf[..response_len];
                trace!(response_len, "Send response");
                framed
                    .write_all(response)
                    .await
                    .map_err(|e| ironrdp_connector::custom_err!("write all", e))?;
            }
        }

        acceptor.received_credentials = sequence.take_delegated_credentials().map(|delegated| {
            // Shaped like the credentials of a ClientInfoPdu: a user principal name stays whole,
            // a down-level logon name splits into account and domain.
            let (username, domain) = match delegated.username.parts() {
                UsernameParts::UserPrincipalName(name) => (name.upn(), None),
                UsernameParts::DownLevelLogonName(name) => (name.account_name(), name.netbios_domain()),
            };
            Credentials {
                username: username.to_owned(),
                password: delegated.password.as_ref().clone(),
                domain: domain.map(str::to_owned),
            }
        });

        Ok(())
    }
}
