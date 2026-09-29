//! The server-direction halves of the drive PDUs ([MS-RDPEFS] 2.2.3): what a server sends to a client
//! and what it reads back. Every request goes through the decoder a client uses and every response
//! through the encoder a client uses, so that the two halves agree on the wire.
//!
//! [MS-RDPEFS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpefs/34d9de58-b2b5-40b6-b970-f82d4603bdb5

use ironrdp_core::{ReadCursor, encode_vec};
use ironrdp_rdpdr::pdu::efs::{
    Boolean, ClientDeviceListAnnounce, ClientDeviceListRemove, ClientDriveQueryDirectoryResponse,
    ClientDriveQueryInformationResponse, ClientNameRequest, ClientNameRequestUnicodeFlag, CreateDisposition,
    CreateOptions, DesiredAccess, DeviceCloseRequest, DeviceCloseResponse, DeviceCreateRequest, DeviceCreateResponse,
    DeviceIoRequest, DeviceIoResponse, DeviceReadRequest, DeviceReadResponse, DeviceType, DeviceWriteRequest,
    DeviceWriteResponse, FileAllocationInformation, FileAttributes, FileBasicInformation, FileDirectoryInformation,
    FileDispositionInformation, FileEndOfFileInformation, FileInformationClass, FileInformationClassLevel,
    FileRenameInformation, FileStandardInformation, Information, MajorFunction, MinorFunction, NtStatus,
    ServerDriveIoRequest, ServerDriveQueryDirectoryRequest, ServerDriveQueryInformationRequest,
    ServerDriveSetInformationRequest, SharedAccess,
};
use ironrdp_rdpdr::pdu::{PacketId, RdpdrPdu, SharedHeader};

const DEVICE_ID: u32 = 7;
const FILE_ID: u32 = 3;
const COMPLETION_ID: u32 = 42;

fn io_request(major_function: MajorFunction, minor_function: MinorFunction) -> DeviceIoRequest {
    DeviceIoRequest {
        device_id: DEVICE_ID,
        file_id: FILE_ID,
        completion_id: COMPLETION_ID,
        major_function,
        minor_function,
    }
}

fn io_response(io_status: NtStatus) -> DeviceIoResponse {
    DeviceIoResponse {
        device_id: DEVICE_ID,
        completion_id: COMPLETION_ID,
        io_status,
    }
}

/// Encodes `request` as a server sends it and decodes it as a client does.
fn through_client(request: &ServerDriveIoRequest) -> ServerDriveIoRequest {
    let bytes = encode_vec(request).unwrap();
    let mut src = ReadCursor::new(&bytes);
    let header = SharedHeader::decode(&mut src).unwrap();
    assert_eq!(header.packet_id, PacketId::CoreDeviceIoRequest);
    let dev_io_req = DeviceIoRequest::decode(&mut src).unwrap();
    ServerDriveIoRequest::decode(dev_io_req, &mut src).unwrap()
}

/// Encodes `pdu` as a client sends it and returns what follows the RDPDR header, which is what a
/// server gives to the decoders.
fn body_from_client(pdu: RdpdrPdu, packet_id: PacketId) -> Vec<u8> {
    let bytes = encode_vec(&pdu).unwrap();
    let mut src = ReadCursor::new(&bytes);
    let header = SharedHeader::decode(&mut src).unwrap();
    assert_eq!(header.packet_id, packet_id);
    src.remaining().to_vec()
}

fn device_announce(device_type: u32, device_id: u32, dos_name: &[u8; 8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&device_type.to_le_bytes());
    out.extend_from_slice(&device_id.to_le_bytes());
    out.extend_from_slice(dos_name);
    out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
    out.extend_from_slice(data);
    out
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

#[test]
fn client_name_is_read_in_either_encoding() {
    for (name, flag) in [
        ("DESKTOP-01", ClientNameRequestUnicodeFlag::Unicode),
        ("linux-box", ClientNameRequestUnicodeFlag::Ascii),
    ] {
        let sent = ClientNameRequest::new(name.to_owned(), flag);
        let body = body_from_client(RdpdrPdu::ClientNameRequest(sent.clone()), PacketId::CoreClientName);
        assert_eq!(ClientNameRequest::decode(&mut ReadCursor::new(&body)).unwrap(), sent);
    }
}

#[test]
fn drive_announces_keep_their_full_name_in_device_data() {
    // mstsc follows the specification: the full name as UTF-16 in DeviceData. FreeRDP sends the full
    // name as 8-bit characters and cuts PreferredDosName to eight characters without a terminator.
    let mut body = 3u32.to_le_bytes().to_vec();
    body.extend(device_announce(0x08, 1, b"C\0\0\0\0\0\0\0", &utf16z("C on DESKTOP-01")));
    body.extend(device_announce(0x08, 2, b"Document", b"Documents_2026\0"));
    body.extend(device_announce(0x20, 3, b"SCARD\0\0\0", b""));

    let announce = ClientDeviceListAnnounce::decode(&mut ReadCursor::new(&body)).unwrap();
    let devices: Vec<_> = announce
        .device_list
        .iter()
        .map(|d| (d.device_id(), d.device_type(), d.preferred_dos_name().to_owned(), d.device_data().to_vec()))
        .collect();
    assert_eq!(
        devices,
        [
            (1, DeviceType::Filesystem, "C".to_owned(), utf16z("C on DESKTOP-01")),
            (2, DeviceType::Filesystem, "Document".to_owned(), b"Documents_2026\0".to_vec()),
            (3, DeviceType::Smartcard, "SCARD".to_owned(), Vec::new()),
        ]
    );
}

#[test]
fn truncated_device_announce_is_an_error() {
    let mut body = 1u32.to_le_bytes().to_vec();
    body.extend(device_announce(0x08, 1, b"C\0\0\0\0\0\0\0", b"C\0"));
    body.truncate(body.len() - 1);
    assert!(ClientDeviceListAnnounce::decode(&mut ReadCursor::new(&body)).is_err());
}

#[test]
fn device_list_remove_round_trips() {
    let sent = ClientDeviceListRemove {
        device_list: vec![1, 7],
    };
    let body = body_from_client(RdpdrPdu::ClientDeviceListRemove(sent.clone()), PacketId::CoreDevicelistRemove);
    assert_eq!(ClientDeviceListRemove::decode(&mut ReadCursor::new(&body)).unwrap(), sent);

    // A count larger than the ids that follow must not be read past the end.
    let mut short = 3u32.to_le_bytes().to_vec();
    short.extend_from_slice(&1u32.to_le_bytes());
    assert!(ClientDeviceListRemove::decode(&mut ReadCursor::new(&short)).is_err());
}

#[test]
fn create_request_round_trips() {
    let request = ServerDriveIoRequest::ServerCreateDriveRequest(DeviceCreateRequest {
        device_io_request: io_request(MajorFunction::Create, MinorFunction::from(0)),
        desired_access: DesiredAccess::FILE_READ_DATA_OR_FILE_LIST_DIRECTORY
            | DesiredAccess::FILE_READ_ATTRIBUTES
            | DesiredAccess::SYNCHRONIZE,
        allocation_size: 0,
        file_attributes: FileAttributes::empty(),
        shared_access: SharedAccess::FILE_SHARE_READ | SharedAccess::FILE_SHARE_WRITE | SharedAccess::FILE_SHARE_DELETE,
        create_disposition: CreateDisposition::FILE_OPEN_IF,
        create_options: CreateOptions::FILE_SYNCHRONOUS_IO_NONALERT | CreateOptions::FILE_NON_DIRECTORY_FILE,
        path: "\\docs\\caf\u{e9} report.txt".to_owned(),
    });
    assert_eq!(through_client(&request), request);
}

#[test]
fn create_response_round_trips() {
    let sent = DeviceCreateResponse {
        device_io_reply: io_response(NtStatus::SUCCESS),
        file_id: 9,
        information: Information::FILE_OPENED,
    };
    let body = body_from_client(RdpdrPdu::DeviceCreateResponse(sent.clone()), PacketId::CoreDeviceIoCompletion);
    assert_eq!(DeviceCreateResponse::decode(&mut ReadCursor::new(&body)).unwrap(), sent);
}

#[test]
fn read_request_and_response_round_trip() {
    let request = ServerDriveIoRequest::DeviceReadRequest(DeviceReadRequest {
        device_io_request: io_request(MajorFunction::Read, MinorFunction::from(0)),
        length: 262_144,
        offset: 0x1_0000_0000,
    });
    assert_eq!(through_client(&request), request);

    let body = body_from_client(
        RdpdrPdu::DeviceReadResponse(DeviceReadResponse {
            device_io_reply: io_response(NtStatus::SUCCESS),
            read_data: b"hello".to_vec(),
        }),
        PacketId::CoreDeviceIoCompletion,
    );
    let response = DeviceReadResponse::decode(&mut ReadCursor::new(&body)).unwrap();
    assert_eq!(response.device_io_reply, io_response(NtStatus::SUCCESS));
    assert_eq!(response.read_data, b"hello");
}

#[test]
fn read_request_wire_layout() {
    // Header, DeviceIoRequest, Length, Offset and 20 bytes of padding ([MS-RDPEFS] 2.2.1.4.3).
    let request = ServerDriveIoRequest::DeviceReadRequest(DeviceReadRequest {
        device_io_request: io_request(MajorFunction::Read, MinorFunction::from(0)),
        length: 4096,
        offset: 8192,
    });
    let bytes = encode_vec(&request).unwrap();
    let mut expected = Vec::new();
    expected.extend_from_slice(&0x4472u16.to_le_bytes()); // RDPDR_CTYP_CORE
    expected.extend_from_slice(&0x4952u16.to_le_bytes()); // PAKID_CORE_DEVICE_IOREQUEST
    for field in [DEVICE_ID, FILE_ID, COMPLETION_ID, 0x03, 0x00] {
        expected.extend_from_slice(&field.to_le_bytes()); // DeviceId FileId CompletionId IRP_MJ_READ minor
    }
    expected.extend_from_slice(&4096u32.to_le_bytes());
    expected.extend_from_slice(&8192u64.to_le_bytes());
    expected.extend_from_slice(&[0; 20]);
    assert_eq!(bytes, expected);
}

#[test]
fn write_request_and_response_round_trip() {
    let request = ServerDriveIoRequest::DeviceWriteRequest(DeviceWriteRequest {
        device_io_request: io_request(MajorFunction::Write, MinorFunction::from(0)),
        offset: 12,
        write_data: vec![1, 2, 3, 4, 5],
    });
    assert_eq!(through_client(&request), request);

    let sent = DeviceWriteResponse {
        device_io_reply: io_response(NtStatus::SUCCESS),
        length: 5,
    };
    let body = body_from_client(RdpdrPdu::DeviceWriteResponse(sent.clone()), PacketId::CoreDeviceIoCompletion);
    assert_eq!(DeviceWriteResponse::decode(&mut ReadCursor::new(&body)).unwrap(), sent);
}

#[test]
fn close_request_and_response_round_trip() {
    let request = ServerDriveIoRequest::DeviceCloseRequest(DeviceCloseRequest {
        device_io_request: io_request(MajorFunction::Close, MinorFunction::from(0)),
    });
    assert_eq!(through_client(&request), request);

    let sent = DeviceCloseResponse {
        device_io_response: io_response(NtStatus::SUCCESS),
    };
    let body = body_from_client(RdpdrPdu::DeviceCloseResponse(sent.clone()), PacketId::CoreDeviceIoCompletion);
    assert_eq!(DeviceCloseResponse::decode(&mut ReadCursor::new(&body)).unwrap(), sent);
}

#[test]
fn query_directory_requests_round_trip() {
    for (initial_query, path) in [(1, "\\docs\\*"), (0, "")] {
        let request = ServerDriveIoRequest::ServerDriveQueryDirectoryRequest(ServerDriveQueryDirectoryRequest {
            device_io_request: io_request(MajorFunction::DirectoryControl, MinorFunction::IRP_MN_QUERY_DIRECTORY),
            file_info_class_lvl: FileInformationClassLevel::FILE_DIRECTORY_INFORMATION,
            initial_query,
            path: path.to_owned(),
        });
        assert_eq!(through_client(&request), request);
    }
}

#[test]
fn query_directory_response_carries_one_entry_or_none() {
    let entry = FileDirectoryInformation::new(
        133_000_000_000_000_000,
        133_000_000_000_000_001,
        133_000_000_000_000_002,
        133_000_000_000_000_003,
        1234,
        FileAttributes::FILE_ATTRIBUTE_ARCHIVE,
        "report.txt".to_owned(),
    );
    let sent = ClientDriveQueryDirectoryResponse {
        device_io_reply: io_response(NtStatus::SUCCESS),
        buffer: Some(FileInformationClass::Directory(entry)),
    };
    let body = body_from_client(
        RdpdrPdu::ClientDriveQueryDirectoryResponse(sent.clone()),
        PacketId::CoreDeviceIoCompletion,
    );
    let level = FileInformationClassLevel::FILE_DIRECTORY_INFORMATION;
    assert_eq!(
        ClientDriveQueryDirectoryResponse::decode(&mut ReadCursor::new(&body), level.clone()).unwrap(),
        sent
    );

    let end = ClientDriveQueryDirectoryResponse {
        device_io_reply: io_response(NtStatus::NO_MORE_FILES),
        buffer: None,
    };
    let body = body_from_client(
        RdpdrPdu::ClientDriveQueryDirectoryResponse(end.clone()),
        PacketId::CoreDeviceIoCompletion,
    );
    assert_eq!(
        ClientDriveQueryDirectoryResponse::decode(&mut ReadCursor::new(&body), level).unwrap(),
        end
    );
}

#[test]
fn query_information_request_round_trips_and_sends_no_query_buffer() {
    for level in [
        FileInformationClassLevel::FILE_BASIC_INFORMATION,
        FileInformationClassLevel::FILE_STANDARD_INFORMATION,
    ] {
        let request = ServerDriveIoRequest::ServerDriveQueryInformationRequest(ServerDriveQueryInformationRequest {
            device_io_request: io_request(MajorFunction::QueryInformation, MinorFunction::from(0)),
            file_info_class_lvl: level,
        });
        assert_eq!(through_client(&request), request);

        // Header 4, DeviceIoRequest 20, FsInformationClass 4, Length 4 (zero), Padding 24.
        let bytes = encode_vec(&request).unwrap();
        assert_eq!(bytes.len(), 56);
        assert_eq!(bytes[28..32], [0, 0, 0, 0]);
    }
}

#[test]
fn query_information_responses_round_trip() {
    let basic = FileInformationClass::Basic(FileBasicInformation {
        creation_time: 133_000_000_000_000_000,
        last_access_time: 133_000_000_000_000_001,
        last_write_time: 133_000_000_000_000_002,
        change_time: 133_000_000_000_000_003,
        file_attributes: FileAttributes::FILE_ATTRIBUTE_DIRECTORY,
    });
    let standard = FileInformationClass::Standard(FileStandardInformation {
        allocation_size: 4096,
        end_of_file: 1234,
        number_of_links: 1,
        delete_pending: Boolean::False,
        directory: Boolean::False,
    });
    for (level, buffer) in [
        (FileInformationClassLevel::FILE_BASIC_INFORMATION, basic),
        (FileInformationClassLevel::FILE_STANDARD_INFORMATION, standard),
    ] {
        let sent = ClientDriveQueryInformationResponse {
            device_io_response: io_response(NtStatus::SUCCESS),
            buffer: Some(buffer),
        };
        let body = body_from_client(
            RdpdrPdu::ClientDriveQueryInformationResponse(sent.clone()),
            PacketId::CoreDeviceIoCompletion,
        );
        assert_eq!(
            ClientDriveQueryInformationResponse::decode(&mut ReadCursor::new(&body), level).unwrap(),
            sent
        );
    }

    let failed = ClientDriveQueryInformationResponse {
        device_io_response: io_response(NtStatus::OBJECT_NAME_NOT_FOUND),
        buffer: None,
    };
    let body = body_from_client(
        RdpdrPdu::ClientDriveQueryInformationResponse(failed.clone()),
        PacketId::CoreDeviceIoCompletion,
    );
    assert_eq!(
        ClientDriveQueryInformationResponse::decode(
            &mut ReadCursor::new(&body),
            FileInformationClassLevel::FILE_BASIC_INFORMATION
        )
        .unwrap(),
        failed
    );
}

#[test]
fn set_information_requests_round_trip() {
    for set_buffer in [
        FileInformationClass::EndOfFile(FileEndOfFileInformation { end_of_file: 1 << 33 }),
        FileInformationClass::Disposition(FileDispositionInformation { delete_pending: 1 }),
        FileInformationClass::Rename(FileRenameInformation {
            replace_if_exists: Boolean::True,
            file_name: "\\docs\\new name.txt".to_owned(),
        }),
        FileInformationClass::Allocation(FileAllocationInformation { allocation_size: 65_536 }),
    ] {
        let request = ServerDriveIoRequest::ServerDriveSetInformationRequest(ServerDriveSetInformationRequest {
            device_io_request: io_request(MajorFunction::SetInformation, MinorFunction::from(0)),
            set_buffer,
        });
        assert_eq!(through_client(&request), request);
    }
}

#[test]
fn requests_a_server_cannot_send_are_an_error() {
    let request = ServerDriveIoRequest::DeviceControlRequest(ironrdp_rdpdr::pdu::efs::DeviceControlRequest {
        header: io_request(MajorFunction::DeviceControl, MinorFunction::from(0)),
        output_buffer_length: 0,
        input_buffer_length: 0,
        io_control_code: ironrdp_rdpdr::pdu::efs::AnyIoCtlCode(0),
    });
    assert!(encode_vec(&request).is_err());
}
