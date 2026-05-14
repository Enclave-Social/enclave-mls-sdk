// Copyright (C) 2026 Enclave Technologies LLC
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#![allow(dead_code, unused_imports, unused_variables)]

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_memory_storage::MemoryStorage;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{HashMap, BTreeMap};
use std::convert::TryFrom;
use tls_codec::{
    Deserialize as TlsDeserializeTrait,
    Serialize as TlsSerializeTrait,
};
use wasm_bindgen::prelude::*;

const DEFAULT_CIPHERSUITE_NAME: &str =
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

thread_local! {
    static CLIENTS: RefCell<HashMap<String, ClientState>> = RefCell::new(HashMap::new());
    static GROUPS: RefCell<HashMap<String, StoredGroupState>> = RefCell::new(HashMap::new());
}

struct ClientState {
    user_id: String,
    device_id: String,
    identity: String,
    provider: OpenMlsRustCrypto,
    ciphersuite: Ciphersuite,
    signature_public_key: Vec<u8>,
}

struct StoredGroupState {
    group: MlsGroup,
    member_identities: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateIdentityRequest {
    client_id: String,
    user_id: String,
    device_id: String,
    identity: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateKeyPackageRequest {
    client_id: String,
    lifetime_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupRequest {
    client_id: String,
    group_id: Option<String>,
    member_key_packages: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddMembersRequest {
    client_id: String,
    group_id: String,
    member_key_packages: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinFromWelcomeRequest {
    client_id: String,
    welcome: String,
    ratchet_tree: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateApplicationMessageRequest {
    client_id: String,
    group_id: String,
    plaintext: String,
    authenticated_data: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcessIncomingMessageRequest {
    client_id: String,
    group_id: String,
    message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportGroupStateRequest {
    client_id: String,
    group_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportedGroupState {
    group_id: String,
    group_data: BTreeMap<String, String>, 
    member_identities: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportGroupStateRequest {
    client_id: String,
    state: ExportedGroupState,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportedClientState {
    user_id: String,
    device_id: String,
    identity: String,
    signature_public_key: String, // Base64
    storage_data: BTreeMap<String, String>, 
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportClientStateRequest {
    client_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportClientStateRequest {
    client_id: String,
    state: ExportedClientState,
}

#[derive(Serialize)]
struct OpenMlsBuildInfo {
    crate_name: &'static str,
    crate_version: String,
    ciphersuite: &'static str,
    runtime: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityRecordResponse {
    client_id: String,
    user_id: String,
    device_id: String,
    identity: String,
    ciphersuite: &'static str,
    signature_key_length: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyPackageRecordResponse {
    client_id: String,
    key_package_ref: String,
    ciphersuite: &'static str,
    credential_identity: String,
    key_package: String,
    expires_at: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupRecordResponse {
    client_id: String,
    group_id: String,
    epoch: u64,
    ciphersuite: &'static str,
    member_identities: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WelcomeRecordResponse {
    group_id: String,
    welcome: String,
    inviter_identity: Option<String>,
    ratchet_tree: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateGroupResponse {
    group: GroupRecordResponse,
    welcome: Option<WelcomeRecordResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AddMembersResponse {
    group: GroupRecordResponse,
    welcome: WelcomeRecordResponse,
    commit_message: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApplicationMessageResponse {
    group_id: String,
    epoch: u64,
    message: String,
    authenticated_data: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessIncomingMessageResponse {
    group_id: String,
    epoch: u64,
    sender_identity: Option<String>,
    content_type: &'static str,
    plaintext: Option<String>,
    commit: Option<String>,
    welcome: Option<String>,
}

fn default_ciphersuite() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn default_group_config(ciphersuite: Ciphersuite) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build()
}

fn parse_json<T: for<'a> Deserialize<'a>>(request_json: &str) -> Result<T, JsValue> {
    serde_json::from_str(request_json)
        .map_err(|error| JsValue::from_str(&format!("invalid request JSON: {error}")))
}

fn to_json_string<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value)
        .map_err(|error| JsValue::from_str(&format!("failed to serialize response: {error}")))
}

fn encode_tls<T: TlsSerializeTrait>(value: &T) -> Result<String, JsValue> {
    value
        .tls_serialize_detached()
        .map(|bytes| BASE64.encode(bytes))
        .map_err(|error| JsValue::from_str(&format!("TLS serialization failed: {error:?}")))
}

fn encode_mls_message(message: &MlsMessageOut) -> Result<String, JsValue> {
    message
        .to_bytes()
        .map(|bytes| BASE64.encode(bytes))
        .map_err(|error| JsValue::from_str(&format!("message serialization failed: {error:?}")))
}

fn decode_mls_message(encoded: &str) -> Result<MlsMessageIn, JsValue> {
    let bytes = decode_base64(encoded)?;
    MlsMessageIn::tls_deserialize_exact(bytes.as_slice())
        .map_err(|error| JsValue::from_str(&format!("message deserialization failed: {error:?}")))
}

fn decode_welcome(encoded: &str) -> Result<Welcome, JsValue> {
    match decode_mls_message(encoded)?.extract() {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err(JsValue::from_str("expected a Welcome message")),
    }
}

fn decode_ratchet_tree(encoded: &str) -> Result<RatchetTreeIn, JsValue> {
    let bytes = decode_base64(encoded)?;
    RatchetTreeIn::tls_deserialize_exact(bytes.as_slice()).map_err(|error| {
        JsValue::from_str(&format!("ratchet tree deserialization failed: {error:?}"))
    })
}

fn encode_ratchet_tree(group: &MlsGroup) -> Result<String, JsValue> {
    let ratchet_tree: RatchetTreeIn = group.export_ratchet_tree().into();
    encode_tls(&ratchet_tree)
}

fn group_state_key(client_id: &str, group_id: &str) -> String {
    format!("{client_id}:{group_id}")
}

fn identity_from_credential(credential: Credential) -> Option<String> {
    BasicCredential::try_from(credential)
        .ok()
        .map(|credential| String::from_utf8_lossy(credential.identity()).into_owned())
}

fn group_id_to_string(group_id: &GroupId) -> String {
    String::from_utf8(group_id.as_slice().to_vec())
        .unwrap_or_else(|_| BASE64.encode(group_id.as_slice()))
}

fn group_epoch_to_u64(epoch: GroupEpoch) -> u64 {
    epoch.as_u64()
}

fn build_group_record(
    client_id: &str,
    group_id: String,
    epoch: u64,
    member_identities: Vec<String>,
) -> GroupRecordResponse {
    GroupRecordResponse {
        client_id: client_id.to_string(),
        group_id,
        epoch,
        ciphersuite: DEFAULT_CIPHERSUITE_NAME,
        member_identities,
    }
}

fn stored_member_identities(group: &MlsGroup) -> Vec<String> {
    group.members()
        .filter_map(|member| identity_from_credential(member.credential))
        .collect()
}

fn lookup_client<T>(
    client_id: &str,
    callback: impl FnOnce(&ClientState) -> Result<T, JsValue>,
) -> Result<T, JsValue> {
    CLIENTS.with(|clients| {
        let clients = clients.borrow();
        let client = clients
            .get(client_id)
            .ok_or_else(|| JsValue::from_str(&format!("unknown MLS client: {client_id}")))?;
        callback(client)
    })
}

fn key_packages_from_base64(
    crypto: &impl OpenMlsCrypto,
    encoded_packages: &[String],
) -> Result<Vec<KeyPackage>, JsValue> {
    encoded_packages
        .iter()
        .map(|encoded| {
            let bytes = decode_base64(encoded)?;
            let key_package_in = KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
                .map_err(|error| {
                    JsValue::from_str(&format!("failed to deserialize key package: {error:?}"))
                })?;
            key_package_in
                .validate(crypto, ProtocolVersion::Mls10)
                .map_err(|error| {
                    JsValue::from_str(&format!("failed to validate key package: {error:?}"))
                })
        })
        .collect()
}

fn decode_base64(value: &str) -> Result<Vec<u8>, JsValue> {
    BASE64
        .decode(value)
        .map_err(|error| JsValue::from_str(&format!("base64 decode failed: {error}")))
}

#[wasm_bindgen]
pub fn openmls_build_info() -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(&OpenMlsBuildInfo {
        crate_name: "openmls",
        crate_version: env!("CARGO_PKG_VERSION").to_string(),
        ciphersuite: DEFAULT_CIPHERSUITE_NAME,
        runtime: "wasm32/browser-or-node-with-js-apis",
    })
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
pub fn create_identity_record(request_json: String) -> Result<String, JsValue> {
    let request: CreateIdentityRequest = parse_json(&request_json)?;
    let ciphersuite = default_ciphersuite();
    let provider = OpenMlsRustCrypto::default();
    
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm())
        .map_err(|error| JsValue::from_str(&format!("signature generation failed: {error:?}")))?;

    signature_keys
        .store(provider.storage())
        .map_err(|error| JsValue::from_str(&format!("storing signature key failed: {error:?}")))?;

    let public_key = signature_keys.to_public_vec();

    CLIENTS.with(|clients| {
        clients.borrow_mut().insert(
            request.client_id.clone(),
            ClientState {
                user_id: request.user_id.clone(),
                device_id: request.device_id.clone(),
                identity: request.identity.clone(),
                provider,
                ciphersuite,
                signature_public_key: public_key.clone(),
            },
        );
    });

    to_json_string(&IdentityRecordResponse {
        client_id: request.client_id,
        user_id: request.user_id,
        device_id: request.device_id,
        identity: request.identity,
        ciphersuite: DEFAULT_CIPHERSUITE_NAME,
        signature_key_length: public_key.len(),
    })
}

#[wasm_bindgen]
pub fn create_key_package(request_json: String) -> Result<String, JsValue> {
    let request: CreateKeyPackageRequest = parse_json(&request_json)?;

    lookup_client(&request.client_id, |client| {
        let signature_keys = SignatureKeyPair::read(client.provider.storage(), &client.signature_public_key, client.ciphersuite.signature_algorithm())
            .ok_or_else(|| JsValue::from_str("no signature keys in storage"))?;

        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(client.identity.clone().into_bytes()).into(),
            signature_key: client.signature_public_key.clone().into(),
        };

        let key_package_bundle = KeyPackage::builder()
            .build(
                client.ciphersuite,
                &client.provider,
                &signature_keys,
                credential_with_key,
            )
            .map_err(|error| JsValue::from_str(&format!("key package creation failed: {error:?}")))?;

        let key_package_ref = key_package_bundle
            .key_package()
            .hash_ref(client.provider.crypto())
            .map_err(|error| JsValue::from_str(&format!("key package ref failed: {error:?}")))?;

        let key_package = key_package_bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| {
                JsValue::from_str(&format!("key package serialization failed: {error:?}"))
            })?;

        to_json_string(&KeyPackageRecordResponse {
            client_id: request.client_id.clone(),
            key_package_ref: BASE64.encode(key_package_ref.as_slice()),
            ciphersuite: DEFAULT_CIPHERSUITE_NAME,
            credential_identity: client.identity.clone(),
            key_package: BASE64.encode(key_package),
            expires_at: None,
        })
    })
}

#[wasm_bindgen]
pub fn create_group(request_json: String) -> Result<String, JsValue> {
    let request: CreateGroupRequest = parse_json(&request_json)?;

    lookup_client(&request.client_id, |client| {
        let signature_keys = SignatureKeyPair::read(client.provider.storage(), &client.signature_public_key, client.ciphersuite.signature_algorithm())
            .ok_or_else(|| JsValue::from_str("no signature keys in storage"))?;

        let credential_with_key = CredentialWithKey {
            credential: BasicCredential::new(client.identity.clone().into_bytes()).into(),
            signature_key: client.signature_public_key.clone().into(),
        };

        let group_id = normalized_group_id(request.group_id.clone());
        let mut group = MlsGroup::new_with_group_id(
            &client.provider,
            &signature_keys,
            &default_group_config(client.ciphersuite),
            GroupId::from_slice(group_id.as_bytes()),
            credential_with_key,
        )
        .map_err(|error| JsValue::from_str(&format!("group creation failed: {error:?}")))?;

        let mut welcome_response = None;

        if let Some(encoded_key_packages) = request.member_key_packages.as_ref() {
            if !encoded_key_packages.is_empty() {
                let key_packages =
                    key_packages_from_base64(client.provider.crypto(), encoded_key_packages)?;

                let (_commit_message, welcome_message, _group_info) = group
                    .add_members(&client.provider, &signature_keys, &key_packages)
                    .map_err(|error| JsValue::from_str(&format!("add members failed: {error:?}")))?;

                group
                    .merge_pending_commit(&client.provider)
                    .map_err(|error| {
                        JsValue::from_str(&format!("merge pending commit failed: {error:?}"))
                    })?;

                welcome_response = Some(WelcomeRecordResponse {
                    group_id: group_id.clone(),
                    welcome: encode_mls_message(&welcome_message)?,
                    inviter_identity: Some(client.identity.clone()),
                    ratchet_tree: Some(encode_ratchet_tree(&group)?),
                });
            }
        }

        let member_identities = stored_member_identities(&group);
        let group_record = build_group_record(
            &request.client_id,
            group_id.clone(),
            group_epoch_to_u64(group.epoch()),
            member_identities.clone(),
        );

        GROUPS.with(|groups| {
            groups.borrow_mut().insert(
                group_state_key(&request.client_id, &group_id),
                StoredGroupState {
                    group,
                    member_identities,
                },
            );
        });

        to_json_string(&CreateGroupResponse {
            group: group_record,
            welcome: welcome_response,
        })
    })
}

#[wasm_bindgen]
pub fn join_from_welcome(request_json: String) -> Result<String, JsValue> {
    let request: JoinFromWelcomeRequest = parse_json(&request_json)?;

    lookup_client(&request.client_id, |client| {
        let welcome = decode_welcome(&request.welcome)?;
        let ratchet_tree = request
            .ratchet_tree
            .as_deref()
            .map(decode_ratchet_tree)
            .transpose()?;

        let group = StagedWelcome::new_from_welcome(
            &client.provider,
            &default_group_config(client.ciphersuite).join_config(),
            welcome,
            ratchet_tree,
        )
        .map_err(|error| JsValue::from_str(&format!("staging welcome failed: {error:?}")))?
        .into_group(&client.provider)
        .map_err(|error| JsValue::from_str(&format!("joining group failed: {error:?}")))?;

        let group_id = group_id_to_string(group.group_id());
        let member_identities = stored_member_identities(&group);
        let response = build_group_record(
            &request.client_id,
            group_id.clone(),
            group_epoch_to_u64(group.epoch()),
            member_identities.clone(),
        );

        GROUPS.with(|groups| {
            groups.borrow_mut().insert(
                group_state_key(&request.client_id, &group_id),
                StoredGroupState {
                    group,
                    member_identities,
                },
            );
        });

        to_json_string(&response)
    })
}

#[wasm_bindgen]
pub fn create_application_message(request_json: String) -> Result<String, JsValue> {
    let request: CreateApplicationMessageRequest = parse_json(&request_json)?;

    lookup_client(&request.client_id, |client| {
        let signature_keys = SignatureKeyPair::read(client.provider.storage(), &client.signature_public_key, client.ciphersuite.signature_algorithm())
            .ok_or_else(|| JsValue::from_str("no signature keys in storage"))?;

        GROUPS.with(|groups| {
            let mut groups = groups.borrow_mut();
            let stored_group = groups.get_mut(&group_state_key(&request.client_id, &request.group_id)).ok_or_else(|| {
                JsValue::from_str(&format!(
                    "unknown MLS group {} for client {}",
                    request.group_id, request.client_id
                ))
            })?;

            let message = stored_group
                .group
                .create_message(
                    &client.provider,
                    &signature_keys,
                    request.plaintext.as_bytes(),
                )
                .map_err(|error| {
                    JsValue::from_str(&format!("application message creation failed: {error:?}"))
                })?;

            to_json_string(&ApplicationMessageResponse {
                group_id: request.group_id,
                epoch: group_epoch_to_u64(stored_group.group.epoch()),
                message: encode_mls_message(&message)?,
                authenticated_data: None,
            })
        })
    })
}

#[wasm_bindgen]
pub fn process_incoming_message(request_json: String) -> Result<String, JsValue> {
    let request: ProcessIncomingMessageRequest = parse_json(&request_json)?;

    lookup_client(&request.client_id, |client| {
        GROUPS.with(|groups| {
            let mut groups = groups.borrow_mut();
            let stored_group = groups.get_mut(&group_state_key(&request.client_id, &request.group_id)).ok_or_else(|| {
                JsValue::from_str(&format!(
                    "unknown MLS group {} for client {}",
                    request.group_id, request.client_id
                ))
            })?;

            let protocol_message = decode_mls_message(&request.message)?
                .try_into_protocol_message()
                .map_err(|error| {
                    JsValue::from_str(&format!("protocol message conversion failed: {error:?}"))
                })?;

            let processed_message = stored_group
                .group
                .process_message(&client.provider, protocol_message)
                .map_err(|error| {
                    JsValue::from_str(&format!("message processing failed: {error:?}"))
                })?;

            let epoch = group_epoch_to_u64(processed_message.epoch());
            let sender_identity = identity_from_credential(processed_message.credential().clone());

            match processed_message.into_content() {
                ProcessedMessageContent::ApplicationMessage(application_message) => {
                    to_json_string(&ProcessIncomingMessageResponse {
                        group_id: request.group_id,
                        epoch,
                        sender_identity,
                        content_type: "application",
                        plaintext: Some(
                            String::from_utf8_lossy(&application_message.into_bytes()).into_owned(),
                        ),
                        commit: None,
                        welcome: None,
                    })
                }
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                    stored_group
                        .group
                        .merge_staged_commit(&client.provider, *staged_commit)
                        .map_err(|error| {
                            JsValue::from_str(&format!("commit merge failed: {error:?}"))
                        })?;
                    stored_group.member_identities = stored_member_identities(&stored_group.group);

                    to_json_string(&ProcessIncomingMessageResponse {
                        group_id: request.group_id,
                        epoch: group_epoch_to_u64(stored_group.group.epoch()),
                        sender_identity,
                        content_type: "commit",
                        plaintext: None,
                        commit: Some("merged".to_string()),
                        welcome: None,
                    })
                }
                _ => {
                    to_json_string(&ProcessIncomingMessageResponse {
                        group_id: request.group_id,
                        epoch,
                        sender_identity,
                        content_type: "other",
                        plaintext: None,
                        commit: None,
                        welcome: None,
                    })
                }
            }
        })
    })
}

#[wasm_bindgen]
pub fn export_client_state(request_json: String) -> Result<String, JsValue> {
    let request: ExportClientStateRequest = parse_json(&request_json)?;
    lookup_client(&request.client_id, |client| {
        let storage = client.provider.storage();
        let mut base64_data = BTreeMap::new();
        let values = storage.values.read().unwrap();
        for (k, v) in values.iter() {
            base64_data.insert(BASE64.encode(k), BASE64.encode(v));
        }

        to_json_string(&ExportedClientState {
            user_id: client.user_id.clone(),
            device_id: client.device_id.clone(),
            identity: client.identity.clone(),
            signature_public_key: BASE64.encode(&client.signature_public_key),
            storage_data: base64_data,
        })
    })
}

#[wasm_bindgen]
pub fn import_client_state(request_json: String) -> Result<String, JsValue> {
    let request: ImportClientStateRequest = parse_json(&request_json)?;
    let ciphersuite = default_ciphersuite();
    let provider = OpenMlsRustCrypto::default();
    
    let signature_public_key = decode_base64(&request.state.signature_public_key)?;

    {
        let storage = provider.storage();
        let mut values = storage.values.write().unwrap();
        for (k_b64, v_b64) in request.state.storage_data {
            let k = decode_base64(&k_b64)?;
            let v = decode_base64(&v_b64)?;
            values.insert(k, v);
        }
    }

    CLIENTS.with(|clients| {
        clients.borrow_mut().insert(
            request.client_id.clone(),
            ClientState {
                user_id: request.state.user_id.clone(),
                device_id: request.state.device_id.clone(),
                identity: request.state.identity.clone(),
                provider,
                ciphersuite,
                signature_public_key,
            },
        );
    });

    to_json_string(&IdentityRecordResponse {
        client_id: request.client_id,
        user_id: request.state.user_id,
        device_id: request.state.device_id,
        identity: request.state.identity,
        ciphersuite: DEFAULT_CIPHERSUITE_NAME,
        signature_key_length: 0, 
    })
}

#[wasm_bindgen]
pub fn export_group_state(request_json: String) -> Result<String, JsValue> {
    let request: ExportGroupStateRequest = parse_json(&request_json)?;
    
    lookup_client(&request.client_id, |client| {
        GROUPS.with(|groups| {
            let groups = groups.borrow();
            let stored_group = groups.get(&group_state_key(&request.client_id, &request.group_id)).ok_or_else(|| {
                JsValue::from_str(&format!(
                    "unknown MLS group {} for client {}",
                    request.group_id, request.client_id
                ))
            })?;

            let storage = client.provider.storage();
            let mut base64_data = BTreeMap::new();
            let values = storage.values.read().unwrap();
            for (k, v) in values.iter() {
                base64_data.insert(BASE64.encode(k), BASE64.encode(v));
            }

            to_json_string(&ExportedGroupState {
                group_id: request.group_id.clone(),
                group_data: base64_data,
                member_identities: stored_group.member_identities.clone(),
            })
        })
    })
}

#[wasm_bindgen]
pub fn import_group_state(request_json: String) -> Result<String, JsValue> {
    let request: ImportGroupStateRequest = parse_json(&request_json)?;
    
    lookup_client(&request.client_id, |client| {
        let storage = client.provider.storage();
        {
            let mut values = storage.values.write().unwrap();
            for (k_b64, v_b64) in &request.state.group_data {
                let k = decode_base64(k_b64)?;
                let v = decode_base64(v_b64)?;
                values.insert(k, v);
            }
        }

        let group_id = GroupId::from_slice(request.state.group_id.as_bytes());
        let group = MlsGroup::load(storage, &group_id)
            .map_err(|e| JsValue::from_str(&format!("failed to load group: {:?}", e)))?
            .ok_or_else(|| JsValue::from_str("group not found in storage after import"))?;

        let group_id_str = request.state.group_id.clone();
        let member_identities = request.state.member_identities.clone();
        
        let response = build_group_record(
            &request.client_id,
            group_id_str.clone(),
            group_epoch_to_u64(group.epoch()),
            member_identities.clone(),
        );

        GROUPS.with(|groups| {
            groups.borrow_mut().insert(
                group_state_key(&request.client_id, &group_id_str),
                StoredGroupState {
                    group,
                    member_identities,
                },
            );
        });

        to_json_string(&response)
    })
}

fn normalized_group_id(requested_group_id: Option<String>) -> String {
    requested_group_id.unwrap_or_else(|| {
        format!(
            "group-{}-{}",
            js_sys::Date::now() as u64,
            (js_sys::Math::random() * 1_000_000.0) as u64
        )
    })
}
