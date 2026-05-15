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

export type OpenMlsWasmOperation =
  | "openmls_build_info"
  | "create_basic_identity"
  | "create_key_package"
  | "create_group"
  | "add_members"
  | "join_from_welcome"
  | "create_application_message"
  | "process_incoming_message"
  | "export_client_state"
  | "import_client_state"
  | "export_group_state"
  | "import_group_state"
  | "export_group_secret";

export interface ExportedClientState {
  userId: string;
  deviceId: string;
  identity: string;
  signaturePublicKey: string;
  storageData: Record<string, string>;
}

export interface ExportedGroupState {
  groupId: string;
  groupData: string;
  memberIdentities: string[];
}

export interface OpenMlsBuildInfo {
  crate_name: string;
  crate_version: string;
  ciphersuite: string;
  runtime: string;
}

export interface OpenMlsBasicIdentity {
  identity: string;
  ciphersuite: string;
  signature_key_len: number;
}

export interface OpenMlsIdentityRecord {
  clientId: string;
  userId: string;
  deviceId: string;
  identity: string;
  ciphersuite: string;
  signatureKeyLength: number;
}

export interface OpenMlsKeyPackageRecord {
  clientId: string;
  keyPackageRef: string;
  ciphersuite: string;
  credentialIdentity: string;
  keyPackage: string;
  expiresAt?: string | null;
}

export interface OpenMlsGroupRecord {
  clientId: string;
  groupId: string;
  epoch: number;
  ciphersuite: string;
  memberIdentities: string[];
}

export interface OpenMlsWelcomeRecord {
  groupId: string;
  welcome: string;
  inviterIdentity?: string | null;
  ratchetTree?: string | null;
}

export interface OpenMlsApplicationMessage {
  groupId: string;
  epoch: number;
  message: string;
  authenticatedData?: string | null;
}

export interface OpenMlsProcessedIncomingMessage {
  groupId: string;
  epoch: number;
  senderIdentity?: string | null;
  contentType: "application" | "proposal" | "commit" | "welcome" | "unknown";
  plaintext?: string | null;
  commit?: string | null;
  welcome?: string | null;
}

export interface CreateOpenMlsIdentityInput {
  userId: string;
  deviceId: string;
  clientId?: string;
  identityOverride?: string;
}

export interface CreateOpenMlsKeyPackageInput {
  clientId: string;
  lifetimeSeconds?: number;
}

export interface CreateOpenMlsGroupInput {
  clientId: string;
  groupId?: string;
  memberKeyPackages?: string[];
  metadata?: Record<string, unknown>;
}

export interface AddOpenMlsMembersInput {
  clientId: string;
  groupId: string;
  memberKeyPackages: string[];
}

export interface JoinFromWelcomeInput {
  clientId: string;
  welcome: string;
  ratchetTree?: string | null;
}

export interface CreateApplicationMessageInput {
  clientId: string;
  groupId: string;
  plaintext: string;
  authenticatedData?: string | null;
}

export interface ProcessIncomingMessageInput {
  clientId: string;
  groupId: string;
  message: string;
}

export interface ExportGroupSecretInput {
  clientId: string;
  groupId: string;
  label: string;
  context: string;
  length: number;
}

export interface ExportGroupSecretRecord {
  groupId: string;
  epoch: number;
  secret: string;
}
