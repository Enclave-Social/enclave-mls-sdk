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

import * as Crypto from "expo-crypto";

import {
  callOpenMlsJsonMethod,
  createOpenMlsIdentityRecord,
  getOpenMlsBuildInfo,
  isOpenMlsWebRuntime,
} from "./openmls";
import type {
  AddOpenMlsMembersInput,
  CreateApplicationMessageInput,
  CreateOpenMlsGroupInput,
  CreateOpenMlsIdentityInput,
  CreateOpenMlsKeyPackageInput,
  ExportedClientState,
  ExportedGroupState,
  ExportGroupSecretInput,
  ExportGroupSecretRecord,
  JoinFromWelcomeInput,
  OpenMlsApplicationMessage,
  OpenMlsGroupRecord,
  OpenMlsIdentityRecord,
  OpenMlsKeyPackageRecord,
  OpenMlsProcessedIncomingMessage,
  OpenMlsWelcomeRecord,
  ProcessIncomingMessageInput,
} from "./types";

function defaultIdentity(input: CreateOpenMlsIdentityInput) {
  return input.identityOverride ?? `${input.userId}:${input.deviceId}`;
}

function assertWebRuntime() {
  if (!isOpenMlsWebRuntime()) {
    throw new Error(
      "OpenMLS is currently scaffolded through WASM for web only. A native Expo bridge is still needed for iOS/Android.",
    );
  }
}

function generateUUID() {
  try {
    return Crypto.randomUUID();
  } catch {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

export class OpenMlsClient {
  async getBuildInfo() {
    assertWebRuntime();
    return getOpenMlsBuildInfo();
  }

  async createIdentity(
    input: CreateOpenMlsIdentityInput,
  ): Promise<OpenMlsIdentityRecord> {
    assertWebRuntime();
    const identity = defaultIdentity(input);
    const clientId = input.clientId ?? generateUUID();

    return createOpenMlsIdentityRecord({
      clientId,
      userId: input.userId,
      deviceId: input.deviceId,
      identity,
      ciphersuite: "",
      signatureKeyLength: 0,
    });
  }

  async createKeyPackage(
    input: CreateOpenMlsKeyPackageInput,
  ): Promise<OpenMlsKeyPackageRecord> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      CreateOpenMlsKeyPackageInput,
      OpenMlsKeyPackageRecord
    >("create_key_package", input);
  }

  async createGroup(
    input: CreateOpenMlsGroupInput,
  ): Promise<{
    group: OpenMlsGroupRecord;
    welcome?: OpenMlsWelcomeRecord | null;
  }> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      CreateOpenMlsGroupInput,
      {
        group: OpenMlsGroupRecord;
        welcome?: OpenMlsWelcomeRecord | null;
      }
    >("create_group", input);
  }

  async addMembers(
    input: AddOpenMlsMembersInput,
  ): Promise<{
    group: OpenMlsGroupRecord;
    welcome: OpenMlsWelcomeRecord;
    commitMessage: string;
  }> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      AddOpenMlsMembersInput,
      {
        group: OpenMlsGroupRecord;
        welcome: OpenMlsWelcomeRecord;
        commitMessage: string;
      }
    >("add_members", input);
  }

  async joinFromWelcome(
    input: JoinFromWelcomeInput,
  ): Promise<OpenMlsGroupRecord> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<JoinFromWelcomeInput, OpenMlsGroupRecord>(
      "join_from_welcome",
      input,
    );
  }

  async createApplicationMessage(
    input: CreateApplicationMessageInput,
  ): Promise<OpenMlsApplicationMessage> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      CreateApplicationMessageInput,
      OpenMlsApplicationMessage
    >("create_application_message", input);
  }

  async processIncomingMessage(
    input: ProcessIncomingMessageInput,
  ): Promise<OpenMlsProcessedIncomingMessage> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      ProcessIncomingMessageInput,
      OpenMlsProcessedIncomingMessage
    >("process_incoming_message", input);
  }

  async exportClientState(input: {
    clientId: string;
  }): Promise<ExportedClientState> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<{ clientId: string }, ExportedClientState>(
      "export_client_state",
      input,
    );
  }

  async importClientState(input: {
    clientId: string;
    state: ExportedClientState;
  }): Promise<OpenMlsIdentityRecord> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      { clientId: string; state: ExportedClientState },
      OpenMlsIdentityRecord
    >("import_client_state", input);
  }

  async exportGroupState(input: {
    clientId: string;
    groupId: string;
  }): Promise<ExportedGroupState> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      { clientId: string; groupId: string },
      ExportedGroupState
    >("export_group_state", input);
  }

  async importGroupState(input: {
    clientId: string;
    state: ExportedGroupState;
  }): Promise<OpenMlsGroupRecord> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<
      { clientId: string; state: ExportedGroupState },
      OpenMlsGroupRecord
    >("import_group_state", input);
  }

  async exportGroupSecret(
    input: ExportGroupSecretInput,
  ): Promise<ExportGroupSecretRecord> {
    assertWebRuntime();
    return callOpenMlsJsonMethod<ExportGroupSecretInput, ExportGroupSecretRecord>(
      "export_group_secret",
      input,
    );
  }
}

let cachedClient: OpenMlsClient | null = null;

export function getOpenMlsClient() {
  if (!cachedClient) {
    cachedClient = new OpenMlsClient();
  }

  return cachedClient;
}
