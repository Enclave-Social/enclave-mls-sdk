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

export {
  getOpenMlsClient,
  OpenMlsClient,
} from "./client";
export {
  isMlsChannelMessageRow,
  prepareChannelForMls,
  resolveChannelMessageData,
  sendChannelMessageWithMls,
  updateChannelMessageWithMls,
} from "./channelRuntime";
export {
  ensureLocalMlsClient,
  ensurePublishedDmKeyPackage,
  isMlsDirectMessageRow,
  resolveDirectMessagePlaintext,
  sendDirectMessageWithMls,
  updateDirectMessageWithMls,
} from "./dmRuntime";
export {
  callOpenMlsJsonMethod,
  createOpenMlsBasicIdentity,
  getOpenMlsBuildInfo,
  isOpenMlsWebRuntime,
  loadOpenMlsWasm,
} from "./openmls";
export type {
  AddOpenMlsMembersInput,
  CreateApplicationMessageInput,
  CreateOpenMlsGroupInput,
  CreateOpenMlsIdentityInput,
  CreateOpenMlsKeyPackageInput,
  ExportGroupSecretInput,
  ExportGroupSecretRecord,
  JoinFromWelcomeInput,
  OpenMlsApplicationMessage,
  OpenMlsBasicIdentity,
  OpenMlsBuildInfo,
  OpenMlsGroupRecord,
  OpenMlsIdentityRecord,
  OpenMlsKeyPackageRecord,
  OpenMlsProcessedIncomingMessage,
  OpenMlsWelcomeRecord,
  OpenMlsWasmOperation,
  ProcessIncomingMessageInput,
} from "./types";
