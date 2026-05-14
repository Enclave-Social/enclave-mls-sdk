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

import { supabase } from "../supabase";
import { LocalPacketStore, buildChannelConversationId } from "../crypto";
import { getOpenMlsClient } from "./client";
import { ensureLocalMlsClient } from "./dmRuntime";
import { LocalGroupStore } from "./groupStore";
import type { ExportedClientState, ExportedGroupState } from "./types";

type LocalMlsClientState = Awaited<ReturnType<typeof ensureLocalMlsClient>>;

type ChannelGroupRow = {
  id: number;
  group_identifier: string;
  current_epoch: number;
  server_id: number | null;
  channel_id: number | null;
};

type ChannelSnapshotRow = {
  id: number;
  mls_group_id: number;
  channel_id: number;
  server_id: number;
  group_identifier: string;
  current_epoch: number;
  state_version: number;
  client_state: ExportedClientState;
  group_state: ExportedGroupState;
  snapshot_payload: ChannelSnapshotPayload | null;
};

type ChannelMessageRow = {
  id: string | number;
  channel_id: string | number;
  sender_id?: string | null;
  sender_device_id?: number | null;
  mls_group_id?: number | null;
  mls_epoch?: number | null;
  mls_message?: unknown;
  msg_packet?: unknown;
};

type EnsureChannelGroupResult = {
  dbGroupId: number;
  groupId: string;
  channelKeyBase64: string;
};

type PreparedManagedChannelState = EnsureChannelGroupResult & {
  runtimeClientId: string;
  senderDevicePk: number;
};

type ResolvedChannelMessage = {
  plaintext: string | null;
  senderUserId: string | null;
  senderDeviceId: number | null;
};

type ChannelSnapshotPayload = {
  client_state?: ExportedClientState;
  group_state?: ExportedGroupState;
  channel_key_base64?: string | null;
};

const activeChannelBridgeGroups = new Set<string>();
const channelGroupStores = new Map<string, LocalGroupStore>();
const loadedChannelSnapshotVersions = new Map<string, number>();
const activeChannelRuntimeClientIds = new Map<string, string>();
const CHANNEL_SHARED_DEVICE_ID = "shared-channel-state";

function getWebCrypto() {
  const maybeGlobalCrypto =
    (typeof globalThis !== "undefined" &&
      "crypto" in globalThis &&
      (globalThis.crypto as Crypto | undefined)) ||
    (typeof window !== "undefined"
      ? (window.crypto as Crypto | undefined)
      : undefined) ||
    (typeof self !== "undefined" ? (self.crypto as Crypto | undefined) : undefined);

  if (maybeGlobalCrypto?.subtle) {
    return maybeGlobalCrypto;
  }

  const maybeWebcrypto = (maybeGlobalCrypto as Crypto & { webcrypto?: Crypto })
    ?.webcrypto;

  if (maybeWebcrypto?.subtle) {
    return maybeWebcrypto;
  }

  throw new Error(
    "WebCrypto SubtleCrypto is unavailable on this client. Channel encryption requires a secure browser context with crypto.subtle support.",
  );
}

function parseJsonField<T>(value: unknown): T | null {
  if (!value) return null;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      return null;
    }
  }
  if (typeof value === "object") {
    return value as T;
  }
  return null;
}

function runtimeGroupKey(clientId: string, groupId: string) {
  return `${clientId}:${groupId}`;
}

function channelSnapshotIdentity(channelId: string | number) {
  return `channel:${channelId}`;
}

function channelSnapshotClientId(userId: string, channelId: string | number) {
  return `channel-snapshot:${userId}:${channelId}`;
}

function channelRuntimeIdentityKey(userId: string, channelId: string | number) {
  return `${userId}:${channelId}`;
}

function createChannelRuntimeClientId(userId: string, channelId: string | number) {
  return `${channelSnapshotClientId(userId, channelId)}:${generateUUID()}`;
}

function getGroupStore(userId: string) {
  let store = channelGroupStores.get(userId);
  if (!store) {
    store = new LocalGroupStore(userId);
    channelGroupStores.set(userId, store);
  }
  return store;
}

function senderIdentityToUserId(identity: string | null | undefined) {
  if (!identity) return null;
  const separatorIndex = identity.indexOf(":");
  if (separatorIndex <= 0) return identity;
  return identity.slice(0, separatorIndex);
}

function generateUUID() {
  try {
    const webCrypto = getWebCrypto();
    if (typeof webCrypto.randomUUID === "function") {
      return webCrypto.randomUUID();
    }
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      const random = getWebCrypto().getRandomValues(new Uint8Array(1))[0] & 15;
      const v = c === "x" ? random : (random & 0x3) | 0x8;
      return v.toString(16);
    });
  } catch {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function (c) {
      const r = (Math.random() * 16) | 0;
      const v = c === "x" ? r : (r & 0x3) | 0x8;
      return v.toString(16);
    });
  }
}

function randomBytes(length: number) {
  const bytes = new Uint8Array(length);
  getWebCrypto().getRandomValues(bytes);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array) {
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value: string) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function importChannelPacketKey(channelKeyBase64: string) {
  return getWebCrypto().subtle.importKey(
    "raw",
    base64ToBytes(channelKeyBase64),
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

function ensureChannelPacketKey(snapshot: ChannelSnapshotRow | null) {
  return (
    snapshot?.snapshot_payload?.channel_key_base64 ?? bytesToBase64(randomBytes(32))
  );
}

async function encryptChannelPlaintext(input: {
  channelKeyBase64: string;
  plaintext: string;
}) {
  const iv = randomBytes(12);
  const key = await importChannelPacketKey(input.channelKeyBase64);
  const ciphertext = await getWebCrypto().subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    new TextEncoder().encode(input.plaintext),
  );
  return {
    ciphertextBase64: bytesToBase64(new Uint8Array(ciphertext)),
    ivBase64: bytesToBase64(iv),
  };
}

async function decryptChannelPlaintext(input: {
  channelKeyBase64: string;
  ciphertextBase64: string;
  ivBase64: string;
}) {
  const key = await importChannelPacketKey(input.channelKeyBase64);
  const plaintext = await getWebCrypto().subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(input.ivBase64) },
    key,
    base64ToBytes(input.ciphertextBase64),
  );
  return new TextDecoder().decode(plaintext);
}

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function buildEncryptedPacket(input: {
  senderUserId: string | null;
  senderDeviceId: number | null;
  plaintext: string | null;
  plaintextCiphertext?: string | null;
  plaintextIv?: string | null;
  mlsMessage: string | null;
  mlsGroupId: number | null;
  mlsEpoch: number | null;
}) {
  return {
    unencrypted: {
      msg_type: "standard",
    },
    encrypted: {
      from_user_id: input.senderUserId,
      from_device_id: input.senderDeviceId,
      thread: null,
      "replying to": null,
      msg_content: input.plaintext,
      msg_content_ciphertext: input.plaintextCiphertext ?? null,
      msg_content_iv: input.plaintextIv ?? null,
      mls_message: input.mlsMessage,
      mls_group_id: input.mlsGroupId,
      mls_epoch: input.mlsEpoch,
    },
  };
}

async function saveResolvedChannelPacket(input: {
  ownerUserId: string;
  remoteMessageId: string;
  channelId: string | number;
  senderUserId: string | null;
  senderDeviceId: number | null;
  plaintext: string | null;
  plaintextCiphertext?: string | null;
  plaintextIv?: string | null;
  mlsMessage: string | null;
  mlsGroupId: number | null;
  mlsEpoch: number | null;
}) {
  try {
    await new LocalPacketStore().saveReceivedPacket({
      ownerUserId: input.ownerUserId,
      sourceTable: "messages",
      conversationId: buildChannelConversationId(String(input.channelId)),
      remoteMessageId: input.remoteMessageId,
      packet: buildEncryptedPacket({
        senderUserId: input.senderUserId,
        senderDeviceId: input.senderDeviceId,
        plaintext: input.plaintext,
        plaintextCiphertext: input.plaintextCiphertext ?? null,
        plaintextIv: input.plaintextIv ?? null,
        mlsMessage: input.mlsMessage,
        mlsGroupId: input.mlsGroupId,
        mlsEpoch: input.mlsEpoch,
      }),
      receivedAt: Date.now(),
    });
  } catch (error) {
    console.warn("Failed to save resolved MLS channel packet", error);
  }
}

async function findExistingChannelGroup(channelId: string | number) {
  const response = await supabase
    .from("mls_groups")
    .select("id, group_identifier, current_epoch, server_id, channel_id")
    .eq("conversation_kind", "channel")
    .eq("channel_id", channelId)
    .maybeSingle();

  if (response.error) {
    throw response.error;
  }

  return response.data as ChannelGroupRow | null;
}

async function ensureChannelGroupMetadata(input: {
  channelId: string | number;
  serverId: string | number;
  creatorDeviceId: number;
}) {
  const existing = await findExistingChannelGroup(input.channelId);
  if (existing) {
    return existing;
  }

  const groupIdentifier = generateUUID();
  const inserted = await supabase
    .from("mls_groups")
    .upsert(
      {
        group_identifier: groupIdentifier,
        conversation_kind: "channel",
        server_id: input.serverId,
        channel_id: input.channelId,
        creator_device_id: input.creatorDeviceId,
        cipher_suite: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        current_epoch: 0,
        is_active: true,
      },
      { onConflict: "channel_id", ignoreDuplicates: true },
    )
    .select("id, group_identifier, current_epoch, server_id, channel_id")
    .maybeSingle();

  if (inserted.error) {
    throw inserted.error;
  }

  if (inserted.data) {
    return inserted.data as ChannelGroupRow;
  }

  const duplicate = await findExistingChannelGroup(input.channelId);
  if (!duplicate) {
    throw new Error("Failed to create or load MLS channel group metadata.");
  }

  return duplicate;
}

async function loadChannelSnapshot(channelId: string | number) {
  const response = await supabase
    .from("mls_channel_state_snapshots")
    .select(
      "id, mls_group_id, channel_id, server_id, group_identifier, current_epoch, state_version, client_state, group_state, snapshot_payload",
    )
    .eq("channel_id", channelId)
    .maybeSingle();

  if (response.error) {
    throw response.error;
  }

  if (!response.data) {
    return null;
  }

  return {
    ...response.data,
    client_state:
      parseJsonField<ExportedClientState>(response.data.client_state) ??
      (response.data.client_state as ExportedClientState),
    group_state:
      parseJsonField<ExportedGroupState>(response.data.group_state) ??
      (response.data.group_state as ExportedGroupState),
    snapshot_payload:
      parseJsonField<ChannelSnapshotPayload>(response.data.snapshot_payload) ??
      (response.data.snapshot_payload as ChannelSnapshotPayload | null),
  } satisfies ChannelSnapshotRow;
}

async function persistChannelSnapshot(input: {
  userId: string;
  serverId: string | number;
  channelId: string | number;
  groupRow: ChannelGroupRow;
  clientId: string;
  updatedByDeviceId?: number | null;
  channelKeyBase64?: string | null;
}) {
  const clientState = await getOpenMlsClient().exportClientState({
    clientId: input.clientId,
  });
  const groupState = await getOpenMlsClient().exportGroupState({
    clientId: input.clientId,
    groupId: input.groupRow.group_identifier,
  });

  const currentSnapshot = await loadChannelSnapshot(input.channelId);
  const stateVersion = (currentSnapshot?.state_version ?? 0) + 1;
  const channelKeyBase64 =
    input.channelKeyBase64 ?? ensureChannelPacketKey(currentSnapshot);

  const snapshotUpsert = await supabase.from("mls_channel_state_snapshots").upsert(
    {
      mls_group_id: input.groupRow.id,
      channel_id: input.channelId,
      server_id: input.serverId,
      group_identifier: input.groupRow.group_identifier,
      current_epoch: input.groupRow.current_epoch,
      state_version: stateVersion,
      client_state: clientState,
      group_state: groupState,
      snapshot_payload: {
        client_state: clientState,
        group_state: groupState,
        channel_key_base64: channelKeyBase64,
      },
      updated_by_user_id: input.userId,
      updated_by_device_id: input.updatedByDeviceId ?? null,
    },
    { onConflict: "channel_id" },
  );

  if (snapshotUpsert.error) {
    throw snapshotUpsert.error;
  }

  await getGroupStore(input.userId).saveGroupState(groupState);

  const epochFromState = Number(
    parseJsonField<{ epoch?: number }>(groupState.groupData)?.epoch ??
      input.groupRow.current_epoch,
  );
  const normalizedEpoch = Number.isFinite(epochFromState)
    ? epochFromState
    : input.groupRow.current_epoch;

  await supabase
    .from("mls_groups")
    .update({
      current_epoch: normalizedEpoch,
      updated_at: new Date().toISOString(),
    })
    .eq("id", input.groupRow.id);

  loadedChannelSnapshotVersions.set(
    runtimeGroupKey(input.clientId, input.groupRow.group_identifier),
    stateVersion,
  );
}

async function createFreshChannelSnapshot(input: {
  userId: string;
  serverId: string | number;
  channelId: string | number;
  localClient: LocalMlsClientState;
  groupRow: ChannelGroupRow;
}) {
  const clientId = createChannelRuntimeClientId(input.userId, input.channelId);
  const sharedIdentity = channelSnapshotIdentity(input.channelId);
  const channelKeyBase64 = ensureChannelPacketKey(null);

  await getOpenMlsClient().createIdentity({
    userId: sharedIdentity,
    deviceId: CHANNEL_SHARED_DEVICE_ID,
    clientId,
    identityOverride: sharedIdentity,
  });

  await getOpenMlsClient().createGroup({
    clientId,
    groupId: input.groupRow.group_identifier,
    memberKeyPackages: [],
  });

  await persistChannelSnapshot({
    userId: input.userId,
    serverId: input.serverId,
    channelId: input.channelId,
    groupRow: input.groupRow,
    clientId,
    updatedByDeviceId: input.localClient.devicePk,
    channelKeyBase64,
  });

  activeChannelBridgeGroups.add(runtimeGroupKey(clientId, input.groupRow.group_identifier));
  activeChannelRuntimeClientIds.set(
    channelRuntimeIdentityKey(input.userId, input.channelId),
    clientId,
  );

  return {
    dbGroupId: input.groupRow.id,
    groupId: input.groupRow.group_identifier,
    channelKeyBase64,
  } satisfies EnsureChannelGroupResult;
}

async function importChannelSnapshot(input: {
  userId: string;
  channelId: string | number;
  snapshot: ChannelSnapshotRow;
}) {
  const existingClientId = activeChannelRuntimeClientIds.get(
    channelRuntimeIdentityKey(input.userId, input.channelId),
  );
  if (existingClientId) {
    const groupKey = runtimeGroupKey(existingClientId, input.snapshot.group_identifier);
    const loadedVersion = loadedChannelSnapshotVersions.get(groupKey);

    if (
      activeChannelBridgeGroups.has(groupKey) &&
      loadedVersion === input.snapshot.state_version
    ) {
      return existingClientId;
    }
  }

  const clientId = createChannelRuntimeClientId(input.userId, input.channelId);

  await getOpenMlsClient().importClientState({
    clientId,
    state: input.snapshot.client_state,
  });
  await getOpenMlsClient().importGroupState({
    clientId,
    state: input.snapshot.group_state,
  });

  await getGroupStore(input.userId).saveGroupState(input.snapshot.group_state);
  const groupKey = runtimeGroupKey(clientId, input.snapshot.group_identifier);
  activeChannelBridgeGroups.add(groupKey);
  activeChannelRuntimeClientIds.set(
    channelRuntimeIdentityKey(input.userId, input.channelId),
    clientId,
  );
  loadedChannelSnapshotVersions.set(groupKey, input.snapshot.state_version);
  return clientId;
}

async function takeOverManagedChannelState(input: {
  userId: string;
  serverId: string | number;
  channelId: string | number;
  localClient: LocalMlsClientState;
  groupRow: ChannelGroupRow;
}) {
  console.warn("Taking over managed MLS channel state with a fresh snapshot", {
    channelId: input.channelId,
    serverId: input.serverId,
    userId: input.userId,
  });

  const result = await createFreshChannelSnapshot({
    userId: input.userId,
    serverId: input.serverId,
    channelId: input.channelId,
    localClient: input.localClient,
    groupRow: input.groupRow,
  });

  return {
    ...result,
    runtimeClientId:
      activeChannelRuntimeClientIds.get(
        channelRuntimeIdentityKey(input.userId, input.channelId),
      ) ?? createChannelRuntimeClientId(input.userId, input.channelId),
    senderDevicePk: input.localClient.devicePk,
  } satisfies PreparedManagedChannelState;
}

function getActiveRuntimeClientId(input: {
  userId: string;
  channelId: string | number;
  groupId: string;
}) {
  const clientId = activeChannelRuntimeClientIds.get(
    channelRuntimeIdentityKey(input.userId, input.channelId),
  );
  if (!clientId) {
    return null;
  }
  const groupKey = runtimeGroupKey(clientId, input.groupId);
  return activeChannelBridgeGroups.has(groupKey) ? clientId : null;
}

async function prepareManagedChannelState(input: {
  userId: string;
  serverId: string | number;
  channelId: string | number;
  forceTakeover?: boolean;
  createIfMissing?: boolean;
}) {
  const localClient = await ensureLocalMlsClient(input.userId);
  const groupRow = await ensureChannelGroupMetadata({
    channelId: input.channelId,
    serverId: input.serverId,
    creatorDeviceId: localClient.devicePk,
  });

  if (input.forceTakeover) {
    return takeOverManagedChannelState({
      userId: input.userId,
      serverId: input.serverId,
      channelId: input.channelId,
      localClient,
      groupRow,
    });
  }

  const snapshot = await loadChannelSnapshot(input.channelId);
  if (!snapshot) {
    if (!input.createIfMissing) {
      throw new Error("Managed MLS channel session has not been created yet.");
    }
    const result = await createFreshChannelSnapshot({
      userId: input.userId,
      serverId: input.serverId,
      channelId: input.channelId,
      localClient,
      groupRow,
    });

    return {
      ...result,
      runtimeClientId:
        activeChannelRuntimeClientIds.get(
          channelRuntimeIdentityKey(input.userId, input.channelId),
        ) ?? createChannelRuntimeClientId(input.userId, input.channelId),
      senderDevicePk: localClient.devicePk,
    } satisfies PreparedManagedChannelState;
  }

  try {
    const runtimeClientId = await importChannelSnapshot({
      userId: input.userId,
      channelId: input.channelId,
      snapshot,
    });

    return {
      dbGroupId: snapshot.mls_group_id,
      groupId: snapshot.group_identifier,
      runtimeClientId,
      senderDevicePk: localClient.devicePk,
      channelKeyBase64: ensureChannelPacketKey(snapshot),
    } satisfies PreparedManagedChannelState;
  } catch (error) {
    console.warn(
      "Failed to import managed MLS channel snapshot, taking over with a fresh snapshot",
      error,
    );

    return takeOverManagedChannelState({
      userId: input.userId,
      serverId: input.serverId,
      channelId: input.channelId,
      localClient,
      groupRow,
    });
  }
}

function extractChannelEnvelope(row: ChannelMessageRow) {
  const payload = parseJsonField<{ message?: string }>(row.mls_message);
  if (payload?.message) {
    return payload.message;
  }

  const packet = parseJsonField<any>(row.msg_packet);
  const packetMessage = packet?.encrypted?.mls_message;
  return typeof packetMessage === "string" ? packetMessage : null;
}

export function isMlsChannelMessageRow(row: {
  mls_message?: unknown;
  mls_group_id?: number | null;
  msg_packet?: unknown;
}) {
  return Boolean(row?.mls_group_id && extractChannelEnvelope(row as ChannelMessageRow));
}

export async function prepareChannelForMls(input: {
  userId: string;
  serverId: string | number;
  channelId: string | number;
}) {
  try {
    return await prepareManagedChannelState({
      ...input,
      createIfMissing: false,
    });
  } catch (error) {
    if (
      error instanceof Error &&
      error.message === "Managed MLS channel session has not been created yet."
    ) {
      return null;
    }
    throw error;
  }
}

export async function sendChannelMessageWithMls(input: {
  senderUserId: string;
  serverId: string | number;
  channelId: string | number;
  plaintext: string;
}) {
  let prepared = await prepareManagedChannelState({
    userId: input.senderUserId,
    serverId: input.serverId,
    channelId: input.channelId,
    createIfMissing: true,
  });

  let applicationMessage;
  try {
    applicationMessage = await getOpenMlsClient().createApplicationMessage({
      clientId: prepared.runtimeClientId,
      groupId: prepared.groupId,
      plaintext: input.plaintext,
    });
  } catch (error) {
    console.warn(
      "Failed to create managed MLS channel message from inherited snapshot, taking over session",
      error,
    );

    prepared = await prepareManagedChannelState({
      userId: input.senderUserId,
      serverId: input.serverId,
      channelId: input.channelId,
      forceTakeover: true,
      createIfMissing: true,
    });

    applicationMessage = await getOpenMlsClient().createApplicationMessage({
      clientId: prepared.runtimeClientId,
      groupId: prepared.groupId,
      plaintext: input.plaintext,
    });
  }

  const encryptedContent = await encryptChannelPlaintext({
    channelKeyBase64: prepared.channelKeyBase64,
    plaintext: input.plaintext,
  });

  const msgPacket = buildEncryptedPacket({
    senderUserId: input.senderUserId,
    senderDeviceId: prepared.senderDevicePk,
    plaintext: null,
    plaintextCiphertext: encryptedContent.ciphertextBase64,
    plaintextIv: encryptedContent.ivBase64,
    mlsMessage: applicationMessage.message,
    mlsGroupId: prepared.dbGroupId,
    mlsEpoch: applicationMessage.epoch,
  });

  await persistChannelSnapshot({
    userId: input.senderUserId,
    serverId: input.serverId,
    channelId: input.channelId,
    groupRow: {
      id: prepared.dbGroupId,
      group_identifier: prepared.groupId,
      current_epoch: applicationMessage.epoch,
      server_id: Number(input.serverId),
      channel_id: Number(input.channelId),
    },
    clientId: prepared.runtimeClientId,
    updatedByDeviceId: prepared.senderDevicePk,
    channelKeyBase64: prepared.channelKeyBase64,
  });

  const inserted = await supabase
    .from("messages")
    .insert({
      channel_id: input.channelId,
      sender_id: input.senderUserId,
      sender_device_id: prepared.senderDevicePk,
      ciphertext: "You should not be seeing this message client-side",
      msg_packet: msgPacket,
      mls_group_id: prepared.dbGroupId,
      mls_epoch: applicationMessage.epoch,
      mls_message_type: "application",
      mls_wire_format: "private_message",
      mls_content_type: "application",
      mls_authenticated_data: null,
      mls_message: {
        message: applicationMessage.message,
      },
    })
    .select("*")
    .single();

  if (inserted.error) {
    throw inserted.error;
  }

  await saveResolvedChannelPacket({
    ownerUserId: input.senderUserId,
    remoteMessageId: String(inserted.data.id),
    channelId: input.channelId,
    senderUserId: input.senderUserId,
    senderDeviceId: prepared.senderDevicePk,
    plaintext: input.plaintext,
    plaintextCiphertext: encryptedContent.ciphertextBase64,
    plaintextIv: encryptedContent.ivBase64,
    mlsMessage: applicationMessage.message,
    mlsGroupId: prepared.dbGroupId,
    mlsEpoch: applicationMessage.epoch,
  });

  return {
    row: {
      ...inserted.data,
      plaintext_resolved: input.plaintext,
      resolved_sender_user_id: input.senderUserId,
      resolved_sender_device_id: prepared.senderDevicePk,
    },
    plaintext: input.plaintext,
  };
}

export async function updateChannelMessageWithMls(input: {
  senderUserId: string;
  serverId: string | number;
  channelId: string | number;
  messageId: string | number;
  plaintext: string;
}) {
  let prepared = await prepareManagedChannelState({
    userId: input.senderUserId,
    serverId: input.serverId,
    channelId: input.channelId,
    createIfMissing: true,
  });

  let applicationMessage;
  try {
    applicationMessage = await getOpenMlsClient().createApplicationMessage({
      clientId: prepared.runtimeClientId,
      groupId: prepared.groupId,
      plaintext: input.plaintext,
    });
  } catch {
    prepared = await prepareManagedChannelState({
      userId: input.senderUserId,
      serverId: input.serverId,
      channelId: input.channelId,
      forceTakeover: true,
      createIfMissing: true,
    });

    applicationMessage = await getOpenMlsClient().createApplicationMessage({
      clientId: prepared.runtimeClientId,
      groupId: prepared.groupId,
      plaintext: input.plaintext,
    });
  }

  const encryptedContent = await encryptChannelPlaintext({
    channelKeyBase64: prepared.channelKeyBase64,
    plaintext: input.plaintext,
  });

  const msgPacket = buildEncryptedPacket({
    senderUserId: input.senderUserId,
    senderDeviceId: prepared.senderDevicePk,
    plaintext: null,
    plaintextCiphertext: encryptedContent.ciphertextBase64,
    plaintextIv: encryptedContent.ivBase64,
    mlsMessage: applicationMessage.message,
    mlsGroupId: prepared.dbGroupId,
    mlsEpoch: applicationMessage.epoch,
  });

  await persistChannelSnapshot({
    userId: input.senderUserId,
    serverId: input.serverId,
    channelId: input.channelId,
    groupRow: {
      id: prepared.dbGroupId,
      group_identifier: prepared.groupId,
      current_epoch: applicationMessage.epoch,
      server_id: Number(input.serverId),
      channel_id: Number(input.channelId),
    },
    clientId: prepared.runtimeClientId,
    updatedByDeviceId: prepared.senderDevicePk,
    channelKeyBase64: prepared.channelKeyBase64,
  });

  const updated = await supabase
    .from("messages")
    .update({
      channel_id: input.channelId,
      sender_id: input.senderUserId,
      sender_device_id: prepared.senderDevicePk,
      ciphertext: "You should not be seeing this message client-side",
      msg_packet: msgPacket,
      mls_group_id: prepared.dbGroupId,
      mls_epoch: applicationMessage.epoch,
      mls_message_type: "application",
      mls_wire_format: "private_message",
      mls_content_type: "application",
      mls_authenticated_data: null,
      mls_message: {
        message: applicationMessage.message,
      },
    })
    .eq("id", input.messageId)
    .eq("sender_id", input.senderUserId)
    .select("*")
    .single();

  if (updated.error) {
    throw updated.error;
  }

  await saveResolvedChannelPacket({
    ownerUserId: input.senderUserId,
    remoteMessageId: String(input.messageId),
    channelId: input.channelId,
    senderUserId: input.senderUserId,
    senderDeviceId: prepared.senderDevicePk,
    plaintext: input.plaintext,
    plaintextCiphertext: encryptedContent.ciphertextBase64,
    plaintextIv: encryptedContent.ivBase64,
    mlsMessage: applicationMessage.message,
    mlsGroupId: prepared.dbGroupId,
    mlsEpoch: applicationMessage.epoch,
  });

  return {
    row: {
      ...updated.data,
      plaintext_resolved: input.plaintext,
      resolved_sender_user_id: input.senderUserId,
      resolved_sender_device_id: prepared.senderDevicePk,
    },
    plaintext: input.plaintext,
  };
}

export async function resolveChannelMessageData(input: {
  ownerUserId: string;
  row: ChannelMessageRow;
}) {
  const fallbackResult = {
    plaintext: null,
    senderUserId: input.row.sender_id ?? null,
    senderDeviceId: Number(input.row.sender_device_id ?? 0) || null,
  } satisfies ResolvedChannelMessage;

  const snapshot = await loadChannelSnapshot(input.row.channel_id);
  const packet = parseJsonField<any>(input.row.msg_packet);
  const packetCiphertext =
    typeof packet?.encrypted?.msg_content_ciphertext === "string"
      ? packet.encrypted.msg_content_ciphertext
      : null;
  const packetIv =
    typeof packet?.encrypted?.msg_content_iv === "string"
      ? packet.encrypted.msg_content_iv
      : null;
  const senderDeviceId = Number(input.row.sender_device_id ?? 0) || null;
  const senderUserId = input.row.sender_id ?? null;

  if (snapshot?.snapshot_payload?.channel_key_base64 && packetCiphertext && packetIv) {
    try {
      const plaintext =
        (await decryptChannelPlaintext({
          channelKeyBase64: snapshot.snapshot_payload.channel_key_base64,
          ciphertextBase64: packetCiphertext,
          ivBase64: packetIv,
        })) ?? null;

      await saveResolvedChannelPacket({
        ownerUserId: input.ownerUserId,
        remoteMessageId: String(input.row.id),
        channelId: input.row.channel_id,
        senderUserId,
        senderDeviceId,
        plaintext,
        plaintextCiphertext: packetCiphertext,
        plaintextIv: packetIv,
        mlsMessage: extractChannelEnvelope(input.row),
        mlsGroupId: Number(input.row.mls_group_id ?? 0) || null,
        mlsEpoch: Number(input.row.mls_epoch ?? 0) || null,
      });

      return {
        plaintext,
        senderUserId,
        senderDeviceId,
      } satisfies ResolvedChannelMessage;
    } catch (error) {
      console.warn("Primary channel packet decrypt failed", error);
      await wait(150);

      const refreshedSnapshot = await loadChannelSnapshot(input.row.channel_id);
      if (
        refreshedSnapshot?.snapshot_payload?.channel_key_base64 &&
        packetCiphertext &&
        packetIv
      ) {
        try {
          const plaintext = await decryptChannelPlaintext({
            channelKeyBase64: refreshedSnapshot.snapshot_payload.channel_key_base64,
            ciphertextBase64: packetCiphertext,
            ivBase64: packetIv,
          });

          await saveResolvedChannelPacket({
            ownerUserId: input.ownerUserId,
            remoteMessageId: String(input.row.id),
            channelId: input.row.channel_id,
            senderUserId,
            senderDeviceId,
            plaintext,
            plaintextCiphertext: packetCiphertext,
            plaintextIv: packetIv,
            mlsMessage: extractChannelEnvelope(input.row),
            mlsGroupId: Number(input.row.mls_group_id ?? 0) || null,
            mlsEpoch: Number(input.row.mls_epoch ?? 0) || null,
          });

          return {
            plaintext,
            senderUserId,
            senderDeviceId,
          } satisfies ResolvedChannelMessage;
        } catch (retryError) {
          console.warn("Retried channel packet decrypt failed", retryError);
        }
      }
    }
  }

  if (!isMlsChannelMessageRow(input.row)) {
    return fallbackResult;
  }

  const message = extractChannelEnvelope(input.row);
  if (!message) {
    return fallbackResult;
  }

  const runtimeClientId = snapshot
    ? getActiveRuntimeClientId({
        userId: input.ownerUserId,
        channelId: input.row.channel_id,
        groupId: snapshot.group_identifier,
      }) ??
      (await importChannelSnapshot({
        userId: input.ownerUserId,
        channelId: input.row.channel_id,
        snapshot,
      }))
    : null;

  if (!snapshot || !runtimeClientId) {
    return fallbackResult;
  }

  try {
    const processed = await getOpenMlsClient().processIncomingMessage({
      clientId: runtimeClientId,
      groupId: snapshot.group_identifier,
      message,
    });

    await persistChannelSnapshot({
      userId: input.ownerUserId,
      serverId: snapshot.server_id,
      channelId: snapshot.channel_id,
      groupRow: {
        id: snapshot.mls_group_id,
        group_identifier: snapshot.group_identifier,
        current_epoch: processed.epoch,
        server_id: snapshot.server_id,
        channel_id: snapshot.channel_id,
      },
      clientId: runtimeClientId,
      updatedByDeviceId: senderDeviceId,
      channelKeyBase64: ensureChannelPacketKey(snapshot),
    });

    const processedSenderUserId =
      input.row.sender_id ?? senderIdentityToUserId(processed.senderIdentity) ?? null;

    await saveResolvedChannelPacket({
      ownerUserId: input.ownerUserId,
      remoteMessageId: String(input.row.id),
      channelId: input.row.channel_id,
      senderUserId: processedSenderUserId,
      senderDeviceId,
      plaintext: processed.plaintext ?? null,
      mlsMessage: message,
      mlsGroupId: Number(input.row.mls_group_id ?? 0) || null,
      mlsEpoch: Number(input.row.mls_epoch ?? processed.epoch ?? 0) || null,
    });

    return {
      plaintext: processed.plaintext ?? null,
      senderUserId: processedSenderUserId,
      senderDeviceId,
    } satisfies ResolvedChannelMessage;
  } catch (error) {
    console.warn("Failed to process managed MLS channel message", error);
    return {
      plaintext: null,
      senderUserId: input.row.sender_id ?? null,
      senderDeviceId: Number(input.row.sender_device_id ?? 0) || null,
    } satisfies ResolvedChannelMessage;
  }
}
