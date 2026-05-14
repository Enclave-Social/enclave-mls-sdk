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
  buildDirectConversationId,
  LocalMessageStore,
  SecureVault,
} from "../crypto";
import { devicePlatformLabel } from "../os";
import { supabase } from "../supabase";
import { getOpenMlsClient } from "./client";
import { LocalGroupStore } from "./groupStore";
import type {
  OpenMlsWelcomeRecord,
  ExportedClientState,
} from "./types";

type LocalMlsClientRecord = {
  clientId: string;
  deviceId: string;
  identity: string;
  state?: ExportedClientState;
};

type LocalMlsClientState = LocalMlsClientRecord & {
  userId: string;
  devicePk: number;
  wasRestored: boolean;
};

type DirectMessageRow = {
  id: string | number;
  sender_id: string;
  recipient_id: string;
  sender_device_id?: number | null;
  recipient_device_id?: number | null;
  mls_group_id?: number | null;
  mls_message?: unknown;
};

type DmGroupRow = {
  id: number;
  group_identifier: string;
  current_epoch: number;
  created_at?: string;
  is_active?: boolean;
};

type RemoteDeviceState = {
  devicePk: number;
  keyPackage: string;
  credentialIdentity: string;
};

type EnsureDmGroupResult = {
  dbGroupId: number;
  groupId: string;
  remoteDevicePk: number;
};

const DEVICE_ID_KEY = "device_id";
const CLIENT_ID_KEY = "client_id";
const IDENTITY_KEY = "identity";
const CLIENT_STATE_KEY = "client_state";

const activeBridgeGroups = new Set<string>();
const localClientPromises = new Map<string, Promise<LocalMlsClientState>>();
const messageStores = new Map<string, LocalMessageStore>();
const groupStores = new Map<string, LocalGroupStore>();

function getStores(userId: string) {
  let messageStore = messageStores.get(userId);
  if (!messageStore) {
    messageStore = new LocalMessageStore(userId);
    messageStores.set(userId, messageStore);
  }

  let groupStore = groupStores.get(userId);
  if (!groupStore) {
    groupStore = new LocalGroupStore(userId);
    groupStores.set(userId, groupStore);
  }

  return { messageStore, groupStore };
}

function runtimeGroupKey(clientId: string, groupId: string) {
  return `${clientId}:${groupId}`;
}

function dmConversationId(input: {
  localUserId: string;
  localDevicePk: number;
  remoteUserId: string;
  remoteDevicePk: number;
}) {
  return buildDirectConversationId({
    localUserId: input.localUserId,
    localDeviceId: input.localDevicePk,
    remoteUserId: input.remoteUserId,
    remoteDeviceId: input.remoteDevicePk,
  });
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

function normalizeWelcomeRecord(value: unknown): OpenMlsWelcomeRecord | null {
  const parsed = parseJsonField<Record<string, unknown>>(value);
  if (!parsed) return null;

  const welcome =
    typeof parsed.welcome === "string"
      ? parsed.welcome
      : typeof parsed.welcome_message === "string"
        ? parsed.welcome_message
        : null;

  if (!welcome) {
    return null;
  }

  const ratchetTree =
    typeof parsed.ratchetTree === "string"
      ? parsed.ratchetTree
      : typeof parsed.ratchet_tree === "string"
        ? parsed.ratchet_tree
        : typeof parsed.ratchetTreeBase64 === "string"
          ? parsed.ratchetTreeBase64
          : typeof parsed.ratchet_tree_base64 === "string"
            ? parsed.ratchet_tree_base64
            : null;

  const groupId =
    typeof parsed.groupId === "string"
      ? parsed.groupId
      : typeof parsed.group_id === "string"
        ? parsed.group_id
        : "";

  const inviterIdentity =
    typeof parsed.inviterIdentity === "string"
      ? parsed.inviterIdentity
      : typeof parsed.inviter_identity === "string"
        ? parsed.inviter_identity
        : null;

  return {
    groupId,
    welcome,
    inviterIdentity,
    ratchetTree,
  };
}

function orderedDmUsers(left: string, right: string) {
  return [left, right].sort((a, b) => a.localeCompare(b));
}

function generateUUID() {
  try {
    return Crypto.randomUUID();
  } catch {
    // Fallback for non-secure contexts or older browsers
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}

async function loadStoredClientRecord(userId: string) {
  const vault = new SecureVault(`dm_mls_client_${userId}`);
  const [deviceId, clientId, identity, stateJson] = await Promise.all([
    vault.getString(DEVICE_ID_KEY),
    vault.getString(CLIENT_ID_KEY),
    vault.getString(IDENTITY_KEY),
    vault.getString(CLIENT_STATE_KEY),
  ]);

  let state: ExportedClientState | undefined;
  if (stateJson) {
    try {
      const parsed = JSON.parse(stateJson);
      if (parsed && typeof parsed === "object") {
        state = parsed as ExportedClientState;
      }
    } catch (error) {
      console.warn("[MLS] Failed to parse stored client state, will recreate client", error);
    }
  }

  if (deviceId && clientId && identity) {
    return {
      vault,
      record: {
        deviceId,
        clientId,
        identity,
        state,
      } satisfies LocalMlsClientRecord,
    };
  }

  const nextRecord: LocalMlsClientRecord = {
    deviceId: `${devicePlatformLabel}-${generateUUID()}`,
    clientId: generateUUID(),
    identity: "",
  };
  nextRecord.identity = `${userId}:${nextRecord.deviceId}`;

  await Promise.all([
    vault.setString(DEVICE_ID_KEY, nextRecord.deviceId),
    vault.setString(CLIENT_ID_KEY, nextRecord.clientId),
    vault.setString(IDENTITY_KEY, nextRecord.identity),
  ]);

  return { vault, record: nextRecord };
}

export async function saveClientState(userId: string, clientId: string) {
  const vault = new SecureVault(`dm_mls_client_${userId}`);
  const exported = await getOpenMlsClient().exportClientState({ clientId });
  await vault.setString(CLIENT_STATE_KEY, JSON.stringify(exported));
  return exported;
}

async function ensureUserDeviceRow(userId: string, deviceId: string) {
  const existing = await supabase
    .from("user_devices")
    .select("id")
    .eq("user_id", userId)
    .eq("device_id", deviceId)
    .maybeSingle();

  if (existing.error) {
    throw existing.error;
  }

  if (existing.data?.id) {
    await supabase
      .from("user_devices")
      .update({
        last_seen_at: new Date().toISOString(),
        is_active: true,
      })
      .eq("id", existing.data.id);

    return Number(existing.data.id);
  }

  const inserted = await supabase
    .from("user_devices")
    .insert({
      user_id: userId,
      device_id: deviceId,
      label: `${devicePlatformLabel} device`,
      last_seen_at: new Date().toISOString(),
      is_active: true,
    })
    .select("id")
    .single();

  if (inserted.error) {
    throw inserted.error;
  }

  return Number(inserted.data.id);
}

export async function ensureLocalMlsClient(userId: string) {
  const existing = localClientPromises.get(userId);
  if (existing) {
    return existing;
  }

  const promise = (async () => {
    const { record, vault } = await loadStoredClientRecord(userId);
    const devicePk = await ensureUserDeviceRow(userId, record.deviceId);
    const client = getOpenMlsClient();

    let finalRecord = record;
    let wasRestored = false;

    if (record.state) {
      try {
        console.log("[MLS] Importing full client state for", userId);
        await client.importClientState({
          clientId: record.clientId,
          state: record.state,
        });
        wasRestored = true;
      } catch (error) {
        console.warn(
          "[MLS] Stored client state could not be imported, recreating local identity",
          error,
        );
        await vault.delete(CLIENT_STATE_KEY);
      }
    }

    if (!wasRestored) {
      console.log("[MLS] Creating fresh identity for", userId);
      await client.createIdentity({
        userId,
        deviceId: record.deviceId,
        clientId: record.clientId,
        identityOverride: record.identity,
      });

      const exported = await saveClientState(userId, record.clientId);
      finalRecord = { ...record, state: exported };
    }

    return {
      ...finalRecord,
      userId,
      devicePk,
      wasRestored,
    } satisfies LocalMlsClientState;
  })();

  localClientPromises.set(userId, promise);
  return promise;
}

export async function ensurePublishedDmKeyPackage(userId: string) {
  const localClient = await ensureLocalMlsClient(userId);

  // If this is a fresh session, we MUST invalidate any key packages 
  // previously published for this devicePk, as we no longer have the 
  // private keys required to use them.
  if (!localClient.wasRestored) {
    console.log("[MLS] Fresh session: invalidating stale key packages for device", localClient.devicePk);
    await supabase
      .from("mls_key_packages")
      .update({ is_consumed: true })
      .eq("user_device_id", localClient.devicePk)
      .eq("is_consumed", false);
  }

  const existing = await supabase
    .from("mls_key_packages")
    .select("id")
    .eq("user_device_id", localClient.devicePk)
    .eq("is_consumed", false)
    .limit(1);

  if (existing.error) {
    throw existing.error;
  }

  if ((existing.data?.length ?? 0) > 0) {
    return localClient;
  }

  console.log("[MLS] Publishing fresh key package for", userId);
  const keyPackage = await getOpenMlsClient().createKeyPackage({
    clientId: localClient.clientId,
  });

  // Key package generation updates the storage (new HPKE keys)
  await saveClientState(userId, localClient.clientId);

  const inserted = await supabase.from("mls_key_packages").insert({
    user_device_id: localClient.devicePk,
    cipher_suite: keyPackage.ciphersuite,
    credential_identity: keyPackage.credentialIdentity,
    key_package: keyPackage.keyPackage,
  });

  if (inserted.error) {
    throw inserted.error;
  }

  return localClient;
}

/**
 * Fetches ALL active devices for a user and their latest key packages.
 */
async function loadAllActiveUserDevices(userId: string) {
  const { data: devices, error } = await supabase
    .from("user_devices")
    .select("id")
    .eq("user_id", userId)
    .eq("is_active", true);

  if (error) throw error;
  if (!devices || devices.length === 0) return [];

  const deviceIds = devices.map(d => d.id);
  
  const { data: packages, error: pkError } = await supabase
    .from("mls_key_packages")
    .select("user_device_id, key_package, credential_identity")
    .in("user_device_id", deviceIds)
    .eq("is_consumed", false)
    .order("created_at", { ascending: false });

  if (pkError) throw pkError;
  if (!packages) return [];

  // Return the latest package for each device
  const seen = new Set();
  return packages.filter(p => {
    if (seen.has(p.user_device_id)) return false;
    seen.add(p.user_device_id);
    return true;
  }).map(p => ({
    devicePk: Number(p.user_device_id),
    keyPackage: p.key_package,
    credentialIdentity: p.credential_identity,
  } satisfies RemoteDeviceState));
}

async function findExistingDmGroup(currentUserId: string, remoteUserId: string) {
  const [firstUser, secondUser] = orderedDmUsers(currentUserId, remoteUserId);
  const response = await supabase
    .from("mls_groups")
    .select("id, group_identifier, current_epoch, created_at, is_active")
    .eq("conversation_kind", "dm")
    .eq("dm_user_a", firstUser)
    .eq("dm_user_b", secondUser)
    .eq("is_active", true)
    .order("created_at", { ascending: false })
    .limit(1);

  if (response.error) {
    throw response.error;
  }

  return ((response.data ?? [])[0] as DmGroupRow | undefined) ?? null;
}

async function findLatestWelcome(groupDbId: number) {
  const response = await supabase
    .from("mls_commits")
    .select("welcome_message")
    .eq("mls_group_id", groupDbId)
    .not("welcome_message", "is", null)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  if (response.error) {
    throw response.error;
  }

  return normalizeWelcomeRecord(response.data?.welcome_message ?? null);
}

async function ensureJoinedDmGroup(
  localClient: LocalMlsClientState,
  groupRow: DmGroupRow,
) {
  const groupKey = runtimeGroupKey(
    localClient.clientId,
    groupRow.group_identifier,
  );
  if (activeBridgeGroups.has(groupKey)) {
    return;
  }

  // 1. Try to load and import stored group state
  const { groupStore } = getStores(localClient.userId);
  const storedState = await groupStore.getGroupState(groupRow.group_identifier);

  if (storedState) {
    try {
      console.log("[MLS] Importing group state for", groupRow.group_identifier);
      await getOpenMlsClient().importGroupState({
        clientId: localClient.clientId,
        state: storedState,
      });
      activeBridgeGroups.add(groupKey);
      return;
    } catch (error) {
      console.warn(
        "[MLS] Stored DM group state import failed, falling back to welcome rejoin",
        groupRow.group_identifier,
        error,
      );
      await groupStore.deleteGroupState(groupRow.group_identifier);
    }
  }

  // 2. Fallback: Re-join from welcome
  console.log("[MLS] Group state missing, re-joining from welcome for", groupRow.group_identifier);
  const welcomeRecord = await findLatestWelcome(groupRow.id);
  if (!welcomeRecord?.welcome) {
    throw new Error(
      "This MLS DM exists remotely, but the local bridge cannot rejoin it from the current stored data yet.",
    );
  }

  await getOpenMlsClient().joinFromWelcome({
    clientId: localClient.clientId,
    welcome: welcomeRecord.welcome,
    ratchetTree: welcomeRecord.ratchetTree,
  }).catch(e => {
    console.error("[MLS] joinFromWelcome failed for", groupRow.group_identifier, e);
    throw new Error(`Failed to join group from welcome: ${e instanceof Error ? e.message : e}`);
  });

  // Joining a group updates both the group state and the client storage
  const exportedGroup = await getOpenMlsClient().exportGroupState({
    clientId: localClient.clientId,
    groupId: groupRow.group_identifier,
  });
  await groupStore.saveGroupState(exportedGroup);
  await saveClientState(localClient.userId, localClient.clientId);

  activeBridgeGroups.add(groupKey);
}

function shouldRecreateDmGroupFromError(error: unknown) {
  const message =
    error instanceof Error ? error.message : String(error ?? "");
  return (
    message.includes("NoMatchingKeyPackage") ||
    message.includes("staging welcome failed")
  );
}

async function retireDmGroup(localClient: LocalMlsClientState, groupRow: DmGroupRow) {
  activeBridgeGroups.delete(
    runtimeGroupKey(localClient.clientId, groupRow.group_identifier),
  );
  const { groupStore } = getStores(localClient.userId);
  await groupStore.deleteGroupState(groupRow.group_identifier);

  const retired = await supabase
    .from("mls_groups")
    .update({
      is_active: false,
      updated_at: new Date().toISOString(),
    })
    .eq("id", groupRow.id);

  if (retired.error) {
    throw retired.error;
  }
}

async function createNewDmGroup(
  localClient: LocalMlsClientState,
  remoteUserId: string,
) {
  console.log("[MLS] Creating new multi-device DM group with", remoteUserId);
  
  // Fetch ALL active devices for the other user AND our other devices
  const remoteDevices = await loadAllActiveUserDevices(remoteUserId);
  const myOtherDevices = (await loadAllActiveUserDevices(localClient.userId))
    .filter(d => d.devicePk !== localClient.devicePk);

  const allRemoteKeyPackages = [...remoteDevices, ...myOtherDevices].map(d => d.keyPackage);

  if (allRemoteKeyPackages.length === 0) {
    throw new Error("No active MLS devices found for the recipient.");
  }

  const groupId = generateUUID();
  const created = await getOpenMlsClient().createGroup({
    clientId: localClient.clientId,
    groupId,
    memberKeyPackages: allRemoteKeyPackages,
  }).catch(e => {
    console.error("[MLS] WASM createGroup failed:", e);
    throw e;
  });

  const [firstUser, secondUser] = orderedDmUsers(localClient.userId, remoteUserId);
  const insertedGroup = await supabase
    .from("mls_groups")
    .insert({
      group_identifier: groupId,
      conversation_kind: "dm",
      dm_user_a: firstUser,
      dm_user_b: secondUser,
      creator_device_id: localClient.devicePk,
      cipher_suite: created.group.ciphersuite,
      current_epoch: created.group.epoch,
      is_active: true,
    })
    .select("id, group_identifier, current_epoch")
    .single();

  if (insertedGroup.error) {
    throw insertedGroup.error;
  }

  // Add ALL devices to the membership table
  const membersToInsert = [
    {
      mls_group_id: insertedGroup.data.id,
      user_id: localClient.userId,
      user_device_id: localClient.devicePk,
      leaf_index: 0,
      credential_identity: localClient.identity,
      joined_at_epoch: created.group.epoch,
      membership_status: "active",
      added_by_device_id: localClient.devicePk,
    },
    ...[...remoteDevices, ...myOtherDevices].map((d, idx) => ({
      mls_group_id: insertedGroup.data.id,
      user_id: allRemoteKeyPackages.indexOf(d.keyPackage) < remoteDevices.length ? remoteUserId : localClient.userId,
      user_device_id: d.devicePk,
      leaf_index: idx + 1,
      credential_identity: d.credentialIdentity,
      joined_at_epoch: created.group.epoch,
      membership_status: "active",
      added_by_device_id: localClient.devicePk,
    }))
  ];

  const insertedMembers = await supabase.from("mls_group_members").insert(membersToInsert);

  if (insertedMembers.error) {
    throw insertedMembers.error;
  }

  const insertedCommit = await supabase.from("mls_commits").insert({
    mls_group_id: insertedGroup.data.id,
    epoch: created.group.epoch,
    sender_device_id: localClient.devicePk,
    commit_type: "create",
    commit_message: JSON.stringify({ kind: "create" }),
    welcome_message: created.welcome ? JSON.stringify(created.welcome) : null,
  });

  if (insertedCommit.error) {
    throw insertedCommit.error;
  }

  // Export group AND updated client secrets
  const exportedGroup = await getOpenMlsClient().exportGroupState({
    clientId: localClient.clientId,
    groupId,
  });
  const { groupStore } = getStores(localClient.userId);
  await groupStore.saveGroupState(exportedGroup);
  await saveClientState(localClient.userId, localClient.clientId);

  activeBridgeGroups.add(runtimeGroupKey(localClient.clientId, groupId));

  return {
    dbGroupId: Number(insertedGroup.data.id),
    groupId,
    remoteDevicePk: remoteDevices[0]?.devicePk ?? 0, // Legacy compatibility
  } satisfies EnsureDmGroupResult;
}

async function loadRemoteDevicePkForGroup(groupDbId: number, localDevicePk: number) {
  const membership = await supabase
    .from("mls_group_members")
    .select("user_device_id")
    .eq("mls_group_id", groupDbId)
    .neq("user_device_id", localDevicePk)
    .eq("membership_status", "active")
    .limit(1)
    .maybeSingle();

  if (membership.error) {
    throw membership.error;
  }

  return Number(membership.data?.user_device_id ?? 0);
}

async function ensureDmGroup(
  localClient: LocalMlsClientState,
  remoteUserId: string,
) {
  const existingGroup = await findExistingDmGroup(localClient.userId, remoteUserId);
  if (!existingGroup) {
    return createNewDmGroup(localClient, remoteUserId);
  }

  try {
    await ensureJoinedDmGroup(localClient, existingGroup);
  } catch (error) {
    if (!shouldRecreateDmGroupFromError(error)) {
      throw error;
    }

    console.warn(
      "[MLS] Existing DM group could not be rejoined, creating a fresh DM session",
      existingGroup.group_identifier,
      error,
    );
    await retireDmGroup(localClient, existingGroup);
    return createNewDmGroup(localClient, remoteUserId);
  }

  return {
    dbGroupId: existingGroup.id,
    groupId: existingGroup.group_identifier,
    remoteDevicePk: await loadRemoteDevicePkForGroup(
      existingGroup.id,
      localClient.devicePk,
    ),
  } satisfies EnsureDmGroupResult;
}

export async function sendDirectMessageWithMls(input: {
  senderUserId: string;
  recipientUserId: string;
  plaintext: string;
}) {
  const localClient = await ensurePublishedDmKeyPackage(input.senderUserId);
  const group = await ensureDmGroup(localClient, input.recipientUserId);
  
  console.log("[MLS] Sending message to group", group.groupId);
  const applicationMessage = await getOpenMlsClient().createApplicationMessage({
    clientId: localClient.clientId,
    groupId: group.groupId,
    plaintext: input.plaintext,
  }).catch(e => {
    console.error("[MLS] WASM createApplicationMessage failed:", e);
    throw new Error(`Failed to encrypt message: ${e instanceof Error ? e.message : e}`);
  });

  const inserted = await supabase
    .from("direct_messages")
    .insert({
      sender_id: input.senderUserId,
      recipient_id: input.recipientUserId,
      sender_device_id: localClient.devicePk,
      recipient_device_id: group.remoteDevicePk,
      ciphertext: "You should not be seeing this message client-side",
      mls_group_id: group.dbGroupId,
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

  // Export group AND updated client secrets (storage changes after sending)
  const exportedGroup = await getOpenMlsClient().exportGroupState({
    clientId: localClient.clientId,
    groupId: group.groupId,
  });
  const { messageStore, groupStore } = getStores(input.senderUserId);
  await groupStore.saveGroupState(exportedGroup);
  await saveClientState(input.senderUserId, localClient.clientId);

  await messageStore.saveMessage({
    conversationId: dmConversationId({
      localUserId: input.senderUserId,
      localDevicePk: localClient.devicePk,
      remoteUserId: input.recipientUserId,
      remoteDevicePk: group.remoteDevicePk,
    }),
    remoteMessageId: String(inserted.data.id),
    senderUserId: input.senderUserId,
    senderDeviceId: localClient.devicePk,
    recipientUserId: input.recipientUserId,
    recipientDeviceId: group.remoteDevicePk,
    ciphertextType: 2,
    ciphertextBody: applicationMessage.message,
    plaintext: input.plaintext,
    isOutbound: true,
  });

  return {
    row: inserted.data,
    plaintext: input.plaintext,
  };
}

export async function updateDirectMessageWithMls(input: {
  senderUserId: string;
  recipientUserId: string;
  messageId: string | number;
  plaintext: string;
}) {
  const localClient = await ensurePublishedDmKeyPackage(input.senderUserId);
  const group = await ensureDmGroup(localClient, input.recipientUserId);

  const applicationMessage = await getOpenMlsClient().createApplicationMessage({
    clientId: localClient.clientId,
    groupId: group.groupId,
    plaintext: input.plaintext,
  }).catch(e => {
    throw new Error(`Failed to encrypt message: ${e instanceof Error ? e.message : e}`);
  });

  const updated = await supabase
    .from("direct_messages")
    .update({
      sender_id: input.senderUserId,
      recipient_id: input.recipientUserId,
      sender_device_id: localClient.devicePk,
      recipient_device_id: group.remoteDevicePk,
      ciphertext: "You should not be seeing this message client-side",
      mls_group_id: group.dbGroupId,
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

  const exportedGroup = await getOpenMlsClient().exportGroupState({
    clientId: localClient.clientId,
    groupId: group.groupId,
  });
  const { messageStore, groupStore } = getStores(input.senderUserId);
  await groupStore.saveGroupState(exportedGroup);
  await saveClientState(input.senderUserId, localClient.clientId);

  await messageStore.saveMessage({
    conversationId: dmConversationId({
      localUserId: input.senderUserId,
      localDevicePk: localClient.devicePk,
      remoteUserId: input.recipientUserId,
      remoteDevicePk: group.remoteDevicePk,
    }),
    remoteMessageId: String(input.messageId),
    senderUserId: input.senderUserId,
    senderDeviceId: localClient.devicePk,
    recipientUserId: input.recipientUserId,
    recipientDeviceId: group.remoteDevicePk,
    ciphertextType: 2,
    ciphertextBody: applicationMessage.message,
    plaintext: input.plaintext,
    isOutbound: true,
  });

  return {
    row: updated.data,
    plaintext: input.plaintext,
  };
}

export async function resolveDirectMessagePlaintext(input: {
  ownerUserId: string;
  remoteUserId: string;
  row: DirectMessageRow;
}) {
  const localClient = await ensurePublishedDmKeyPackage(input.ownerUserId);
  const remoteDevicePk =
    input.row.sender_id === input.ownerUserId
      ? Number(input.row.recipient_device_id ?? 0)
      : Number(input.row.sender_device_id ?? 0);

  const { messageStore, groupStore } = getStores(input.ownerUserId);

  if (input.row.id) {
    const existingLocalMessage = await messageStore.getMessageByRemoteId(
      String(input.row.id),
    );
    if (existingLocalMessage?.plaintext) {
      return existingLocalMessage.plaintext;
    }
  }

  if (!input.row.mls_group_id) {
    return null;
  }

  const groupRow = await supabase
    .from("mls_groups")
    .select("id, group_identifier, current_epoch")
    .eq("id", input.row.mls_group_id)
    .maybeSingle();

  if (groupRow.error) {
    throw groupRow.error;
  }

  if (!groupRow.data) {
    return null;
  }

  await ensureJoinedDmGroup(localClient, groupRow.data as DmGroupRow);

  const messageEnvelope = parseJsonField<{ message?: string }>(input.row.mls_message);
  if (!messageEnvelope?.message) {
    return null;
  }

  if (input.row.sender_id === input.ownerUserId) {
    // We were the sender on another device, we can decrypt this!
  }

  console.log("[MLS] Decrypting message from", input.row.sender_id);
  const processed = await getOpenMlsClient().processIncomingMessage({
    clientId: localClient.clientId,
    groupId: groupRow.data.group_identifier,
    message: messageEnvelope.message,
  }).catch(e => {
    console.error("[MLS] WASM processIncomingMessage failed:", e);
    throw new Error(`Failed to decrypt message: ${e instanceof Error ? e.message : e}`);
  });

  // Export group AND updated client secrets (storage changes after processing)
  const exportedGroup = await getOpenMlsClient().exportGroupState({
    clientId: localClient.clientId,
    groupId: groupRow.data.group_identifier,
  });
  await groupStore.saveGroupState(exportedGroup);
  await saveClientState(input.ownerUserId, localClient.clientId);

  if (!processed.plaintext) {
    return null;
  }

  await messageStore.saveMessage({
    conversationId: dmConversationId({
      localUserId: input.ownerUserId,
      localDevicePk: localClient.devicePk,
      remoteUserId: input.remoteUserId,
      remoteDevicePk,
    }),
    remoteMessageId: String(input.row.id),
    senderUserId: input.row.sender_id,
    senderDeviceId: Number(input.row.sender_device_id ?? 0),
    recipientUserId: input.row.recipient_id,
    recipientDeviceId: Number(input.row.recipient_device_id ?? 0),
    ciphertextType: 2,
    ciphertextBody: messageEnvelope.message,
    plaintext: processed.plaintext,
    isOutbound: input.row.sender_id === input.ownerUserId,
  });

  return processed.plaintext;
}

export function isMlsDirectMessageRow(row: { mls_message?: unknown; mls_group_id?: number | null }) {
  return Boolean(row?.mls_group_id && parseJsonField(row.mls_message));
}
