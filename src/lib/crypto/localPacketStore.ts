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

import * as ExpoCrypto from "expo-crypto";

import { base64ToBytes, bytesToBase64 } from "./base64";
import { getAllAsync, runAsync } from "./localDatabase";
import { SecureVault } from "./secureVault";

const LOCAL_PACKET_KEY_NAME = "local_message_packet_key";
const LOCAL_PACKET_KEY_BYTES = 32;
const LOCAL_PACKET_IV_BYTES = 12;
const LOCAL_PACKET_CIPHER_PREFIX = "v1";

export interface LocalPacketRow {
  id: number;
  owner_user_id: string;
  source_table: string;
  conversation_id: string;
  remote_message_id: string;
  encrypted_packet_base64: string;
  received_at: number;
  created_at: number;
  updated_at: number;
}

export interface SaveReceivedPacketInput {
  ownerUserId: string;
  sourceTable: string;
  conversationId: string;
  remoteMessageId: string;
  packet: string | Record<string, unknown>;
  receivedAt?: number;
}

export interface DecryptedLocalPacket {
  id: number;
  ownerUserId: string;
  sourceTable: string;
  conversationId: string;
  remoteMessageId: string;
  packet: unknown;
  receivedAt: number;
  createdAt: number;
  updatedAt: number;
}

function packetToString(packet: SaveReceivedPacketInput["packet"]) {
  return typeof packet === "string" ? packet : JSON.stringify(packet);
}

function encodeText(value: string) {
  return new TextEncoder().encode(value);
}

function decodeText(value: Uint8Array) {
  return new TextDecoder().decode(value);
}

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
    "WebCrypto SubtleCrypto is unavailable on this client. Local packet encryption requires crypto.subtle support.",
  );
}

function toArrayBuffer(value: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy.buffer;
}

function buildAdditionalData(input: {
  ownerUserId: string;
  sourceTable: string;
  conversationId: string;
  remoteMessageId: string;
}) {
  return encodeText(
    JSON.stringify({
      ownerUserId: input.ownerUserId,
      sourceTable: input.sourceTable,
      conversationId: input.conversationId,
      remoteMessageId: input.remoteMessageId,
    }),
  );
}

async function getUserPacketKeyAsync(ownerUserId: string) {
  const vault = new SecureVault(`message_packets_${ownerUserId}`);
  const existingKey = await vault.getString(LOCAL_PACKET_KEY_NAME);
  const subtle = getWebCrypto().subtle;

  if (existingKey) {
    return subtle.importKey(
      "raw",
      toArrayBuffer(base64ToBytes(existingKey)),
      "AES-GCM",
      false,
      ["encrypt", "decrypt"],
    );
  }

  const keyBytes = ExpoCrypto.getRandomBytes(LOCAL_PACKET_KEY_BYTES);
  await vault.setString(LOCAL_PACKET_KEY_NAME, bytesToBase64(keyBytes));
  return subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    "AES-GCM",
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptPacketStringAsync(
  metadata: Omit<SaveReceivedPacketInput, "packet" | "receivedAt">,
  packetString: string,
) {
  const encryptionKey = await getUserPacketKeyAsync(metadata.ownerUserId);
  const iv = ExpoCrypto.getRandomBytes(LOCAL_PACKET_IV_BYTES);
  const ciphertext = await getWebCrypto().subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: toArrayBuffer(buildAdditionalData(metadata)),
    },
    encryptionKey,
    toArrayBuffer(encodeText(packetString)),
  );

  return [
    LOCAL_PACKET_CIPHER_PREFIX,
    bytesToBase64(iv),
    bytesToBase64(new Uint8Array(ciphertext)),
  ].join(".");
}

async function decryptPacketStringAsync(row: LocalPacketRow) {
  const encryptionKey = await getUserPacketKeyAsync(row.owner_user_id);
  const [version, ivBase64, ciphertextBase64] = row.encrypted_packet_base64.split(".");
  if (
    version !== LOCAL_PACKET_CIPHER_PREFIX ||
    !ivBase64 ||
    !ciphertextBase64
  ) {
    throw new Error("Unsupported local packet encryption format.");
  }

  const decrypted = await getWebCrypto().subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(base64ToBytes(ivBase64)),
      additionalData: toArrayBuffer(
        buildAdditionalData({
          ownerUserId: row.owner_user_id,
          sourceTable: row.source_table,
          conversationId: row.conversation_id,
          remoteMessageId: row.remote_message_id,
        }),
      ),
    },
    encryptionKey,
    toArrayBuffer(base64ToBytes(ciphertextBase64)),
  );

  return decodeText(new Uint8Array(decrypted));
}

export function buildChannelConversationId(channelId: string | number) {
  return `channel:${channelId}`;
}

export class LocalPacketStore {
  async saveReceivedPacket(input: SaveReceivedPacketInput) {
    const timestamp = input.receivedAt ?? Date.now();
    const packetString = packetToString(input.packet);
    const encryptedPacketBase64 = await encryptPacketStringAsync(
      {
        ownerUserId: input.ownerUserId,
        sourceTable: input.sourceTable,
        conversationId: input.conversationId,
        remoteMessageId: input.remoteMessageId,
      },
      packetString,
    );

    await runAsync(
      input.ownerUserId,
      `
      INSERT INTO local_message_packets (
        owner_user_id,
        source_table,
        conversation_id,
        remote_message_id,
        encrypted_packet_base64,
        received_at,
        created_at,
        updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(owner_user_id, source_table, remote_message_id)
      DO UPDATE SET
        conversation_id = excluded.conversation_id,
        encrypted_packet_base64 = excluded.encrypted_packet_base64,
        received_at = excluded.received_at,
        updated_at = excluded.updated_at
      `,
      [
        input.ownerUserId,
        input.sourceTable,
        input.conversationId,
        input.remoteMessageId,
        encryptedPacketBase64,
        timestamp,
        timestamp,
        timestamp,
      ],
    );
  }

  async listConversationPackets(ownerUserId: string, conversationId: string, limit = 100) {
    const rows = await getAllAsync<LocalPacketRow>(
      ownerUserId,
      `
      SELECT *
      FROM local_message_packets
      WHERE owner_user_id = ?
        AND conversation_id = ?
      ORDER BY received_at DESC
      LIMIT ?
      `,
      [ownerUserId, conversationId, limit],
    );

    return Promise.all(
      rows.map(async (row: LocalPacketRow) => {
        const packetString = await decryptPacketStringAsync(row);
        return {
          id: row.id,
          ownerUserId: row.owner_user_id,
          sourceTable: row.source_table,
          conversationId: row.conversation_id,
          remoteMessageId: row.remote_message_id,
          packet: JSON.parse(packetString),
          receivedAt: row.received_at,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        } satisfies DecryptedLocalPacket;
      }),
    );
  }

  async getPacketByRemoteId(
    ownerUserId: string,
    sourceTable: string,
    remoteMessageId: string,
  ) {
    const rows = await getAllAsync<LocalPacketRow>(
      ownerUserId,
      `
      SELECT *
      FROM local_message_packets
      WHERE owner_user_id = ?
        AND source_table = ?
        AND remote_message_id = ?
      LIMIT 1
      `,
      [ownerUserId, sourceTable, remoteMessageId],
    );

    const row = rows[0];
    if (!row) {
      return null;
    }

    const packetString = await decryptPacketStringAsync(row);
    return {
      id: row.id,
      ownerUserId: row.owner_user_id,
      sourceTable: row.source_table,
      conversationId: row.conversation_id,
      remoteMessageId: row.remote_message_id,
      packet: JSON.parse(packetString),
      receivedAt: row.received_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    } satisfies DecryptedLocalPacket;
  }
}
