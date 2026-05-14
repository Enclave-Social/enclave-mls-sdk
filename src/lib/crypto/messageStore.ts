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

import { getAllAsync, getFirstAsync, runAsync } from "./localDatabase";

export interface LocalMessageRecord {
  id: number;
  conversation_id: string;
  client_message_id: string | null;
  remote_message_id: string | null;
  sender_user_id: string;
  sender_device_id: number;
  recipient_user_id: string;
  recipient_device_id: number;
  ciphertext_type: number;
  ciphertext_body: string;
  plaintext: string | null;
  is_outbound: number;
  is_read: number;
  sent_at: number;
  delivered_at: number | null;
  read_at: number | null;
  created_at: number;
}

export interface SaveMessageInput {
  conversationId: string;
  clientMessageId?: string | null;
  remoteMessageId?: string | null;
  senderUserId: string;
  senderDeviceId: number;
  recipientUserId: string;
  recipientDeviceId: number;
  ciphertextType: number;
  ciphertextBody: string;
  plaintext?: string | null;
  isOutbound: boolean;
  isRead?: boolean;
  sentAt?: number;
  deliveredAt?: number | null;
  readAt?: number | null;
  createdAt?: number;
}

export function buildDirectConversationId(input: {
  localUserId: string;
  localDeviceId: number;
  remoteUserId: string;
  remoteDeviceId: number;
}) {
  const left = `${input.localUserId}:${input.localDeviceId}`;
  const right = `${input.remoteUserId}:${input.remoteDeviceId}`;
  return ["dm", ...[left, right].sort()].join(":");
}

export class LocalMessageStore {
  constructor(private userId: string) {}

  async saveMessage(input: SaveMessageInput) {
    const timestamp = input.createdAt ?? Date.now();
    const result = await runAsync(
      this.userId,
      `
      INSERT INTO encrypted_messages (
        conversation_id,
        client_message_id,
        remote_message_id,
        sender_user_id,
        sender_device_id,
        recipient_user_id,
        recipient_device_id,
        ciphertext_type,
        ciphertext_body,
        plaintext,
        is_outbound,
        is_read,
        sent_at,
        delivered_at,
        read_at,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        input.conversationId,
        input.clientMessageId ?? null,
        input.remoteMessageId ?? null,
        input.senderUserId,
        input.senderDeviceId,
        input.recipientUserId,
        input.recipientDeviceId,
        input.ciphertextType,
        input.ciphertextBody,
        input.plaintext ?? null,
        input.isOutbound ? 1 : 0,
        input.isRead ? 1 : 0,
        input.sentAt ?? timestamp,
        input.deliveredAt ?? null,
        input.readAt ?? null,
        timestamp,
      ],
    );

    return result.lastInsertRowId;
  }

  async listMessages(conversationId: string, limit = 100) {
    return getAllAsync<LocalMessageRecord>(
      this.userId,
      `
      SELECT *
      FROM encrypted_messages
      WHERE conversation_id = ?
      ORDER BY created_at DESC
      LIMIT ?
      `,
      [conversationId, limit],
    );
  }

  async getMessageByClientId(clientMessageId: string) {
    return getFirstAsync<LocalMessageRecord>(
      this.userId,
      `
      SELECT *
      FROM encrypted_messages
      WHERE client_message_id = ?
      LIMIT 1
      `,
      [clientMessageId],
    );
  }

  async getMessageByRemoteId(remoteMessageId: string) {
    return getFirstAsync<LocalMessageRecord>(
      this.userId,
      `
      SELECT *
      FROM encrypted_messages
      WHERE remote_message_id = ?
      LIMIT 1
      `,
      [remoteMessageId],
    );
  }

  async markDelivered(localMessageId: number, deliveredAt = Date.now()) {
    await runAsync(
      this.userId,
      `
      UPDATE encrypted_messages
      SET delivered_at = ?
      WHERE id = ?
      `,
      [deliveredAt, localMessageId],
    );
  }

  async markRead(localMessageId: number, readAt = Date.now()) {
    await runAsync(
      this.userId,
      `
      UPDATE encrypted_messages
      SET is_read = 1, read_at = ?
      WHERE id = ?
      `,
      [readAt, localMessageId],
    );
  }

  async attachPlaintext(localMessageId: number, plaintext: string) {
    await runAsync(
      this.userId,
      `
      UPDATE encrypted_messages
      SET plaintext = ?
      WHERE id = ?
      `,
      [plaintext, localMessageId],
    );
  }
}
