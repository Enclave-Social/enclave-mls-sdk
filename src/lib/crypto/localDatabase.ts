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

import {
  openDatabaseAsync,
  type SQLiteBindValue,
  type SQLiteRunResult,
} from "expo-sqlite";
import { isSqlStorageAvailable } from "../os";

const DATABASE_PREFIX = "enclave_crypto";

const SCHEMA_SQL = `
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS local_identities (
  address TEXT PRIMARY KEY NOT NULL,
  public_key_base64 TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS local_sessions (
  address TEXT PRIMARY KEY NOT NULL,
  record_base64 TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS local_prekeys (
  id INTEGER PRIMARY KEY NOT NULL,
  record_base64 TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS local_signed_prekeys (
  id INTEGER PRIMARY KEY NOT NULL,
  record_base64 TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS local_kyber_prekeys (
  id INTEGER PRIMARY KEY NOT NULL,
  record_base64 TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS encrypted_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  conversation_id TEXT NOT NULL,
  client_message_id TEXT,
  remote_message_id TEXT,
  sender_user_id TEXT NOT NULL,
  sender_device_id INTEGER NOT NULL,
  recipient_user_id TEXT NOT NULL,
  recipient_device_id INTEGER NOT NULL,
  ciphertext_type INTEGER NOT NULL,
  ciphertext_body TEXT NOT NULL,
  plaintext TEXT,
  is_outbound INTEGER NOT NULL DEFAULT 0,
  is_read INTEGER NOT NULL DEFAULT 0,
  sent_at INTEGER NOT NULL,
  delivered_at INTEGER,
  read_at INTEGER,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS encrypted_messages_conversation_created_idx
  ON encrypted_messages (conversation_id, created_at DESC);

CREATE INDEX IF NOT EXISTS encrypted_messages_remote_message_idx
  ON encrypted_messages (remote_message_id);

CREATE TABLE IF NOT EXISTS local_message_packets (
  id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
  owner_user_id TEXT NOT NULL,
  source_table TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  remote_message_id TEXT NOT NULL,
  encrypted_packet_base64 TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (owner_user_id, source_table, remote_message_id)
);

CREATE INDEX IF NOT EXISTS local_message_packets_owner_conversation_idx
  ON local_message_packets (owner_user_id, conversation_id, received_at DESC);

CREATE TABLE IF NOT EXISTS mls_group_states (
  owner_user_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  state_json TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (owner_user_id, group_id)
);
`;

interface DatabaseInterface {
  execAsync(sql: string): Promise<void>;
  runAsync(sql: string, params: any[]): Promise<SQLiteRunResult>;
  getFirstAsync<T>(sql: string, params: any[]): Promise<T | null>;
  getAllAsync<T>(sql: string, params: any[]): Promise<T[]>;
}

class MockDatabase implements DatabaseInterface {
  async execAsync(sql: string) { return; }
  async runAsync(sql: string, params: any[]): Promise<SQLiteRunResult> {
    return { lastInsertRowId: 0, changes: 0 };
  }
  async getFirstAsync<T>(sql: string, params: any[]): Promise<T | null> {
    return null;
  }
  async getAllAsync<T>(sql: string, params: any[]): Promise<T[]> {
    return [];
  }
}

const databasePromises = new Map<string, Promise<DatabaseInterface>>();
const fallbackToMock = new Set<string>();
let taskQueue: Promise<any> = Promise.resolve();

async function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const nextTask = taskQueue.then(task);
  taskQueue = nextTask.catch(() => {});
  return nextTask;
}

export type SqliteParams = SQLiteBindValue[];

function getSanitizedDbName(userId: string) {
  if (!userId || userId === "undefined") {
    throw new Error("No valid User ID provided.");
  }
  const safeId = userId.replace(/[^a-z0-9]/gi, "_");
  return `${DATABASE_PREFIX}_${safeId}.db`;
}

export async function getCryptoDatabaseAsync(userId: string): Promise<DatabaseInterface> {
  const dbName = getSanitizedDbName(userId);

  if (fallbackToMock.has(dbName)) {
    return new MockDatabase();
  }

  let promise = databasePromises.get(dbName);
  if (!promise) {
    if (!isSqlStorageAvailable()) {
      promise = Promise.resolve(new MockDatabase());
    } else {
      promise = initializeDatabaseAsync(userId);
    }
    databasePromises.set(dbName, promise);
  }
  return promise;
}

async function initializeDatabaseAsync(userId: string): Promise<DatabaseInterface> {
  const dbName = getSanitizedDbName(userId);
  try {
    const database = await openDatabaseAsync(dbName);
    await database.execAsync(SCHEMA_SQL);
    return database as unknown as DatabaseInterface;
  } catch (e) {
    console.warn("[Storage] SQLite init failed, falling back to mock:", e);
    fallbackToMock.add(dbName);
    return new MockDatabase();
  }
}

export async function runAsync(userId: string, query: string, params: SqliteParams = []) {
  if (!userId) throw new Error("userId is required for runAsync");
  return enqueue(async () => {
    try {
      const database = await getCryptoDatabaseAsync(userId);
      return await database.runAsync(query, params);
    } catch (e) {
      console.warn("[Storage] Query failed, triggering mock fallback:", e);
      fallbackToMock.add(getSanitizedDbName(userId));
      return { lastInsertRowId: 0, changes: 0 };
    }
  });
}

export async function getFirstAsync<T>(userId: string, query: string, params: SqliteParams = []) {
  if (!userId) throw new Error("userId is required for getFirstAsync");
  return enqueue(async () => {
    try {
      const database = await getCryptoDatabaseAsync(userId);
      return await database.getFirstAsync<T>(query, params);
    } catch {
      fallbackToMock.add(getSanitizedDbName(userId));
      return null;
    }
  });
}

export async function getAllAsync<T>(userId: string, query: string, params: SqliteParams = []) {
  if (!userId) throw new Error("userId is required for getAllAsync");
  return enqueue(async () => {
    try {
      const database = await getCryptoDatabaseAsync(userId);
      return await database.getAllAsync<T>(query, params);
    } catch {
      fallbackToMock.add(getSanitizedDbName(userId));
      return [];
    }
  });
}
