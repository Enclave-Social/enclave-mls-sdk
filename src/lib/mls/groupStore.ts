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

import { getAllAsync, getFirstAsync, runAsync } from "../crypto/localDatabase";
import type { ExportedGroupState } from "./types";

export class LocalGroupStore {
  constructor(private userId: string) {}

  async saveGroupState(state: ExportedGroupState) {
    const now = Date.now();
    await runAsync(
      this.userId,
      `INSERT INTO mls_group_states (owner_user_id, group_id, state_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(owner_user_id, group_id) DO UPDATE SET
         state_json = excluded.state_json,
         updated_at = excluded.updated_at`,
      [this.userId, state.groupId, JSON.stringify(state), now, now]
    );
  }

  async getGroupState(groupId: string): Promise<ExportedGroupState | null> {
    const row = await getFirstAsync<{ state_json: string }>(
      this.userId,
      "SELECT state_json FROM mls_group_states WHERE owner_user_id = ? AND group_id = ?",
      [this.userId, groupId]
    );
    if (!row) return null;
    return JSON.parse(row.state_json);
  }

  async getAllGroupStates(): Promise<ExportedGroupState[]> {
    const rows = await getAllAsync<{ state_json: string }>(
      this.userId,
      "SELECT state_json FROM mls_group_states WHERE owner_user_id = ?",
      [this.userId]
    );
    return rows.map((r: { state_json: string }) => JSON.parse(r.state_json));
  }

  async deleteGroupState(groupId: string) {
    await runAsync(
      this.userId,
      "DELETE FROM mls_group_states WHERE owner_user_id = ? AND group_id = ?",
      [this.userId, groupId]
    );
  }
}
