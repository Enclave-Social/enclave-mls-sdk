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

import { secureStorage } from "../os";

function normalizeNamespace(value: string) {
  return value.replace(/[^a-zA-Z0-9._-]/g, "_");
}

export class SecureVault {
  private readonly namespace: string;

  constructor(namespace: string) {
    this.namespace = normalizeNamespace(namespace);
  }

  private buildKey(name: string) {
    return `mls_${this.namespace}_${name}`;
  }

  async getString(name: string) {
    const key = this.buildKey(name);
    return secureStorage.getSecureValue(key);
  }

  async setString(name: string, value: string) {
    const key = this.buildKey(name);
    await secureStorage.setSecureValue(key, value);
  }

  async delete(name: string) {
    const key = this.buildKey(name);
    await secureStorage.deleteSecureValue(key);
  }
}
