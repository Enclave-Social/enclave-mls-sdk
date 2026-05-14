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

import { Asset } from "expo-asset";
import { supportsBrowserWasmMls } from "../os";

import type {
  OpenMlsIdentityRecord,
  OpenMlsBasicIdentity,
  OpenMlsBuildInfo,
  OpenMlsWasmOperation,
} from "./types";

type OpenMlsWasmModule = {
  default?: (input?: {
    module_or_path?: string | URL | BufferSource | WebAssembly.Module;
  }) => Promise<unknown>;
  openmls_build_info: () => OpenMlsBuildInfo;
  create_basic_identity: (identity: string) => OpenMlsBasicIdentity;
  create_identity_record?: (requestJson: string) => string;
  create_key_package?: (requestJson: string) => string;
  create_group?: (requestJson: string) => string;
  add_members?: (requestJson: string) => string;
  join_from_welcome?: (requestJson: string) => string;
  create_application_message?: (requestJson: string) => string;
  process_incoming_message?: (requestJson: string) => string;
  export_client_state?: (requestJson: string) => string;
  import_client_state?: (requestJson: string) => string;
  export_group_state?: (requestJson: string) => string;
  import_group_state?: (requestJson: string) => string;
};

let cachedModule: OpenMlsWasmModule | null = null;
let cachedModulePromise: Promise<OpenMlsWasmModule> | null = null;

async function getOpenMlsWasmUri() {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const wasmModule = require("../../../openmls-wasm/pkg/openmls_wasm_bg.wasm");
  const wasmAsset = Asset.fromModule(wasmModule);

  if (!wasmAsset.localUri && !wasmAsset.uri) {
    await wasmAsset.downloadAsync();
  }

  return wasmAsset.localUri ?? wasmAsset.uri;
}

export async function loadOpenMlsWasm(): Promise<OpenMlsWasmModule> {
  if (!supportsBrowserWasmMls()) {
    throw new Error(
      "OpenMLS is only scaffolded for WASM/web right now. Native Expo integration still needs an FFI path.",
    );
  }

  if (cachedModule) {
    return cachedModule;
  }

  if (cachedModulePromise) {
    return cachedModulePromise;
  }

  cachedModulePromise = (async () => {
    try {
      const module = (await import(
        "../../../openmls-wasm/pkg/openmls_wasm.js"
      )) as unknown as OpenMlsWasmModule;

      if (typeof module.default === "function") {
        const wasmUri = await getOpenMlsWasmUri();
        await module.default({ module_or_path: wasmUri });
      }

      cachedModule = module;
      return module;
    } catch (error) {
      cachedModulePromise = null;
      const message =
        error instanceof Error ? error.message : "Unknown OpenMLS WASM load error";
      throw new Error(
        `OpenMLS WASM package is not built yet. Run \`npm run mls:wasm:build\` after installing Rust + wasm-pack. Original error: ${message}`,
      );
    }
  })();

  return cachedModulePromise;
}

export async function getOpenMlsBuildInfo() {
  const openmls = await loadOpenMlsWasm();
  return openmls.openmls_build_info();
}

export async function createOpenMlsBasicIdentity(identity: string) {
  const openmls = await loadOpenMlsWasm();
  return openmls.create_basic_identity(identity);
}

export async function createOpenMlsIdentityRecord(
  request: OpenMlsIdentityRecord,
) {
  const openmls = await loadOpenMlsWasm();

  if (typeof openmls.create_identity_record === "function") {
    return JSON.parse(
      openmls.create_identity_record(JSON.stringify(request)),
    ) as OpenMlsIdentityRecord;
  }

  const basicIdentity = openmls.create_basic_identity(request.identity);
  return {
    ...request,
    ciphersuite: basicIdentity.ciphersuite,
    signatureKeyLength: basicIdentity.signature_key_len,
  };
}

function requireWasmMethod(
  wasmModule: OpenMlsWasmModule,
  methodName: OpenMlsWasmOperation,
) {
  const method = wasmModule[methodName];

  if (typeof method !== "function") {
    throw new Error(
      `OpenMLS WASM bridge does not expose \`${methodName}\` yet. The TypeScript plumbing is ready, but the Rust bridge still needs that export.`,
    );
  }

  return method;
}

export async function callOpenMlsJsonMethod<TRequest, TResponse>(
  methodName: Exclude<
    OpenMlsWasmOperation,
    "openmls_build_info" | "create_basic_identity"
  >,
  request: TRequest,
) {
  const openmls = await loadOpenMlsWasm();
  const method = requireWasmMethod(openmls, methodName) as (
    requestJson: string,
  ) => string;

  const responseJson = method(JSON.stringify(request));
  return JSON.parse(responseJson) as TResponse;
}

export function isOpenMlsWebRuntime() {
  return supportsBrowserWasmMls();
}

export type { OpenMlsWasmModule };
