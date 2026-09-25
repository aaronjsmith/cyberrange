/** Browser stub for node:zlib — just-bash gzip helpers are unused in the lab. */

export const constants = {
  Z_SYNC_FLUSH: 2,
  Z_FINISH: 4,
  Z_NO_FLUSH: 0,
  Z_OK: 0,
  Z_STREAM_END: 1,
  Z_DEFAULT_COMPRESSION: -1,
};

export function gunzipSync(_data: Uint8Array): Uint8Array {
  throw new Error('gunzip is not available in the browser lab runtime');
}

export function gzipSync(_data: Uint8Array): Uint8Array {
  throw new Error('gzip is not available in the browser lab runtime');
}

export function createGunzip(): never {
  throw new Error('createGunzip is not available in the browser lab runtime');
}

export function createGzip(): never {
  throw new Error('createGzip is not available in the browser lab runtime');
}

export default {
  constants,
  gunzipSync,
  gzipSync,
  createGunzip,
  createGzip,
};
