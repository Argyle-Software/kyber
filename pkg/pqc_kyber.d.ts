/* tslint:disable */
/* eslint-disable */
/**
* @returns {Keys}
*/
export function keypair(): Keys;
/**
* @param {Uint8Array} pk
* @returns {Kex}
*/
export function encapsulate(pk: Uint8Array): Kex;
/**
* @param {Uint8Array} ct
* @param {Uint8Array} sk
* @returns {Uint8Array}
*/
export function decapsulate(ct: Uint8Array, sk: Uint8Array): Uint8Array;
/**
*/
export class Kex {
  free(): void;
/**
* @param {Uint8Array} public_key
*/
  constructor(public_key: Uint8Array);
/**
*/
  ciphertext: Uint8Array;
/**
*/
  sharedSecret: Uint8Array;
}
/**
*/
export class Keys {
  free(): void;
/**
*/
  constructor();
/**
*/
  readonly pubkey: Uint8Array;
/**
*/
  readonly secret: Uint8Array;
}
/**
*/
export class Params {
  free(): void;
/**
*/
  static readonly ciphertextBytes: number;
/**
*/
  static readonly publicKeyBytes: number;
/**
*/
  static readonly secretKeyBytes: number;
/**
*/
  static readonly sharedSecretBytes: number;
}
