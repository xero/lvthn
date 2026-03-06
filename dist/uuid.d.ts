/**
 * UUID class
 * @deprecated Use the Web Crypto API (`crypto.randomUUID()`) instead.
 */
export declare class UUID {
    msec: number;
    nsec: number;
    clockseq: number | null;
    /**
   * UUID ctor
   */
    constructor();
    /**
   * Create a time based V1 UUID
   * @param {Uint8Array} node 6 byte array of unique node identifier like the MAC address or TRUE random data
   * @param {Uint8Array} clockseq Optional 2 byte array of random data for clockseq init
   * @return {Uint8Array} UUID as 16 byte typed array or 'undefined' if error
   */
    v1(node: Uint8Array, clockseq?: Uint8Array): Uint8Array | undefined;
    /**
   * Create a random based V4 UUID
   * @param {Uint8Array} rand 16 byte array of TRUE random data
   * @return {Uint8Array} UUID as 16 byte typed array or 'undefined' if error
   */
    v4(rand: Uint8Array): Uint8Array | undefined;
    /**
   * Convert an UUID to string format like 550e8400-e29b-11d4-a716-446655440000
   * @param {Uint8Array} uuid 16 byte UUID as byte array
   * @return {String} UUID as string
   */
    toString(uuid: Uint8Array): string;
}
