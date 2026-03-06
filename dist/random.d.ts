import { Serpent } from './serpent';
import { SHA256 } from './sha256';
/**
 * FORTUNA random class
 */
export declare class Random {
    NUM_POOLS: number;
    RESEED_LIMIT: number;
    MILLISECONDS_PER_RESEED: number;
    gen: Serpent;
    genKey: Uint8Array;
    genCnt: Uint8Array;
    poolData: SHA256[];
    poolEntropy: number[];
    robin: {
        kbd: number;
        mouse: number;
        scroll: number;
        touch: number;
        motion: number;
        time: number;
        rnd: number;
        dom: number;
    };
    entropy_level: number;
    eventId: number;
    reseedCnt: number;
    lastReseed: number;
    active: boolean;
    timer: ReturnType<typeof setInterval>;
    /**
   * ctor
   * @param {Number} numPools Number of pools used for entropy acquisition. Defaults to 32 pools, use 16 on limited entropy sources
   * @param {Uint8Array} entropy Optional array of any length with initial (true) random data (the more the better)
   */
    constructor(numPools?: number, entropy?: Uint8Array);
    /**
   * Start the generator (public wrapper for init())
   * Normally start/stop is not necessary, init() is called from ctor
   */
    start(): void;
    /**
   * Stop the generator
   * Normally stopping is not necessary
   */
    stop(): void;
    /**
   * Return the actual generator entropy (number of available random bytes)
   * @return {Number} Number of available random bytes
   */
    getEntropy(): number;
    /**
   * Add external given entropy
   * @param {Uint8Array} entropy Random bytes to be added to the entropy pools
   */
    addEntropy(entropy: Uint8Array): void;
    /**
   * Init/start the module (called by ctor as 'autostart')
   * @param {Uint8Array} entropy Optional array of any length of (true) random bytes to be added to the entropy pools
   */
    private init;
    /**
   * Reseed the generator with the given byte array
   */
    private reseed;
    /**
   * Internal function to generates a number of (16 byte) blocks of random output
   * @param {Number} blocks Number of blocks to generate
   */
    private generateBlocks;
    /**
   * Internal function to get random data bytes
   */
    private pseudoRandomData;
    /**
   * Get random data bytes
   * @param {Number} length Number of bytes to generate
   * @return {Uint8Array} Byte array of crypto secure random values or undefined, if generator is not ready
   */
    get(length: number): Uint8Array | undefined;
    /**
   * Start the built-in entropy collectors
   */
    private startCollectors;
    /**
   * Stop the built-in entropy collectors
   */
    private stopCollectors;
    /**
   * In case of an event burst (eg. motion events), this executes the given fn once every threshold
   * @param {Function} fn Function to be throttled
   * @param {number} threshold Threshold in [ms]
   * @param {Object} scope Optional scope, defaults to 'this'
   * @returns {Function} Resulting function
   */
    private throttle;
    /**
   * Add entropy data to pool
   * @param data {Uint8Array} Entropy data to add
   * @param pool_idx {Number} Pool index number to add the entropy data to
   * @param entropy {Number} Added entropy data quality in bits
   */
    private addRandomEvent;
    private collectorKeyboard;
    private collectorMouse;
    private collectorClick;
    private collectorTouch;
    private collectorScroll;
    private collectorMotion;
    private collectorTime;
    private collectorDom;
    private collectorCryptoRandom;
}
