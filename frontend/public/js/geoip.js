/**
 * GeoIP Engine — Browser-Side MaxMind MMDB Reader
 * 
 * Loads GeoLite2-Country.mmdb and GeoLite2-ASN.mmdb into the browser,
 * caches them in IndexedDB, and provides lookup functions.
 * 
 * Uses a lightweight custom MMDB reader (no dependencies required).
 */

const GeoIP = (() => {
    const DB_NAME = 'SysAdminToolkit_GeoIP';
    const DB_VERSION = 1;
    const STORE_NAME = 'databases';

    let countryReader = null;
    let asnReader = null;
    let initialized = false;

    // ─── IndexedDB Helpers ───

    function openDB() {
        return new Promise((resolve, reject) => {
            const req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = () => {
                const db = req.result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME);
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => reject(req.error);
        });
    }

    async function getCached(key) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readonly');
            const req = tx.objectStore(STORE_NAME).get(key);
            req.onsuccess = () => resolve(req.result || null);
            req.onerror = () => reject(req.error);
        });
    }

    async function setCached(key, value) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            tx.objectStore(STORE_NAME).put(value, key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    async function deleteCached(key) {
        const db = await openDB();
        return new Promise((resolve, reject) => {
            const tx = db.transaction(STORE_NAME, 'readwrite');
            tx.objectStore(STORE_NAME).delete(key);
            tx.oncomplete = () => resolve();
            tx.onerror = () => reject(tx.error);
        });
    }

    // ─── MMDB Reader (lightweight, pure JS) ───

    class MMDBReader {
        constructor(buffer) {
            this.data = new DataView(buffer);
            this.buf = new Uint8Array(buffer);
            this.findMetadata();
        }

        findMetadata() {
            // Metadata marker: \xAB\xCD\xEFMaxMind.com (14 bytes)
            const markerStr = '\xAB\xCD\xEFMaxMind.com';
            const marker = new Uint8Array(markerStr.length);
            for (let i = 0; i < markerStr.length; i++) marker[i] = markerStr.charCodeAt(i);

            const markerLen = marker.length;
            // Search from end of file backwards for the LAST occurrence
            for (let pos = this.buf.length - markerLen; pos >= 0; pos--) {
                let found = true;
                for (let j = 0; j < markerLen; j++) {
                    if (this.buf[pos + j] !== marker[j]) { found = false; break; }
                }
                if (!found) continue;

                // Found marker
                const metaStart = pos + markerLen;
                const decoder = new MMDBDecoder(this.buf, metaStart);
                const [meta] = decoder.decode(metaStart);
                this.metadata = meta;
                break;
            }

            if (!this.metadata) throw new Error('Invalid MMDB: metadata not found');

            this.nodeCount = this.metadata.node_count;
            this.recordSize = this.metadata.record_size;
            this.nodeSize = (this.recordSize * 2) / 8;
            this.searchTreeSize = this.nodeCount * this.nodeSize;
            this.dataStart = this.searchTreeSize + 16; // 16 = data section separator
            if (!(this.nodeCount > 0) || ![24, 28, 32].includes(this.recordSize) || this.dataStart > this.buf.length) {
                throw new Error('Invalid MMDB: search tree does not fit the file');
            }
            this.decoder = new MMDBDecoder(this.buf, this.dataStart);
        }

        lookup(ip) {
            const bits = ipToBits(ip);
            if (!bits) return null;

            let node = 0;
            const bitCount = bits.length;

            for (let i = 0; i < bitCount; i++) {
                if (node >= this.nodeCount) break;

                const bit = bits[i];
                const record = this.readRecord(node, bit);

                if (record === this.nodeCount) {
                    return null; // Not found
                } else if (record > this.nodeCount) {
                    // Data pointer
                    const offset = (record - this.nodeCount) + this.dataStart - 16;
                    try {
                        const [result] = this.decoder.decode(offset);
                        return result;
                    } catch {
                        return null;
                    }
                }
                node = record;
            }
            return null;
        }

        readRecord(node, bit) {
            const offset = node * this.nodeSize;
            if (this.recordSize === 24) {
                if (bit === 0) {
                    return (this.buf[offset] << 16) | (this.buf[offset + 1] << 8) | this.buf[offset + 2];
                } else {
                    return (this.buf[offset + 3] << 16) | (this.buf[offset + 4] << 8) | this.buf[offset + 5];
                }
            } else if (this.recordSize === 28) {
                if (bit === 0) {
                    return ((this.buf[offset + 3] & 0xF0) << 20) |
                        (this.buf[offset] << 16) | (this.buf[offset + 1] << 8) | this.buf[offset + 2];
                } else {
                    return ((this.buf[offset + 3] & 0x0F) << 24) |
                        (this.buf[offset + 4] << 16) | (this.buf[offset + 5] << 8) | this.buf[offset + 6];
                }
            } else if (this.recordSize === 32) {
                if (bit === 0) {
                    return this.data.getUint32(offset);
                } else {
                    return this.data.getUint32(offset + 4);
                }
            }
            throw new Error(`Unsupported record size: ${this.recordSize}`);
        }
    }

    class MMDBDecoder {
        constructor(buf, pointerBase) {
            this.buf = buf;
            this.pointerBase = pointerBase;
        }

        decode(offset) {
            const ctrlByte = this.buf[offset];
            let type = ctrlByte >> 5;
            offset++;

            if (type === 1) return this.decodePointer(ctrlByte, offset);
            if (type === 0) {
                // Extended type
                type = this.buf[offset] + 7;
                offset++;
            }

            const [size, newOffset] = this.sizeFromCtrl(ctrlByte, offset, type);
            return this.decodeByType(type, newOffset, size);
        }

        sizeFromCtrl(ctrlByte, offset, type) {
            let size = ctrlByte & 0x1F;
            if (type === 1) return [size, offset]; // Pointers handled separately

            if (size < 29) return [size, offset];

            if (size === 29) {
                size = 29 + this.buf[offset];
                return [size, offset + 1];
            }
            if (size === 30) {
                size = 285 + (this.buf[offset] << 8) + this.buf[offset + 1];
                return [size, offset + 2];
            }
            if (size === 31) {
                size = 65821 + (this.buf[offset] << 16) + (this.buf[offset + 1] << 8) + this.buf[offset + 2];
                return [size, offset + 3];
            }
            return [size, offset];
        }

        decodePointer(ctrlByte, offset) {
            const ptrSize = ((ctrlByte >> 3) & 0x03);
            let ptr;
            if (ptrSize === 0) {
                ptr = ((ctrlByte & 0x07) << 8) | this.buf[offset];
                offset += 1;
            } else if (ptrSize === 1) {
                ptr = 2048 + (((ctrlByte & 0x07) << 16) | (this.buf[offset] << 8) | this.buf[offset + 1]);
                offset += 2;
            } else if (ptrSize === 2) {
                ptr = 526336 + (((ctrlByte & 0x07) << 24) | (this.buf[offset] << 16) | (this.buf[offset + 1] << 8) | this.buf[offset + 2]);
                offset += 3;
            } else {
                ptr = ((this.buf[offset] << 24) >>> 0) + ((this.buf[offset + 1] << 16) | (this.buf[offset + 2] << 8) | this.buf[offset + 3]);
                offset += 4;
            }
            const [data] = this.decode(ptr + this.pointerBase);
            return [data, offset];
        }

        decodeByType(type, offset, size) {
            switch (type) {
                case 2: return this.decodeString(offset, size);
                case 3: return this.decodeDouble(offset, size);
                case 4: return this.decodeBytes(offset, size);
                case 5: return this.decodeUint16(offset, size);
                case 6: return this.decodeUint32(offset, size);
                case 7: return this.decodeMap(offset, size);
                case 8: return this.decodeInt32(offset, size);
                case 9: return this.decodeUint64(offset, size);
                case 10: return this.decodeUint128(offset, size);
                case 11: return this.decodeArray(offset, size);
                case 14: return [true, offset]; // Boolean true
                case 15: return [false, offset]; // Boolean false
                default: return [null, offset + size];
            }
        }

        decodeString(offset, size) {
            const bytes = this.buf.slice(offset, offset + size);
            const str = new TextDecoder().decode(bytes);
            return [str, offset + size];
        }

        decodeDouble(offset) {
            const view = new DataView(this.buf.buffer, this.buf.byteOffset + offset, 8);
            return [view.getFloat64(0), offset + 8];
        }

        decodeBytes(offset, size) {
            return [this.buf.slice(offset, offset + size), offset + size];
        }

        decodeUint16(offset, size) {
            return [this.decodeUintGeneric(offset, size), offset + size];
        }

        decodeUint32(offset, size) {
            return [this.decodeUintGeneric(offset, size), offset + size];
        }

        decodeUint64(offset, size) {
            return [this.decodeUintGeneric(offset, size), offset + size];
        }

        decodeUint128(offset, size) {
            return [this.decodeUintGeneric(offset, size), offset + size];
        }

        decodeInt32(offset, size) {
            if (size === 0) return [0, offset];
            const val = this.decodeUintGeneric(offset, size);
            // Sign extension for 32-bit
            if (size === 4 && val > 0x7FFFFFFF) return [val - 0x100000000, offset + size];
            return [val, offset + size];
        }

        decodeUintGeneric(offset, size) {
            let val = 0;
            for (let i = 0; i < size; i++) {
                val = val * 256 + this.buf[offset + i];
            }
            return val;
        }

        decodeMap(offset, size) {
            const map = {};
            for (let i = 0; i < size; i++) {
                const [key, keyEnd] = this.decode(offset);
                const [val, valEnd] = this.decode(keyEnd);
                map[key] = val;
                offset = valEnd;
            }
            return [map, offset];
        }

        decodeArray(offset, size) {
            const arr = [];
            for (let i = 0; i < size; i++) {
                const [val, valEnd] = this.decode(offset);
                arr.push(val);
                offset = valEnd;
            }
            return [arr, offset];
        }
    }

    // ─── IP to bits conversion ───

    function ipToBits(ip) {
        ip = ip.trim();
        if (ip.includes(':')) {
            return ipv6ToBits(ip);
        }
        return ipv4ToBits(ip);
    }

    function ipv4ToBits(ip) {
        const parts = ip.split('.');
        if (parts.length !== 4) return null;
        // IPv4 in MaxMind is stored in IPv6-mapped space
        // We need 128 bits: 80 zeros + 16 ones + 32 bits of IPv4
        const bits = [];
        // 80 zeros
        for (let i = 0; i < 80; i++) bits.push(0);
        // 16 ones
        for (let i = 0; i < 16; i++) bits.push(1);
        // 32 bits of IPv4
        for (const part of parts) {
            const num = parseInt(part, 10);
            if (isNaN(num) || num < 0 || num > 255) return null;
            for (let i = 7; i >= 0; i--) {
                bits.push((num >> i) & 1);
            }
        }
        return bits;
    }

    function ipv6ToBits(ip) {
        // Expand abbreviated IPv6
        let groups = ip.split(':');

        if (ip.includes('::')) {
            const parts = ip.split('::');
            const left = parts[0] ? parts[0].split(':') : [];
            const right = parts[1] ? parts[1].split(':') : [];
            const fill = 8 - left.length - right.length;
            groups = [...left, ...Array(fill).fill('0'), ...right];
        }

        if (groups.length !== 8) return null;

        const bits = [];
        for (const group of groups) {
            const num = parseInt(group || '0', 16);
            for (let i = 15; i >= 0; i--) {
                bits.push((num >> i) & 1);
            }
        }
        return bits;
    }

    // ─── IP Cache ───
    const ipCache = new Map();

    // ─── Public API ───

    const DATABASES = {
        country: { name: 'GeoLite2-Country.mmdb', url: '/data/GeoLite2-Country.mmdb' },
        asn: { name: 'GeoLite2-ASN.mmdb', url: '/data/GeoLite2-ASN.mmdb' },
    };
    const dbState = { country: 'pending', asn: 'pending' };
    const dbError = { country: null, asn: null };
    let initPromise = null;
    const progressListeners = new Set();

    /**
     * Load the two databases. Always resolves: a database that cannot be
     * loaded leaves its lookups at "Unknown" and is reported by status(), so
     * the rest of the analysis still runs. Callers that arrive while a load is
     * running share it, and a later call tries a failed database again.
     *
     * @returns {Promise<{ country: string, asn: string, errors: object }>}
     */
    function init(onProgress) {
        if (countryReader && asnReader) return Promise.resolve(status());
        if (onProgress) progressListeners.add(onProgress);
        if (!initPromise) {
            initPromise = doInit().finally(() => {
                initPromise = null;
                progressListeners.clear();
            });
        }
        return initPromise;
    }

    function reportProgress(pct, msg) {
        for (const listener of progressListeners) {
            try { listener(pct, msg); } catch { /* a listener must not stop the load */ }
        }
    }

    async function doInit() {
        // Fetch metadata with must-revalidate to discover current version without cache staleness
        let meta = null;
        try {
            const metaResp = await fetch('/data/geoip-meta.json', { cache: 'no-cache' });
            if (metaResp.ok) {
                meta = await metaResp.json();
            }
        } catch (err) {
            console.warn('GeoIP: Failed to fetch metadata, falling back to conditional request', err);
        }

        if (!countryReader) countryReader = await loadReader('country', meta, 0);
        reportProgress(50, 'Loading ASN database...');
        if (!asnReader) asnReader = await loadReader('asn', meta, 50);

        initialized = Boolean(countryReader && asnReader);
        ipCache.clear();
        reportProgress(100, initialized ? 'Ready!' : 'Location data is incomplete');
        return status();
    }

    async function loadReader(key, meta, baseProgress) {
        const { name, url } = DATABASES[key];
        const version = meta?.databases?.[name]?.version || meta?.version || '';
        try {
            const reader = await loadDatabase(name, url, reportProgress, baseProgress, version);
            dbState[key] = 'ready';
            dbError[key] = null;
            return reader;
        } catch (e) {
            console.error(`GeoIP: ${name} could not be loaded:`, e);
            dbState[key] = 'failed';
            dbError[key] = e && e.message ? e.message : String(e);
            return null;
        }
    }

    /** Which databases are usable: 'pending' (not tried yet), 'ready' or 'failed'. */
    function status() {
        return { country: dbState.country, asn: dbState.asn, errors: { ...dbError } };
    }

    /**
     * @returns {Promise<MMDBReader>} A reader over a database that was parsed
     *   successfully. Only such a database is ever written to the cache.
     */
    async function loadDatabase(name, url, onProgress, baseProgress, expectedVersion = '') {
        // The cache is an optimisation: a browser without IndexedDB still works.
        let cached = null;
        try {
            cached = await getCached(name);
        } catch (e) {
            console.warn(`GeoIP: cache unavailable for ${name}.`, e);
        }
        // Backward compat: old cache format (raw ArrayBuffer without headers).
        const legacy = cached instanceof ArrayBuffer;
        if (legacy) cached = { data: cached };

        let cachedReader = null;
        if (cached && cached.data) {
            try {
                cachedReader = new MMDBReader(cached.data);
            } catch (e) {
                console.warn(`GeoIP: cached ${name} is unreadable, downloading it again.`, e);
                try { await deleteCached(name); } catch { /* nothing to remove */ }
                cached = null;
            }
        }

        if (cachedReader && legacy) {
            if (onProgress) onProgress(baseProgress + 25, `${name}: loaded from cache`);
            return cachedReader;
        }

        // Fast path: cached database version matches current metadata version (0 network bytes)
        if (cachedReader) {
            if (expectedVersion && cached.version && cached.version === expectedVersion) {
                if (onProgress) onProgress(baseProgress + 25, `${name}: up to date (cached)`);
                return cachedReader;
            }

            // Fallback path: if metadata version is unavailable, check freshness via conditional HEAD
            if (!expectedVersion) {
                try {
                    const headers = { 'User-Agent': 'SysAdmin-Toolkit/2.0' };
                    if (cached.lastModified) headers['If-Modified-Since'] = cached.lastModified;
                    if (cached.etag) headers['If-None-Match'] = cached.etag;

                    const checkResp = await fetch(url, { method: 'HEAD', headers });

                    if (checkResp.status === 304) {
                        if (onProgress) onProgress(baseProgress + 25, `${name}: up to date (cached)`);
                        return cachedReader;
                    }

                    const serverLastModified = checkResp.headers.get('last-modified');
                    const serverEtag = checkResp.headers.get('etag');
                    const unchanged = (cached.etag && serverEtag && cached.etag === serverEtag) ||
                                      (cached.lastModified && serverLastModified && cached.lastModified === serverLastModified);

                    if (unchanged) {
                        if (onProgress) onProgress(baseProgress + 25, `${name}: up to date (cached)`);
                        return cachedReader;
                    }

                    console.info(`GeoIP: ${name} updated on server, downloading new version...`);
                } catch (e) {
                    console.warn(`GeoIP: Freshness check failed for ${name}, using cache.`, e);
                    if (onProgress) onProgress(baseProgress + 25, `${name}: loaded from cache (offline)`);
                    return cachedReader;
                }
            } else {
                console.info(`GeoIP: ${name} version updated (${cached.version || 'none'} -> ${expectedVersion}), downloading new version...`);
            }
        }

        // Append version query parameter so Cloudflare edge caches each database version cleanly
        const downloadUrl = expectedVersion ? `${url}?v=${encodeURIComponent(expectedVersion)}` : url;
        if (onProgress) onProgress(baseProgress + 5, `Downloading ${name}...`);

        let buffer, lastModified, etag, reader;
        try {
            const response = await fetch(downloadUrl);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            // Capture freshness headers for future conditional requests
            lastModified = response.headers.get('last-modified');
            etag = response.headers.get('etag');
            buffer = await readBody(response, name, onProgress, baseProgress);
            // An error page or a cut-off file answers 200 too: only bytes that
            // parse as a database are used, and only those are cached.
            reader = new MMDBReader(buffer);
        } catch (downloadErr) {
            if (cachedReader) {
                console.warn(`GeoIP: Download failed for ${name}, falling back to cache:`, downloadErr);
                if (onProgress) onProgress(baseProgress + 25, `${name}: loaded from cache (update failed)`);
                return cachedReader;
            }
            throw new Error(`Failed to download ${name}: ${downloadErr.message}`);
        }

        try {
            await setCached(name, { data: buffer, lastModified, etag, version: expectedVersion || '' });
            if (onProgress) onProgress(baseProgress + 50, `${name}: cached`);
        } catch (e) {
            console.warn(`GeoIP: ${name} could not be cached.`, e);
        }
        return reader;
    }

    async function readBody(response, name, onProgress, baseProgress) {
        const contentLength = response.headers.get('content-length');
        const total = contentLength ? parseInt(contentLength) : 0;
        let loaded = 0;

        const reader = response.body.getReader();
        const chunks = [];

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            loaded += value.length;
            if (total && onProgress) {
                const filePct = Math.min(45, Math.round((loaded / total) * 45));
                onProgress(baseProgress + 5 + filePct, `${name}: ${Math.round(loaded / 1024)}KB / ${Math.round(total / 1024)}KB`);
            }
        }

        // Combine chunks into single ArrayBuffer
        const combined = new Uint8Array(loaded);
        let offset = 0;
        for (const chunk of chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }
        return combined.buffer;
    }

    function lookupCountry(ip) {
        if (!countryReader) return { country: 'Unknown', country_code: '--' };

        const cacheKey = 'c_' + ip;
        if (ipCache.has(cacheKey)) return ipCache.get(cacheKey);

        try {
            const data = countryReader.lookup(ip);
            const result = {
                country: data?.country?.names?.en || 'Unknown',
                country_code: data?.country?.iso_code || '--',
            };
            ipCache.set(cacheKey, result);
            return result;
        } catch {
            return { country: 'Unknown', country_code: '--' };
        }
    }

    function lookupASN(ip) {
        if (!asnReader) return { asn: 0, asn_org: 'Unknown' };

        const cacheKey = 'a_' + ip;
        if (ipCache.has(cacheKey)) return ipCache.get(cacheKey);

        try {
            const data = asnReader.lookup(ip);
            const result = {
                asn: data?.autonomous_system_number || 0,
                asn_org: data?.autonomous_system_organization || 'Unknown',
            };
            ipCache.set(cacheKey, result);
            return result;
        } catch {
            return { asn: 0, asn_org: 'Unknown' };
        }
    }

    function lookupIP(ip) {
        const country = lookupCountry(ip);
        const asn = lookupASN(ip);
        return { ...country, ...asn };
    }

    function isReady() {
        return initialized;
    }

    function clearCache() {
        ipCache.clear();
    }

    return { init, status, lookupCountry, lookupASN, lookupIP, isReady, clearCache };
})();
window.GeoIP = GeoIP;
