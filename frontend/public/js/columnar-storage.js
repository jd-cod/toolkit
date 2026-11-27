/**
 * Binary Columnar Storage & Dictionary Encoding
 *
 * Stores millions of Nginx log entries in compact parallel TypedArrays
 * with dictionary-encoded unique strings (IPs, URLs, Bots, Countries).
 * Provides sub-50ms binary filter queries and on-demand paginated row slicing.
 */

class ColumnarStorage {
    constructor(initialCapacity = 250000) {
        this.capacity = Math.max(10, initialCapacity);
        this.rowCount = 0;

        // Parallel TypedArrays (compact numeric columns)
        this.col_ip = new Uint32Array(this.capacity);
        this.col_time = new Uint32Array(this.capacity);
        this.col_status = new Uint16Array(this.capacity);
        this.col_bytes = new Float64Array(this.capacity); // responses can exceed 4 GiB
        this.col_url = new Uint32Array(this.capacity);
        this.col_bot = new Uint16Array(this.capacity);
        this.col_country = new Uint16Array(this.capacity);
        this.col_asn = new Uint32Array(this.capacity);
        this.col_method = new Uint8Array(this.capacity);
        // Client (IP + User-Agent) of each row, as numbered by the traffic
        // classifier. Unused until a caller passes a client id to appendRow().
        this.col_client = new Uint32Array(this.capacity);
        // Site of the referrer (see RequestPaths.referrerSite), '-' for none.
        this.col_ref = new Uint32Array(this.capacity);
        this.refDict = [];
        this.refMap = new Map();
        // Protocol version of the request ('HTTP/2.0'), '-' when the line has none.
        this.col_proto = new Uint8Array(this.capacity);
        this.protoDict = [];
        this.protoMap = new Map();
        // True while every row is at or after the one before it, as in a log
        // written by one server. Then newest-first needs no sorting.
        this.timeOrdered = true;
        this._lastTime = 0;
        this._timeOrder = null;
        this.hasClients = false;
        this.clientClass = null;   // Uint8Array: class index per client
        this.clientGroup = null;   // string per client: bot group, '' for humans
        this.clientUa = null;      // (clientId) => User-Agent string
        this.classNames = [];

        // String Dictionaries: Array for ID->String, Map for String->ID
        this.ipDict = [];
        this.ipMap = new Map();

        this.urlDict = [];
        this.urlMap = new Map();

        this.botDict = [];
        this.botMap = new Map();

        this.countryDict = [];
        this.countryMap = new Map();

        this.methodDict = [];
        this.methodMap = new Map();
    }

    _ensureCapacity(needed) {
        if (needed <= this.capacity) return;
        const newCap = Math.max(needed, Math.floor(this.capacity * 1.5));

        const realloc = (oldArr, Type) => {
            const newArr = new Type(newCap);
            newArr.set(oldArr);
            return newArr;
        };

        this.col_ip = realloc(this.col_ip, Uint32Array);
        this.col_time = realloc(this.col_time, Uint32Array);
        this.col_status = realloc(this.col_status, Uint16Array);
        this.col_bytes = realloc(this.col_bytes, Float64Array);
        this.col_url = realloc(this.col_url, Uint32Array);
        this.col_bot = realloc(this.col_bot, Uint16Array);
        this.col_country = realloc(this.col_country, Uint16Array);
        this.col_asn = realloc(this.col_asn, Uint32Array);
        this.col_method = realloc(this.col_method, Uint8Array);
        this.col_client = realloc(this.col_client, Uint32Array);
        this.col_ref = realloc(this.col_ref, Uint32Array);
        this.col_proto = realloc(this.col_proto, Uint8Array);

        this.capacity = newCap;
    }

    _getOrSetId(str, dict, map) {
        const val = str || '-';
        let id = map.get(val);
        if (id === undefined) {
            id = dict.length;
            dict.push(val);
            map.set(val, id);
        }
        return id;
    }

    appendRow(ip, timeSec, status, bytes, url, bot, country, asn, method = '-', clientId, refSite = '', httpVersion = '') {
        this._ensureCapacity(this.rowCount + 1);
        const idx = this.rowCount;

        const time = (timeSec >>> 0) || 0;
        if (time < this._lastTime) this.timeOrdered = false;
        this._lastTime = time;

        this.col_ip[idx] = this._getOrSetId(ip, this.ipDict, this.ipMap);
        this.col_time[idx] = time;
        this.col_status[idx] = (status >>> 0) || 0;
        this.col_bytes[idx] = bytes > 0 ? bytes : 0;
        this.col_url[idx] = this._getOrSetId(url, this.urlDict, this.urlMap);
        this.col_bot[idx] = this._getOrSetId(bot, this.botDict, this.botMap);
        this.col_country[idx] = this._getOrSetId(country, this.countryDict, this.countryMap);
        this.col_asn[idx] = (asn >>> 0) || 0;
        this.col_method[idx] = this._getOrSetId(method || '-', this.methodDict, this.methodMap);
        if (clientId !== undefined) {
            this.col_client[idx] = clientId;
            this.hasClients = true;
        }
        this.col_ref[idx] = this._getOrSetId(refSite, this.refDict, this.refMap);
        // A line can carry any text there; the column holds 255 different ones.
        let proto = this.protoMap.get(httpVersion || '-');
        if (proto === undefined) proto = this.protoDict.length < 255 ? this._getOrSetId(httpVersion, this.protoDict, this.protoMap) : this._getOrSetId('-', this.protoDict, this.protoMap);
        this.col_proto[idx] = proto;

        this.rowCount++;
    }

    /**
     * Row numbers from the oldest request to the newest; requests of the same
     * second stay in the order they were read. Only needed for a log that is
     * not in time order (several files, several servers). Sorted in two
     * passes over the 16-bit halves of the time, so ten million rows take a
     * fraction of a second.
     */
    _rowsByTime() {
        const n = this.rowCount;
        if (this._timeOrder && this._timeOrder.length === n) return this._timeOrder;
        const time = this.col_time;
        let from = new Uint32Array(n);
        let to = new Uint32Array(n);
        for (let i = 0; i < n; i++) from[i] = i;
        const starts = new Uint32Array(65537);
        for (const shift of [0, 16]) {
            starts.fill(0);
            for (let i = 0; i < n; i++) starts[((time[from[i]] >>> shift) & 0xFFFF) + 1]++;
            for (let k = 1; k <= 65536; k++) starts[k] += starts[k - 1];
            for (let i = 0; i < n; i++) {
                const row = from[i];
                to[starts[(time[row] >>> shift) & 0xFFFF]++] = row;
            }
            const swap = from; from = to; to = swap;
        }
        this._timeOrder = from;
        return from;
    }

    /**
     * Attach the traffic class of every client, so rows can be filtered and
     * counted by class.
     *
     * @param {string[]} classNames - Class name for each class index.
     * @param {Uint8Array} clientClass - Class index per client id.
     * @param {string[]} clientGroup - Bot group per client id ('' for humans).
     * @param {(clientId: number) => string} [clientUa] - User-Agent of a client.
     */
    setClientClasses(classNames, clientClass, clientGroup, clientUa) {
        this.classNames = classNames;
        this.clientClass = clientClass;
        this.clientGroup = clientGroup;
        this.clientUa = typeof clientUa === 'function' ? clientUa : null;
    }

    /** Country and network of an address, from the last GeoIP enrichment. */
    ipGeo(ip) {
        const id = this.ipMap.get(ip);
        if (id === undefined || !this.ipCountryIds || !this.ipAsns) return null;
        const code = this.countryDict[this.ipCountryIds[id]] || '--';
        const asn = this.ipAsns[id] || 0;
        return {
            country: this._countryName(code),
            country_code: code,
            asn,
            asn_org: (this.asnOrgMap && this.asnOrgMap[asn]) || 'Unknown',
        };
    }

    /** "Germany" for DE; "Unknown" for an address that has no country. */
    _countryName(code) {
        if (!code || code === '-' || code === '--') return 'Unknown';
        return (this.countryNames && this.countryNames[code]) || code;
    }

    enrichGeo(geoMap = {}) {
        const ipCount = this.ipDict.length;
        const ipCountryIds = new Uint16Array(ipCount);
        const ipAsns = new Uint32Array(ipCount);
        this.asnOrgMap = {};
        this.ipCountryIds = ipCountryIds;
        this.ipAsns = ipAsns;

        for (let id = 0; id < ipCount; id++) {
            const ip = this.ipDict[id];
            const geo = (geoMap instanceof Map ? geoMap.get(ip) : geoMap[ip]) || {};
            const countryCode = geo.country_code || geo.country || '-';
            const asnNum = Number(geo.asn) || 0;

            ipCountryIds[id] = this._getOrSetId(countryCode, this.countryDict, this.countryMap);
            ipAsns[id] = asnNum;

            if (asnNum > 0 && geo.asn_org) {
                this.asnOrgMap[asnNum] = geo.asn_org;
            }
        }

        const total = this.rowCount;
        const col_ip = this.col_ip;
        const col_country = this.col_country;
        const col_asn = this.col_asn;

        for (let i = 0; i < total; i++) {
            const ipId = col_ip[i];
            col_country[i] = ipCountryIds[ipId];
            col_asn[i] = ipAsns[ipId];
        }
    }

    enrichGeoCompact(countryIds, asns, countryDict, asnOrgMap) {
        this.countryDict = countryDict || ['-'];
        this.countryMap = new Map();
        for (let i = 0; i < this.countryDict.length; i++) {
            this.countryMap.set(this.countryDict[i], i);
        }
        this.asnOrgMap = asnOrgMap || {};
        this.ipCountryIds = countryIds;
        this.ipAsns = asns;

        const total = this.rowCount;
        const col_ip = this.col_ip;
        const col_country = this.col_country;
        const col_asn = this.col_asn;

        for (let i = 0; i < total; i++) {
            const ipId = col_ip[i];
            col_country[i] = countryIds[ipId];
            col_asn[i] = asns[ipId];
        }
    }

    enrichGeoCompactIncremental(countryIds, asns, countryDict, asnOrgMap, startIpIndex = 0, startRowIndex = 0) {
        if (countryDict && Array.isArray(countryDict)) {
            if (!this.countryDict) this.countryDict = ['-'];
            if (!this.countryMap) {
                this.countryMap = new Map();
                for (let i = 0; i < this.countryDict.length; i++) {
                    this.countryMap.set(this.countryDict[i], i);
                }
            }
            for (let i = 0; i < countryDict.length; i++) {
                const code = countryDict[i];
                if (!this.countryMap.has(code)) {
                    const newId = this.countryDict.length;
                    this.countryDict.push(code);
                    this.countryMap.set(code, newId);
                }
            }
        }
        if (asnOrgMap) {
            this.asnOrgMap = { ...this.asnOrgMap, ...asnOrgMap };
        }
        this.ipCountryIds = countryIds;
        this.ipAsns = asns;

        const total = this.rowCount;
        const col_ip = this.col_ip;
        const col_country = this.col_country;
        const col_asn = this.col_asn;

        const startIdx = Math.max(0, startRowIndex || 0);
        for (let i = startIdx; i < total; i++) {
            const ipId = col_ip[i];
            col_country[i] = countryIds[ipId] !== undefined ? countryIds[ipId] : 0;
            col_asn[i] = asns[ipId] !== undefined ? asns[ipId] : 0;
        }
    }

    getTopIps(limit = 50, filters = {}) {
        const parsed = this._parseFilters(filters);
        if (parsed === null) return [];
        const matches = parsed.matches;
        const col_client = this.col_client;
        const clientClass = this.clientClass;
        const clientGroup = this.clientGroup;

        const counts = new Uint32Array(this.ipDict.length);
        const total = this.rowCount;
        const col_ip = this.col_ip;
        const col_time = this.col_time;
        const col_status = this.col_status;
        const col_bot = this.col_bot;
        const col_country = this.col_country;
        const col_asn = this.col_asn;

        for (let i = 0; i < total; i++) {
            if (!matches(i)) continue;

            counts[col_ip[i]]++;
        }

        const indices = [];
        for (let id = 0; id < counts.length; id++) {
            if (counts[id] > 0) indices.push(id);
        }
        indices.sort((a, b) => counts[b] - counts[a]);

        return indices.slice(0, limit).map(id => ({
            ip: this.ipDict[id],
            hits: counts[id]
        }));
    }

    _parseFilters(filters = {}) {
        // Address filter: a full address, the start of one, or a CIDR block.
        // Decided once per distinct address, then looked up per row.
        let ipMatch = null;
        const ipQuery = filters.ip || filters.ipSearch;
        if (ipQuery && ipQuery.trim()) {
            const exactId = this.ipMap.get(ipQuery.trim());
            const parser = (typeof LogParser !== 'undefined' && LogParser) || (typeof globalThis !== 'undefined' && globalThis.LogParser) || null;
            const test = parser && parser.ipFilterMatcher ? parser.ipFilterMatcher(ipQuery) : (ip => ip === ipQuery.trim());
            ipMatch = new Uint8Array(this.ipDict.length);
            let any = false;
            for (let id = 0; id < this.ipDict.length; id++) {
                if (id === exactId || test(this.ipDict[id])) { ipMatch[id] = 1; any = true; }
            }
            if (!any) return null; // No address in the log matches -> 0 results
        }

        // Path filter (see RequestPaths.pathMatcher), decided once per distinct URL.
        let urlMatch = null;
        if (filters.pathSearch && String(filters.pathSearch).trim()) {
            const paths = (typeof RequestPaths !== 'undefined' && RequestPaths) || (typeof globalThis !== 'undefined' && globalThis.RequestPaths) || null;
            const term = String(filters.pathSearch).trim().toLowerCase();
            const test = paths ? paths.pathMatcher(filters.pathSearch) : (url => (url || '').toLowerCase().includes(term));
            urlMatch = new Uint8Array(this.urlDict.length);
            let any = false;
            for (let id = 0; id < this.urlDict.length; id++) {
                const url = this.urlDict[id];
                if (url && url !== '-' && test(url)) { urlMatch[id] = 1; any = true; }
            }
            if (!any) return null;
        }

        // User-Agent filter, decided once per client (a client is one address
        // with one User-Agent).
        let uaMatch = null;
        if (filters.uaSearch && String(filters.uaSearch).trim()) {
            if (!this.clientUa || !this.clientClass || !this.hasClients) return null;
            const term = String(filters.uaSearch).trim().toLowerCase();
            uaMatch = new Uint8Array(this.clientClass.length);
            let any = false;
            for (let id = 0; id < uaMatch.length; id++) {
                if ((this.clientUa(id) || '').toLowerCase().includes(term)) { uaMatch[id] = 1; any = true; }
            }
            if (!any) return null;
        }

        let targetMethodId;
        if (filters.method && filters.method !== 'all') {
            targetMethodId = this.methodMap.get(String(filters.method).toUpperCase());
            if (targetMethodId === undefined) targetMethodId = this.methodMap.get(filters.method);
            if (targetMethodId === undefined) {
                // Text that is not a method is kept as sent; match it in any letter case.
                const wanted = String(filters.method).toUpperCase();
                for (const [name, id] of this.methodMap) if (name.toUpperCase() === wanted) { targetMethodId = id; break; }
            }
            if (targetMethodId === undefined) return null;
        }

        // Traffic filter. With classified clients the value is a class
        // ('human', 'verified', ...), 'all_bots', or a bot group name; an
        // optional botGroup narrows a class to one group. Without them it is
        // the bot name stored with each row.
        let targetBotId;
        let classMask = 0;
        let groupName = null;
        if (filters.bot && filters.bot !== 'all') {
            if (this.clientClass && this.hasClients) {
                const classIndex = this.classNames.indexOf(filters.bot);
                if (classIndex !== -1) {
                    classMask = 1 << classIndex;
                } else if (filters.bot === 'all_bots') {
                    const humanIndex = this.classNames.indexOf('human');
                    classMask = ((1 << this.classNames.length) - 1) & ~(humanIndex === -1 ? 0 : (1 << humanIndex));
                } else {
                    groupName = filters.bot;
                }
                if (filters.botGroup) groupName = filters.botGroup;
            } else {
                targetBotId = this.botMap.get(filters.bot);
                if (targetBotId === undefined) return null;
            }
        }

        let targetCountryId;
        let unknownCountryIds = null;
        if (filters.country && filters.country !== 'all') {
            targetCountryId = this.countryMap.get(filters.country);
            if (targetCountryId === undefined && this.countryNames) {
                // The dashboard shows country names; rows hold country codes.
                const code = Object.keys(this.countryNames).find(c => this.countryNames[c] === filters.country);
                if (code !== undefined) targetCountryId = this.countryMap.get(code);
            }
            if (targetCountryId === undefined && filters.country === 'Unknown') {
                // No location data is stored as '-', '--' or an empty code.
                unknownCountryIds = new Set(['-', '--', ''].map(c => this.countryMap.get(c)).filter(id => id !== undefined));
            }
            if (targetCountryId === undefined && !unknownCountryIds) return null;
        }

        let minStatus = 0;
        let maxStatus = 65535;
        // 'other': no status, or a number that is not an HTTP status.
        let otherStatus = false;
        if (filters.statusCategory && filters.statusCategory !== 'all') {
            const cat = String(filters.statusCategory).toLowerCase();
            if (/^[1-5]xx$/.test(cat)) { minStatus = Number(cat[0]) * 100; maxStatus = minStatus + 99; }
            else if (cat === 'other') { otherStatus = true; }
            else {
                const s = Number(cat);
                if (s > 0) { minStatus = s; maxStatus = s; }
            }
        }

        // -1: any network. 0 is a network of its own: addresses without one.
        let targetAsn = -1;
        if (filters.asn !== undefined && filters.asn !== null && filters.asn !== '' && filters.asn !== 'all') {
            const rawAsn = String(filters.asn).replace(/^AS/i, '');
            targetAsn = Number(rawAsn) || 0;
        }

        let minTime = 0;
        let maxTime = 4294967295;
        // "The last 30 minutes" lets requests without a readable time through;
        // a chosen stretch of the timeline does not.
        const keepUntimed = Boolean(filters.keepUntimed);
        if (filters.timeRange && Array.isArray(filters.timeRange)) {
            minTime = filters.timeRange[0] || 0;
            maxTime = filters.timeRange[1] || 4294967295;
        } else {
            if (filters.startTimeSec) minTime = filters.startTimeSec;
            if (filters.endTimeSec) maxTime = filters.endTimeSec;
        }

        const { col_ip, col_bot, col_client, col_country, col_status, col_asn, col_time, col_url, col_method, clientClass, clientGroup } = this;
        const matches = i => {
            if (ipMatch !== null && ipMatch[col_ip[i]] === 0) return false;
            if (urlMatch !== null && urlMatch[col_url[i]] === 0) return false;
            if (uaMatch !== null && uaMatch[col_client[i]] === 0) return false;
            if (targetMethodId !== undefined && col_method[i] !== targetMethodId) return false;
            if (targetBotId !== undefined && col_bot[i] !== targetBotId) return false;
            if (classMask !== 0 && !((classMask >> clientClass[col_client[i]]) & 1)) return false;
            if (groupName !== null && clientGroup[col_client[i]] !== groupName) return false;
            if (targetCountryId !== undefined && col_country[i] !== targetCountryId) return false;
            if (unknownCountryIds && !unknownCountryIds.has(col_country[i])) return false;
            if (col_status[i] < minStatus || col_status[i] > maxStatus) return false;
            if (otherStatus && col_status[i] >= 100 && col_status[i] <= 599) return false;
            if (targetAsn !== -1 && col_asn[i] !== targetAsn) return false;
            if ((col_time[i] < minTime || col_time[i] > maxTime) && !(keepUntimed && col_time[i] === 0)) return false;
            return true;
        };
        return { matches };
    }

    /**
     * Seconds per slot of the rate series: the finest of these steps that
     * keeps the series at 20,000 slots or fewer. Every chart interval the page
     * offers for a span is a multiple of the step chosen for that span.
     */
    /**
     * The value that would be at index `n` if `values` were sorted. Reorders
     * `values`: smaller ones end up left of `n`, larger ones right of it.
     */
    static selectNth(values, n) {
        let left = 0;
        let right = values.length - 1;
        while (left < right) {
            const pivot = values[(left + right) >> 1];
            let i = left;
            let j = right;
            while (i <= j) {
                while (values[i] < pivot) i++;
                while (values[j] > pivot) j--;
                if (i <= j) {
                    const swap = values[i]; values[i] = values[j]; values[j] = swap;
                    i++; j--;
                }
            }
            if (n <= j) right = j;
            else if (n >= i) left = i;
            else break;
        }
        return values[n];
    }

    /**
     * One line with a wrong year would stretch the timeline over years: hours
     * far away from where the log's requests are do not belong to it. From 20
     * requests on, when first and last are more than two days apart.
     *
     * @param {Object<number, number>} hourCounts - Requests per hour, by the start of the hour in seconds.
     * @returns {{ first: number, last: number }|null} First and last hour of the log; null when every hour belongs to it.
     */
    static logHours(hourCounts) {
        const hours = Object.keys(hourCounts).map(Number).sort((x, y) => x - y);
        let timed = 0;
        for (const h of hours) timed += hourCounts[h];
        if (timed < 20 || hours.length < 2 || hours[hours.length - 1] - hours[0] <= 2 * 86400) return null;
        const at = share => {
            let seen = 0;
            for (const h of hours) { seen += hourCounts[h]; if (seen > timed * share) return h; }
            return hours[hours.length - 1];
        };
        const lo = at(0.005), hi = at(0.995);
        const margin = Math.max(hi - lo, 86400);
        let first = null, last = null;
        for (const h of hours) {
            if (h < lo - margin || h > hi + margin) continue;
            if (first === null) first = h;
            last = h;
        }
        return first === null ? null : { first, last };
    }

    /** Addresses listed per country, network and bot group. The count beside the list is not cut. */
    static get IP_DETAIL_LIMIT() { return 100; }

    static rateSeriesBase(minSec, maxSec) {
        const slots = step => Math.floor(maxSec / step) - Math.floor(minSec / step) + 1;
        for (const step of [1, 5, 10, 30, 60, 300, 900, 3600]) {
            if (slots(step) <= 20000) return step;
        }
        return Math.ceil((maxSec - minSec + 1) / 20000 / 3600) * 3600;
    }

    /**
     * Requests per time slot, by status class, of the rows marked in `matched`
     * (see RateSeries in analyzer.js). Rows without a time, or outside
     * minSec..maxSec, are left out.
     */
    _rateSeries(matched, minSec, maxSec) {
        if (!(minSec > 0) || !(maxSec >= minSec)) return null;
        const base = ColumnarStorage.rateSeriesBase(minSec, maxSec);
        const first = Math.floor(minSec / base);
        const slots = Math.floor(maxSec / base) - first + 1;
        const total = new Uint32Array(slots);
        const s2 = new Uint32Array(slots), s3 = new Uint32Array(slots), s4 = new Uint32Array(slots), s5 = new Uint32Array(slots);
        const col_time = this.col_time;
        const col_status = this.col_status;
        let requests = 0, used = 0;
        for (let i = 0; i < this.rowCount; i++) {
            const t = col_time[i];
            if (matched[i] === 0 || t < minSec || t > maxSec) continue;
            const slot = Math.floor(t / base) - first;
            if (total[slot]++ === 0) used++;
            requests++;
            const st = col_status[i];
            if (st >= 200 && st < 300) s2[slot]++;
            else if (st >= 300 && st < 400) s3[slot]++;
            else if (st >= 400 && st < 500) s4[slot]++;
            else if (st >= 500 && st < 600) s5[slot]++;
        }
        // Only slots with requests are passed on.
        const out = { base, times: new Uint32Array(used), total: new Uint32Array(used), s2: new Uint32Array(used), s3: new Uint32Array(used), s4: new Uint32Array(used), s5: new Uint32Array(used), minMs: minSec * 1000, maxMs: maxSec * 1000, requests, stray: 0 };
        for (let slot = 0, k = 0; slot < slots; slot++) {
            if (total[slot] === 0) continue;
            out.times[k] = (first + slot) * base;
            out.total[k] = total[slot]; out.s2[k] = s2[slot]; out.s3[k] = s3[slot]; out.s4[k] = s4[slot]; out.s5[k] = s5[slot];
            k++;
        }
        return out;
    }

    // The busiest referring sites, requests without a referrer ('-'), and
    // how many sites there are in all.
    _referrerSites(refHits) {
        const sites = [];
        let direct = 0;
        for (let id = 0; id < refHits.length; id++) {
            if (refHits[id] === 0) continue;
            if (this.refDict[id] === '-') direct += refHits[id];
            else sites.push([this.refDict[id], refHits[id]]);
        }
        sites.sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
        return { referrerSites: [['-', direct], ...sites.slice(0, 50)], referrerSiteCount: sites.length };
    }

    query(filters = {}) {
        const parsed = this._parseFilters(filters);
        if (parsed === null) {
            return {
                matchingCount: 0,
                uniqueIps: 0,
                totalBytes: 0,
                statusCounts: {},
                botCounts: {},
                countryCounts: {},
                asnHits: {},
                timeBuckets: {}
            };
        }

        const matches = parsed.matches;
        const col_client = this.col_client;
        const clientClass = this.clientClass;
        const clientGroup = this.clientGroup;
        const total = this.rowCount;

        let matchingCount = 0;
        let totalBytes = 0;
        // Requests per address, for the address list and the addresses of
        // each country and network.
        const ipHits = new Uint32Array(this.ipDict.length);
        const ipFirstRow = new Uint32Array(this.ipDict.length);
        let uniqueIps = 0;
        const sizes = new Float64Array(total);
        const hourly = new Array(24).fill(0);
        const daily = new Array(7).fill(0);
        let minTimeSec = 0;
        let maxTimeSec = 0;
        const statusCounts = {};
        const botHits = {};
        const countryHits = {};
        const asnHits = {};
        const methodHits = {};
        const timeBuckets = {};
        // Requests per client, for the caller to turn into traffic classes.
        const clientCounts = (clientClass && this.hasClients) ? new Uint32Array(clientClass.length) : null;
        // Requests per distinct URL, for the caller to turn into paths.
        const urlHits = new Uint32Array(this.urlDict.length);
        const col_url = this.col_url;
        const refHits = new Uint32Array(this.refDict.length);
        const col_ref = this.col_ref;

        const col_ip = this.col_ip;
        const col_time = this.col_time;
        const col_status = this.col_status;
        const col_bytes = this.col_bytes;
        const col_bot = this.col_bot;
        const col_country = this.col_country;
        const col_asn = this.col_asn;
        const col_method = this.col_method;

        const matched = new Uint8Array(total);
        for (let i = 0; i < total; i++) {
            if (!matches(i)) continue;

            matched[i] = 1;
            sizes[matchingCount] = col_bytes[i];
            matchingCount++;
            totalBytes += col_bytes[i];
            if (clientCounts) clientCounts[col_client[i]]++;
            urlHits[col_url[i]]++;
            refHits[col_ref[i]]++;
            if (ipHits[col_ip[i]]++ === 0) { uniqueIps++; ipFirstRow[col_ip[i]] = i; }

            const st = col_status[i];
            statusCounts[st] = (statusCounts[st] || 0) + 1;

            const bId = col_bot[i];
            botHits[bId] = (botHits[bId] || 0) + 1;

            const cId = col_country[i];
            countryHits[cId] = (countryHits[cId] || 0) + 1;

            const mId = col_method[i];
            methodHits[mId] = (methodHits[mId] || 0) + 1;

            const asn = col_asn[i];
            asnHits[asn] = (asnHits[asn] || 0) + 1;

            // Timeline hourly bucket (or 10-minute bucket)
            const t = col_time[i];
            if (t > 0) {
                if (minTimeSec === 0 || t < minTimeSec) minTimeSec = t;
                if (t > maxTimeSec) maxTimeSec = t;
                const bucket = t - (t % 3600);
                timeBuckets[bucket] = (timeBuckets[bucket] || 0) + 1;
                hourly[Math.floor(t / 3600) % 24]++;
                daily[(Math.floor(t / 86400) + 4) % 7]++; // 1 January 1970 was a Thursday
            }
        }

        // Smallest, largest and middle response size of the matching requests.
        let responseSize = { median: 0, min: 0, max: 0 };
        if (matchingCount > 0) {
            const values = sizes.subarray(0, matchingCount);
            let min = values[0], max = values[0];
            for (let i = 1; i < matchingCount; i++) {
                if (values[i] < min) min = values[i];
                else if (values[i] > max) max = values[i];
            }
            const mid = Math.floor(matchingCount / 2);
            const upper = ColumnarStorage.selectNth(values, mid);
            let median = upper;
            if (matchingCount % 2 === 0) {
                // The value just below the middle is the largest one left of it.
                let lower = values[0];
                for (let i = 1; i < mid; i++) if (values[i] > lower) lower = values[i];
                median = Math.round((lower + upper) / 2);
            }
            responseSize = { median, min, max };
        }

        // Hours that do not belong to the log (see logHours) do not count.
        const logHours = ColumnarStorage.logHours(timeBuckets);
        if (logHours) {
            const { first, last } = logHours;
            for (const h of Object.keys(timeBuckets)) if (h < first || h > last) delete timeBuckets[h];
            if (minTimeSec < first || maxTimeSec > last + 3599) {
                // First and last request among those that are left.
                let lowest = 0, highest = 0;
                for (let i = 0; i < total; i++) {
                    const t = col_time[i];
                    if (matched[i] === 0 || t < first || t > last + 3599) continue;
                    if (lowest === 0 || t < lowest) lowest = t;
                    if (t > highest) highest = t;
                }
                minTimeSec = lowest;
                maxTimeSec = highest;
            }
        }
        const rateSeries = this._rateSeries(matched, minTimeSec, maxTimeSec);

        // Map IDs back to dictionary strings
        const botCounts = {};
        for (const [id, count] of Object.entries(botHits)) {
            botCounts[this.botDict[id]] = count;
        }

        const countryCounts = {};
        for (const [id, count] of Object.entries(countryHits)) {
            countryCounts[this.countryDict[id]] = count;
        }

        const methodCounts = {};
        for (const [id, count] of Object.entries(methodHits)) {
            if (this.methodDict[id] !== '-') methodCounts[this.methodDict[id]] = count;
        }

        // Addresses with requests, busiest first; equal counts in the order
        // of their first matching request.
        const activeIps = [];
        for (let id = 0; id < ipHits.length; id++) if (ipHits[id] > 0) activeIps.push(id);
        activeIps.sort((a, b) => ipHits[b] - ipHits[a] || ipFirstRow[a] - ipFirstRow[b]);
        const topIps = activeIps.slice(0, 50).map(id => ({ ip: this.ipDict[id], hits: ipHits[id] }));

        const ipGeoMap = {};
        // Per country code and per network: how many addresses, and the busiest of them.
        const countryIps = {};
        const asnIps = {};
        if (this.ipCountryIds && this.ipAsns) {
            for (let k = 0; k < topIps.length; k++) {
                const id = activeIps[k];
                const cCode = this.countryDict[this.ipCountryIds[id]] || '--';
                const asn = this.ipAsns[id] || 0;
                ipGeoMap[topIps[k].ip] = {
                    country: this._countryName(cCode),
                    country_code: cCode,
                    asn,
                    asn_org: this.asnOrgMap ? (this.asnOrgMap[asn] || 'Unknown') : 'Unknown'
                };
            }
            const note = (groups, key, id) => {
                const group = groups[key] || (groups[key] = { unique_ips: 0, ip_details: [] });
                group.unique_ips++;
                if (group.ip_details.length < ColumnarStorage.IP_DETAIL_LIMIT) group.ip_details.push({ ip: this.ipDict[id], hits: ipHits[id] });
            };
            for (const id of activeIps) {
                note(countryIps, this.countryDict[this.ipCountryIds[id]] || '--', id);
                note(asnIps, this.ipAsns[id] || 0, id);
            }
        }

        return {
            matchingCount,
            uniqueIps,
            totalBytes,
            statusCounts,
            botCounts,
            countryCounts,
            methodCounts,
            asnHits,
            asnOrgMap: this.asnOrgMap || {},
            countryNames: this.countryNames || {},
            ipGeoMap,
            countryIps,
            asnIps,
            topIps,
            responseSize,
            hourly,
            daily,
            timeBuckets,
            ...this._referrerSites(refHits),
            rateSeries,
            minTimeSec,
            maxTimeSec,
            urlHits,
            matchedRows: matched,
            ...(clientCounts ? { clientCounts } : {})
        };
    }

    /**
     * Requests per status for groups of URLs.
     * @param {Uint8Array} matchedRows - From `query`: 1 for each row that passed the filters.
     * @param {Int32Array} groupOfUrl - Group number per URL id, -1 for URLs in no group.
     * @param {number} groupCount
     * @returns {Map<number, number>[]} Hits by status, one map per group.
     */
    statusByUrlGroup(matchedRows, groupOfUrl, groupCount) {
        const out = [];
        for (let g = 0; g < groupCount; g++) out.push(new Map());
        const col_url = this.col_url;
        const col_status = this.col_status;
        const rows = Math.min(this.rowCount, matchedRows.length);
        for (let i = 0; i < rows; i++) {
            if (matchedRows[i] === 0) continue;
            const group = groupOfUrl[col_url[i]];
            if (group < 0) continue;
            const statuses = out[group];
            statuses.set(col_status[i], (statuses.get(col_status[i]) || 0) + 1);
        }
        return out;
    }

    getPage(pageNumber = 1, pageSize = 50, filters = {}) {
        const parsed = this._parseFilters(filters);
        const page = Math.max(1, pageNumber);
        const size = Math.max(1, pageSize);

        if (parsed === null) {
            return { rows: [], totalRows: 0, page, totalPages: 0, pageSize: size };
        }

        const matches = parsed.matches;
        const col_client = this.col_client;
        const clientClass = this.clientClass;
        const clientGroup = this.clientGroup;
        const total = this.rowCount;
        const startIndex = (page - 1) * size;
        const endIndex = startIndex + size;
        const knownTotal = Number.isInteger(filters.totalRows) ? filters.totalRows : (Number.isInteger(filters.totalMatching) ? filters.totalMatching : -1);

        let matchedCount = 0;
        const rows = [];

        const col_ip = this.col_ip;
        const col_time = this.col_time;
        const col_status = this.col_status;
        const col_bytes = this.col_bytes;
        const col_url = this.col_url;
        const col_bot = this.col_bot;
        const col_country = this.col_country;
        const col_asn = this.col_asn;
        const col_method = this.col_method;
        const col_proto = this.col_proto;

        // 'newest': latest request first, and of two in the same second the
        // one read later. Otherwise the order the lines were read in.
        const newestFirst = filters.order === 'newest';
        const byTime = newestFirst && !this.timeOrdered ? this._rowsByTime() : null;

        for (let at = 0; at < total; at++) {
            const i = newestFirst ? (byTime ? byTime[total - 1 - at] : total - 1 - at) : at;
            if (!matches(i)) continue;

            if (matchedCount >= startIndex && matchedCount < endIndex) {
                const countryCode = this.countryDict[col_country[i]];
                const hasCountry = countryCode && countryCode !== '-' && countryCode !== '--';
                const proto = this.protoDict[col_proto[i]];
                const row = {
                    ip: this.ipDict[col_ip[i]],
                    timeSec: col_time[i],
                    timestamp: col_time[i] > 0 ? col_time[i] * 1000 : null,
                    status_code: col_status[i],
                    bytes: col_bytes[i],
                    method: this.methodDict[col_method[i]] || '-',
                    url: this.urlDict[col_url[i]],
                    http_version: proto && proto !== '-' ? proto : null,
                    bot: this.botDict[col_bot[i]],
                    country: this._countryName(countryCode),
                    country_code: hasCountry ? countryCode : '--',
                    asn: col_asn[i],
                };
                if (clientClass && this.hasClients) {
                    const clientId = col_client[i];
                    row.traffic_class = this.classNames[clientClass[clientId]];
                    row.bot_group = clientGroup[clientId] || null;
                    if (this.clientUa) row.user_agent = this.clientUa(clientId) || '-';
                }
                rows.push(row);
                if (rows.length >= size && knownTotal >= 0) {
                    matchedCount = knownTotal;
                    break;
                }
            }
            matchedCount++;
        }

        const effectiveTotal = knownTotal >= 0 ? knownTotal : matchedCount;
        const totalPages = Math.ceil(effectiveTotal / size) || 1;

        return {
            page,
            pageSize: size,
            totalPages,
            totalRows: effectiveTotal,
            rows
        };
    }
}

// Universal export: CommonJS (Node.js tests) and Worker/Browser global (importScripts / <script>)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ColumnarStorage };
}
if (typeof self !== 'undefined') {
    self.ColumnarStorage = ColumnarStorage;
}
if (typeof window !== 'undefined') {
    window.ColumnarStorage = ColumnarStorage;
}
