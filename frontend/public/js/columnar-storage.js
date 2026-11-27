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

    appendRow(ip, timeSec, status, bytes, url, bot, country, asn, method = '-', clientId) {
        this._ensureCapacity(this.rowCount + 1);
        const idx = this.rowCount;

        this.col_ip[idx] = this._getOrSetId(ip, this.ipDict, this.ipMap);
        this.col_time[idx] = (timeSec >>> 0) || 0;
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

        this.rowCount++;
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
            country: code,
            country_code: code,
            asn,
            asn_org: (this.asnOrgMap && this.asnOrgMap[asn]) || 'Unknown',
        };
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

        let targetMethodId;
        if (filters.method && filters.method !== 'all') {
            targetMethodId = this.methodMap.get(String(filters.method).toUpperCase());
            if (targetMethodId === undefined) targetMethodId = this.methodMap.get(filters.method);
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
        if (filters.statusCategory && filters.statusCategory !== 'all') {
            const cat = String(filters.statusCategory).toLowerCase();
            if (cat === '2xx') { minStatus = 200; maxStatus = 299; }
            else if (cat === '3xx') { minStatus = 300; maxStatus = 399; }
            else if (cat === '4xx') { minStatus = 400; maxStatus = 499; }
            else if (cat === '5xx') { minStatus = 500; maxStatus = 599; }
            else {
                const s = Number(cat);
                if (s > 0) { minStatus = s; maxStatus = s; }
            }
        }

        let targetAsn = 0;
        if (filters.asn && filters.asn !== 'all') {
            const rawAsn = String(filters.asn).replace(/^AS/i, '');
            targetAsn = Number(rawAsn) || 0;
        }

        let minTime = 0;
        let maxTime = 4294967295;
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
            if (targetMethodId !== undefined && col_method[i] !== targetMethodId) return false;
            if (targetBotId !== undefined && col_bot[i] !== targetBotId) return false;
            if (classMask !== 0 && !((classMask >> clientClass[col_client[i]]) & 1)) return false;
            if (groupName !== null && clientGroup[col_client[i]] !== groupName) return false;
            if (targetCountryId !== undefined && col_country[i] !== targetCountryId) return false;
            if (unknownCountryIds && !unknownCountryIds.has(col_country[i])) return false;
            if (col_status[i] < minStatus || col_status[i] > maxStatus) return false;
            if (targetAsn !== 0 && col_asn[i] !== targetAsn) return false;
            if (col_time[i] < minTime || col_time[i] > maxTime) return false;
            return true;
        };
        return { matches };
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
        const ipSeen = new Uint8Array(this.ipDict.length);
        let uniqueIps = 0;
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

        const col_ip = this.col_ip;
        const col_time = this.col_time;
        const col_status = this.col_status;
        const col_bytes = this.col_bytes;
        const col_bot = this.col_bot;
        const col_country = this.col_country;
        const col_asn = this.col_asn;
        const col_method = this.col_method;

        for (let i = 0; i < total; i++) {
            if (!matches(i)) continue;

            matchingCount++;
            totalBytes += col_bytes[i];
            if (clientCounts) clientCounts[col_client[i]]++;
            urlHits[col_url[i]]++;
            const ipId = col_ip[i];
            if (ipSeen[ipId] === 0) {
                ipSeen[ipId] = 1;
                uniqueIps++;
            }

            const st = col_status[i];
            statusCounts[st] = (statusCounts[st] || 0) + 1;

            const bId = col_bot[i];
            botHits[bId] = (botHits[bId] || 0) + 1;

            const cId = col_country[i];
            countryHits[cId] = (countryHits[cId] || 0) + 1;

            const mId = col_method[i];
            methodHits[mId] = (methodHits[mId] || 0) + 1;

            const asn = col_asn[i];
            if (asn > 0) {
                asnHits[asn] = (asnHits[asn] || 0) + 1;
            }

            // Timeline hourly bucket (or 10-minute bucket)
            const t = col_time[i];
            if (t > 0) {
                if (minTimeSec === 0 || t < minTimeSec) minTimeSec = t;
                if (t > maxTimeSec) maxTimeSec = t;
                const bucket = t - (t % 3600);
                timeBuckets[bucket] = (timeBuckets[bucket] || 0) + 1;
            }
        }

        // One line with a wrong year would stretch the timeline over years:
        // hours far away from where the log's requests are do not count.
        const hours = Object.keys(timeBuckets).map(Number).sort((x, y) => x - y);
        if (hours.length > 2 && hours[hours.length - 1] - hours[0] > 2 * 86400) {
            let timed = 0;
            for (const h of hours) timed += timeBuckets[h];
            const at = share => {
                let seen = 0;
                for (const h of hours) { seen += timeBuckets[h]; if (seen > timed * share) return h; }
                return hours[hours.length - 1];
            };
            const lo = at(0.005), hi = at(0.995);
            const margin = Math.max(hi - lo, 86400);
            let first = null, last = null;
            for (const h of hours) {
                if (h < lo - margin || h > hi + margin) { delete timeBuckets[h]; continue; }
                if (first === null) first = h;
                last = h;
            }
            if (first !== null) {
                if (minTimeSec < first) minTimeSec = first;
                if (maxTimeSec > last + 3599) maxTimeSec = last + 3599;
            }
        }

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

        const topIps = this.getTopIps(50, filters);
        const ipGeoMap = {};
        if (this.ipCountryIds && this.ipAsns) {
            for (let k = 0; k < topIps.length; k++) {
                const item = topIps[k];
                const id = this.ipMap.get(item.ip);
                if (id !== undefined) {
                    const cId = this.ipCountryIds[id];
                    const cCode = this.countryDict[cId] || '--';
                    const asn = this.ipAsns[id] || 0;
                    const asnOrg = this.asnOrgMap ? (this.asnOrgMap[asn] || 'Unknown') : 'Unknown';
                    ipGeoMap[item.ip] = {
                        country: cCode,
                        country_code: cCode,
                        asn,
                        asn_org: asnOrg
                    };
                }
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
            topIps,
            timeBuckets,
            minTimeSec,
            maxTimeSec,
            urlHits,
            ...(clientCounts ? { clientCounts } : {})
        };
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

        for (let i = 0; i < total; i++) {
            if (!matches(i)) continue;

            if (matchedCount >= startIndex && matchedCount < endIndex) {
                const row = {
                    ip: this.ipDict[col_ip[i]],
                    timeSec: col_time[i],
                    status: col_status[i],
                    bytes: col_bytes[i],
                    method: this.methodDict[col_method[i]] || '-',
                    url: this.urlDict[col_url[i]],
                    bot: this.botDict[col_bot[i]],
                    country: this.countryDict[col_country[i]],
                    asn: col_asn[i],
                    // Names the Log Explorer reads, shared with in-memory entries.
                    timestamp: col_time[i] > 0 ? col_time[i] * 1000 : null,
                    status_code: col_status[i]
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
