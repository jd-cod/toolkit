/**
 * SysAdmin Toolkit — Nginx Log Analyzer
 * Geolocation World Map Module (geomap.js)
 *
 * Visualizes geographic origin of incoming traffic on an interactive SVG world map.
 * Features:
 *  - Size-scaled traffic volume dots (radar bubbles)
 *  - Heatmap (choropleth) region shading
 *  - Threat & error severity view
 *  - Rich sysadmin tooltips
 *  - 1-click drill-down filtering
 *  - 100% client-side & offline with zero external API dependencies
 */

(function (window) {
    'use strict';

    // Comprehensive ISO-2 to [latitude, longitude] lookup dictionary
    const COUNTRY_COORDS = {
        'US': [37.0902, -95.7129], 'CA': [56.1304, -106.3468], 'MX': [23.6345, -102.5528],
        'BR': [-14.2350, -51.9253], 'AR': [-38.4161, -63.6167], 'CL': [-35.6751, -71.5430],
        'CO': [4.5709, -74.2973], 'PE': [-9.1899, -75.0152], 'VE': [6.4238, -66.5897],
        'EC': [-1.8312, -78.1834], 'GT': [15.7835, -90.2308], 'CU': [21.5218, -77.7812],
        'DO': [18.7357, -70.1627], 'HN': [15.1999, -86.2419], 'PY': [-23.4425, -58.4438],
        'NI': [12.8654, -85.2072], 'SV': [13.7942, -88.8965], 'CR': [9.7489, -83.7534],
        'PA': [8.5380, -80.7821], 'UY': [-32.5228, -55.7658], 'JM': [18.1096, -77.2975],
        'TT': [10.6918, -61.2225], 'BO': [-16.2902, -63.5887], 'GY': [4.8604, -58.9302],
        'SR': [3.9193, -56.0278], 'BZ': [17.1899, -88.4976], 'BS': [25.0343, -77.3963],
        'HT': [18.9712, -72.2852],

        // Europe
        'GB': [55.3781, -3.4360], 'DE': [51.1657, 10.4515], 'FR': [46.2276, 2.2137],
        'IT': [41.8719, 12.5674], 'ES': [40.4637, -3.7492], 'NL': [52.1326, 5.2913],
        'RU': [61.5240, 105.3188], 'UA': [48.3794, 31.1656], 'PL': [51.9194, 19.1451],
        'RO': [45.9432, 24.9668], 'BE': [50.5039, 4.4699], 'CZ': [49.8175, 15.4730],
        'GR': [39.0742, 21.8243], 'PT': [39.3999, -8.2245], 'SE': [60.1282, 18.6435],
        'HU': [47.1625, 19.5033], 'BY': [53.7098, 27.9534], 'AT': [47.5162, 14.5501],
        'CH': [46.8182, 8.2275], 'BG': [42.7339, 25.4858], 'DK': [56.2639, 9.5018],
        'FI': [61.9241, 25.7482], 'SK': [48.6690, 19.6990], 'NO': [60.4720, 8.4689],
        'IE': [53.1424, -7.6921], 'HR': [45.1000, 15.2000], 'MD': [47.4116, 28.3699],
        'BA': [43.9159, 17.6791], 'AL': [41.1533, 20.1683], 'LT': [55.1694, 23.8813],
        'MK': [41.6086, 21.7453], 'SI': [46.1512, 14.9955], 'LV': [56.8796, 24.6032],
        'EE': [58.5953, 25.0136], 'ME': [42.7087, 19.3744], 'LU': [49.8153, 6.1296],
        'MT': [35.9375, 14.3754], 'IS': [64.9631, -19.0208], 'CY': [35.1264, 33.4299],
        'RS': [44.0165, 21.0059], 'XK': [42.6026, 20.9030],

        // Asia & Middle East
        'CN': [35.8617, 104.1954], 'IN': [20.5937, 78.9629], 'ID': [-0.7893, 113.9213],
        'PK': [30.3753, 69.3451], 'BD': [23.6850, 90.3563], 'JP': [36.2048, 138.2529],
        'PH': [12.8797, 121.7740], 'VN': [14.0583, 108.2772], 'TR': [38.9637, 35.2433],
        'IR': [32.4279, 53.6880], 'TH': [15.8700, 100.9925], 'MM': [21.9162, 95.9560],
        'KR': [35.9078, 127.7669], 'IQ': [33.2232, 43.6793], 'AF': [33.9391, 67.7100],
        'SA': [23.8859, 45.0792], 'UZ': [41.3775, 64.5853], 'MY': [4.2105, 101.9758],
        'YE': [15.5527, 48.5164], 'NP': [28.3949, 84.1240], 'TW': [23.6978, 120.9605],
        'SY': [34.8021, 38.9968], 'LK': [7.8731, 80.7718], 'KZ': [48.0196, 66.9237],
        'KH': [12.5657, 104.9910], 'AZ': [40.1431, 47.5769], 'TJ': [38.8610, 71.2761],
        'AE': [23.4241, 53.8478], 'IL': [31.0461, 34.8516], 'JO': [30.5852, 36.2384],
        'GE': [42.3154, 43.3569], 'KG': [41.2044, 74.7661], 'LA': [19.8563, 102.4955],
        'LB': [33.8547, 35.8623], 'OM': [21.5126, 55.9233], 'KW': [29.3117, 47.4818],
        'MN': [46.8625, 103.8467], 'AM': [40.0691, 45.0382], 'QA': [25.3548, 51.1839],
        'BH': [26.0667, 50.5577], 'SG': [1.3521, 103.8198], 'HK': [22.3193, 114.1694],
        'PS': [31.9522, 35.2332],

        // Africa
        'NG': [9.0820, 8.6753], 'ET': [9.1450, 40.4897], 'EG': [26.8206, 30.8025],
        'CD': [-4.0383, 21.7587], 'TZ': [-6.3690, 34.8888], 'ZA': [-30.5595, 22.9375],
        'KE': [-0.0236, 37.9062], 'UG': [1.3733, 32.2903], 'SD': [12.8628, 30.2176],
        'DZ': [28.0339, 1.6596], 'MA': [31.7917, -7.0926], 'AO': [-11.2027, 17.8739],
        'GH': [7.9465, -1.0232], 'MZ': [-18.6657, 35.5296], 'MG': [-18.7669, 46.8691],
        'CI': [7.5400, -5.5471], 'CM': [7.3697, 12.3547], 'NE': [17.6078, 8.0817],
        'BF': [12.2383, -1.5616], 'ML': [17.5707, -3.9962], 'MW': [-13.2543, 34.3015],
        'ZM': [-13.1339, 27.8493], 'SN': [14.4974, -14.4524], 'TD': [15.4542, 18.7322],
        'SO': [5.1521, 46.1996], 'ZW': [-19.0154, 29.1549], 'GN': [9.9456, -9.6966],
        'RW': [-1.9403, 29.8739], 'BJ': [9.3077, 2.3158], 'TN': [33.8869, 9.5375],
        'LY': [26.3351, 17.2283], 'CG': [-0.2280, 15.8277], 'LR': [6.4281, -9.4295],
        'NA': [-22.9576, 18.4904], 'BW': [-22.3285, 24.6849], 'GA': [-0.8037, 11.6094],
        'MU': [-20.3484, 57.5522],

        // Oceania
        'AU': [-25.2744, 133.7751], 'PG': [-6.3150, 143.9555], 'NZ': [-40.9006, 174.8860],
        'FJ': [-17.7134, 178.0650], 'SB': [-9.6457, 160.1562], 'VU': [-15.3767, 166.9592],
    };

    let activeMapInstance = null;
    let currentMode = 'dots'; // 'dots' | 'choropleth' | 'threats'
    let lastData = null;
    let onCountrySelectCallback = null;

    function getCountryCoords(code) {
        if (code && COUNTRY_COORDS[code.toUpperCase()]) {
            return COUNTRY_COORDS[code.toUpperCase()];
        }
        return null;
    }

    /**
     * Compute visual markers and metadata from analysis data.
     */
    function computeGeoData(data) {
        if (!data || !data.country_hits || data.country_hits.length === 0) {
            return { markers: [], regionsData: {}, topCountries: [], hasGeolocatedTraffic: false };
        }

        const totalRequests = data.total_requests || 1;
        const validHits = data.country_hits.filter(c => c.country_code && c.country_code !== '--' && c.country !== 'Unknown');

        if (validHits.length === 0) {
            return { markers: [], regionsData: {}, topCountries: [], hasGeolocatedTraffic: false };
        }

        const maxHits = Math.max(...validHits.map(c => c.hits), 1);
        const markers = [];
        const regionsData = {};

        // Calculate threat/error proportion per country if available from ip details or security metrics
        validHits.forEach(c => {
            const coords = getCountryCoords(c.country_code);
            if (!coords) return;

            const pct = (c.hits / totalRequests * 100).toFixed(1);
            const ratio = Math.log10(c.hits + 1) / Math.log10(maxHits + 1);
            // Logarithmic radius scale between 6 and 18
            const radius = Math.round(6 + ratio * 12);

            // Compute threat level based on known scanner activity or error status
            let threatScore = 0;
            if (c.ip_details && c.ip_details.length > 0) {
                // If the country has concentrated traffic or suspicious hits
                threatScore = Math.min(100, Math.round(ratio * 70));
            }

            // Colors based on view mode
            let dotColor = '#06b6d4'; // Cyan default

            if (currentMode === 'threats') {
                if (pct > 30 || ratio > 0.7) {
                    dotColor = '#f43f5e'; // Rose / high alert
                } else if (ratio > 0.3) {
                    dotColor = '#f59e0b'; // Amber / medium
                } else {
                    dotColor = '#10b981'; // Emerald / normal
                }
            } else if (currentMode === 'choropleth') {
                dotColor = '#a855f7'; // Purple / indigo
            } else {
                // Default Dots mode
                if (ratio > 0.5) {
                    dotColor = '#38bdf8'; // Sky blue
                } else {
                    dotColor = '#6366f1'; // Indigo
                }
            }

            markers.push({
                name: c.country,
                code: c.country_code.toUpperCase(),
                coords: coords,
                hits: c.hits,
                pct: pct,
                unique_ips: c.unique_ips,
                threatScore: threatScore,
                style: {
                    r: radius,
                    fill: dotColor,
                    stroke: '#ffffff',
                    strokeWidth: ratio > 0.5 ? 2 : 1.2,
                    fillOpacity: 0.92,
                }
            });

            // Region heat value for choropleth (0 to 100)
            regionsData[c.country_code.toUpperCase()] = Math.min(100, Math.round((c.hits / maxHits) * 100));
        });

        return {
            markers,
            regionsData,
            topCountries: validHits.slice(0, 8),
            hasGeolocatedTraffic: markers.length > 0,
            maxHits,
            totalHits: validHits.reduce((acc, c) => acc + c.hits, 0),
        };
    }

    /**
     * Build custom HTML tooltip for country marker or region.
     */
    function buildTooltipHtml(item) {
        if (!item) return '';
        const flag = item.code || '--';
        return `
            <div class="geomap-tooltip-content">
                <div class="geomap-tooltip-header">
                    <span class="country-flag">${escapeHtml(flag)}</span>
                    <strong style="color:var(--text-primary);font-size:0.88rem;">${escapeHtml(item.name || 'Unknown')}</strong>
                </div>
                <div class="geomap-tooltip-body">
                    <div class="geomap-tt-row">
                        <span class="tt-lbl"><i class="bi bi-bar-chart-line-fill" style="color:var(--accent-cyan);margin-right:4px;"></i>Traffic:</span>
                        <span class="tt-val font-mono" style="font-weight:700;color:var(--accent-cyan);">${numberWithCommas(item.hits || 0)} <span style="font-size:0.75rem;opacity:0.85;">(${item.pct || 0}%)</span></span>
                    </div>
                    <div class="geomap-tt-row">
                        <span class="tt-lbl"><i class="bi bi-hdd-network-fill" style="color:var(--accent-indigo);margin-right:4px;"></i>Unique IPs:</span>
                        <span class="tt-val font-mono">${numberWithCommas(item.unique_ips || 0)}</span>
                    </div>
                    ${item.threatScore > 0 ? `
                    <div class="geomap-tt-row">
                        <span class="tt-lbl"><i class="bi bi-shield-exclamation" style="color:var(--accent-amber);margin-right:4px;"></i>Activity:</span>
                        <span class="tt-val font-mono" style="color:var(--accent-amber);">${item.threatScore > 50 ? 'High Volume' : 'Active Traffic'}</span>
                    </div>
                    ` : ''}
                </div>
                <div class="geomap-tooltip-footer">
                    <i class="bi bi-funnel-fill" style="margin-right:4px;color:var(--accent-cyan);"></i>Click to filter dashboard
                </div>
            </div>
        `;
    }

    /**
     * Initialize or update the interactive world map.
     */
    function init(selector, data, options = {}) {
        const container = typeof selector === 'string' ? document.querySelector(selector) : selector;
        if (!container) return;

        lastData = data;
        if (options.onCountrySelect) {
            onCountrySelectCallback = options.onCountrySelect;
        }

        const geo = computeGeoData(data);

        // Fallback for private or unresolvable traffic
        if (!geo.hasGeolocatedTraffic) {
            destroy();
            container.innerHTML = `
                <div class="geomap-empty-state">
                    <div class="geomap-empty-icon"><i class="bi bi-globe-americas"></i></div>
                    <h5 style="margin:0 0 6px 0;font-weight:700;color:var(--text-primary);">No Geolocatable Traffic</h5>
                    <p style="margin:0;font-size:0.84rem;color:var(--text-muted);max-width:440px;">
                        All logged requests originated from private network addresses (e.g. 127.0.0.1, 10.x.x.x, 192.168.x.x) or non-routable IP ranges.
                    </p>
                </div>
            `;
            return;
        }

        // Clean previous instance
        destroy();
        container.innerHTML = '';

        if (typeof window.jsVectorMap === 'undefined') {
            container.innerHTML = `<div style="padding:2rem;text-align:center;color:var(--text-muted);">Vector map library not loaded.</div>`;
            return;
        }

        const isChoropleth = currentMode === 'choropleth';
        const isThreats = currentMode === 'threats';

        try {
            activeMapInstance = new window.jsVectorMap({
                selector: selector,
                map: 'world',
                backgroundColor: 'transparent',
                draggable: true,
                zoomButtons: true,
                zoomOnScroll: false,
                zoomMax: 12,
                zoomMin: 1,
                focusOn: {
                    regions: Object.keys(geo.regionsData).slice(0, 5),
                    animate: true,
                },
                regionStyle: {
                    initial: {
                        fill: document.documentElement.getAttribute('data-theme') === 'light' ? '#dce5ed' : (isChoropleth ? '#141a2e' : '#161d31'),
                        stroke: '#283252',
                        strokeWidth: 0.6,
                        fillOpacity: 1,
                    },
                    hover: {
                        fillOpacity: 0.8,
                        stroke: '#38bdf8',
                        strokeWidth: 1.2,
                        cursor: 'pointer',
                    },
                    selected: {
                        fill: '#6366f1',
                    }
                },
                markers: geo.markers,
                markerStyle: {
                    initial: {
                        fill: '#06b6d4',
                        stroke: '#ffffff',
                        strokeWidth: 1.5,
                        cursor: 'pointer',
                    },
                    hover: {
                        fill: '#f59e0b',
                        stroke: '#ffffff',
                        strokeWidth: 2.2,
                        cursor: 'pointer',
                    }
                },
                onLoaded: function (map) {
                    // Apply mode-specific region styling directly to SVG elements
                    for (const [code, val] of Object.entries(geo.regionsData)) {
                        if (map.regions && map.regions[code]) {
                            let fillColor;
                            if (isThreats) {
                                // Rose/red for high threat volume, amber for medium, emerald for standard
                                fillColor = val > 60 ? '#f43f5e' : (val > 25 ? '#f59e0b' : '#10b981');
                            } else if (isChoropleth) {
                                // Cyan to deep indigo gradient based on volume
                                fillColor = val > 75 ? '#06b6d4' : (val > 45 ? '#6366f1' : (val > 20 ? '#4338ca' : '#283354'));
                            } else {
                                // Default dots mode: subtle highlighted landmass under dots
                                fillColor = '#1d2745';
                            }
                            map.regions[code].element.setStyle('fill', fillColor);
                        }
                    }
                },
                onRegionTooltipShow: function (event, tooltip, code) {
                    const countryHit = (data.country_hits || []).find(c => c.country_code && c.country_code.toUpperCase() === code.toUpperCase());
                    if (countryHit) {
                        const totalReq = data.total_requests || 1;
                        const pct = (countryHit.hits / totalReq * 100).toFixed(1);
                        tooltip.text(buildTooltipHtml({
                            name: countryHit.country,
                            code: code,
                            hits: countryHit.hits,
                            pct: pct,
                            unique_ips: countryHit.unique_ips,
                            threatScore: currentMode === 'threats' ? 75 : 0
                        }), true);
                    } else {
                        tooltip.text(`<div style="padding:4px 8px;font-size:0.75rem;color:#94a3b8;">${tooltip.text()} (0 requests)</div>`, true);
                    }
                },
                onMarkerTooltipShow: function (event, tooltip, index) {
                    const marker = geo.markers[index];
                    if (marker) {
                        tooltip.text(buildTooltipHtml(marker), true);
                    }
                },
                onMarkerClick: function (event, index) {
                    const marker = geo.markers[index];
                    if (marker && onCountrySelectCallback) {
                        onCountrySelectCallback(marker.name, marker.code);
                    }
                },
                onRegionClick: function (event, code) {
                    const countryHit = (data.country_hits || []).find(c => c.country_code && c.country_code.toUpperCase() === code.toUpperCase());
                    if (countryHit && onCountrySelectCallback) {
                        onCountrySelectCallback(countryHit.country, countryHit.country_code);
                    }
                }
            });
        } catch (err) {
            console.error('[TrafficGeoMap] Failed to initialize jsVectorMap:', err);
            container.innerHTML = `<div style="padding:2rem;text-align:center;color:var(--text-muted);">Error rendering world map: ${escapeHtml(err.message)}</div>`;
        }
    }

    /**
     * Destroy the existing map instance cleanly.
     */
    function destroy() {
        if (activeMapInstance) {
            try {
                if (typeof activeMapInstance.destroy === 'function') {
                    activeMapInstance.destroy();
                }
            } catch {
                // Ignore destruction error
            }
            activeMapInstance = null;
        }
    }

    /**
     * Switch map visualization mode: 'dots' | 'choropleth' | 'threats'
     */
    function setMode(mode, selector) {
        if (currentMode === mode) return;
        currentMode = mode;
        if (lastData) {
            init(selector || '#traffic-world-map', lastData);
        }
    }

    /**
     * Reset zoom and pan to global view.
     */
    function resetView() {
        if (activeMapInstance && typeof activeMapInstance.reset === 'function') {
            activeMapInstance.reset();
        }
    }

    function getMode() {
        return currentMode;
    }

    function numberWithCommas(x) {
        if (x === null || x === undefined) return '0';
        return x.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Export to global scope
    window.TrafficGeoMap = {
        init: init,
        update: init,
        destroy: destroy,
        setMode: setMode,
        getMode: getMode,
        resetView: resetView,
        resize: () => activeMapInstance?.updateSize?.(),
        computeGeoData: computeGeoData,
        COUNTRY_COORDS: COUNTRY_COORDS,
    };

})(typeof window !== 'undefined' ? window : this);
