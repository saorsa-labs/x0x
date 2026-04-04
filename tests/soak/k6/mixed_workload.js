// Mixed workload soak test — realistic blend of all endpoint categories.
//
// Usage: k6 run --env X0X_API=http://127.0.0.1:12700 --env X0X_TOKEN=<token> mixed_workload.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.X0X_API || 'http://127.0.0.1:12700';
const TOKEN = __ENV.X0X_TOKEN || '';

const errorRate = new Rate('errors');
const apiLatency = new Trend('api_latency');

export const options = {
    scenarios: {
        mixed: {
            executor: 'constant-arrival-rate',
            rate: 8,
            timeUnit: '1s',
            duration: __ENV.DURATION || '1h',
            preAllocatedVUs: 5,
            maxVUs: 15,
        },
    },
    thresholds: {
        http_req_duration: ['p(95) < 300', 'p(99) < 800'],
        errors: ['rate < 0.02'],
        api_latency: ['p(95) < 250'],
    },
};

const headers = {
    'Content-Type': 'application/json',
    ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
};

const getHeaders = TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {};

// Weighted endpoint selection — mirrors realistic usage patterns
const endpoints = [
    { weight: 20, fn: healthCheck },
    { weight: 15, fn: agentIdentity },
    { weight: 10, fn: listPeers },
    { weight: 10, fn: presenceOnline },
    { weight: 10, fn: listContacts },
    { weight: 10, fn: listGroups },
    { weight: 10, fn: listStores },
    { weight: 5, fn: networkStatus },
    { weight: 5, fn: discoveredAgents },
    { weight: 5, fn: wsSessions },
];

// Build cumulative weights
const totalWeight = endpoints.reduce((sum, e) => sum + e.weight, 0);

function selectEndpoint() {
    let r = Math.random() * totalWeight;
    for (const ep of endpoints) {
        r -= ep.weight;
        if (r <= 0) return ep.fn;
    }
    return endpoints[0].fn;
}

function healthCheck() {
    return http.get(`${BASE_URL}/health`, { headers: getHeaders });
}

function agentIdentity() {
    return http.get(`${BASE_URL}/agent`, { headers: getHeaders });
}

function listPeers() {
    return http.get(`${BASE_URL}/peers`, { headers: getHeaders });
}

function presenceOnline() {
    return http.get(`${BASE_URL}/presence/online`, { headers: getHeaders });
}

function listContacts() {
    return http.get(`${BASE_URL}/contacts`, { headers: getHeaders });
}

function listGroups() {
    return http.get(`${BASE_URL}/groups`, { headers: getHeaders });
}

function listStores() {
    return http.get(`${BASE_URL}/stores`, { headers: getHeaders });
}

function networkStatus() {
    return http.get(`${BASE_URL}/network/status`, { headers: getHeaders });
}

function discoveredAgents() {
    return http.get(`${BASE_URL}/agents/discovered`, {
        headers: getHeaders,
    });
}

function wsSessions() {
    return http.get(`${BASE_URL}/ws/sessions`, { headers: getHeaders });
}

export default function () {
    const fn = selectEndpoint();
    const res = fn();

    apiLatency.add(res.timings.duration);
    errorRate.add(res.status !== 200);

    check(res, {
        'status is 200': (r) => r.status === 200,
        'latency < 800ms': (r) => r.timings.duration < 800,
    });

    sleep(0.05);
}
