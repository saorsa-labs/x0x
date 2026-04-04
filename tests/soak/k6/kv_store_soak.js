// KV store soak test — create/put/get/delete cycles.
//
// Usage: k6 run --env X0X_API=http://127.0.0.1:12700 --env X0X_TOKEN=<token> kv_store_soak.js
//
// Requires: a store already created (store_id in X0X_STORE_ID env var)

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.X0X_API || 'http://127.0.0.1:12700';
const TOKEN = __ENV.X0X_TOKEN || '';
const STORE_ID = __ENV.X0X_STORE_ID || 'soak-store';

const errorRate = new Rate('errors');
const putLatency = new Trend('kv_put_latency');
const getLatency = new Trend('kv_get_latency');

export const options = {
    scenarios: {
        kv_cycle: {
            executor: 'constant-arrival-rate',
            rate: 5,
            timeUnit: '1s',
            duration: __ENV.DURATION || '1h',
            preAllocatedVUs: 3,
            maxVUs: 10,
        },
    },
    thresholds: {
        http_req_duration: ['p(95) < 300', 'p(99) < 800'],
        errors: ['rate < 0.02'],
        kv_put_latency: ['p(95) < 250'],
        kv_get_latency: ['p(95) < 150'],
    },
};

const headers = {
    'Content-Type': 'application/json',
    ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
};

export default function () {
    const key = `soak-key-${__VU}-${__ITER % 100}`;
    const value = `value-${Date.now()}`;

    // PUT
    const putRes = http.put(
        `${BASE_URL}/stores/${STORE_ID}/${key}`,
        JSON.stringify({ value, content_type: 'text/plain' }),
        { headers },
    );
    putLatency.add(putRes.timings.duration);
    errorRate.add(putRes.status !== 200);

    check(putRes, {
        'put status 200': (r) => r.status === 200,
    });

    // GET
    const getRes = http.get(`${BASE_URL}/stores/${STORE_ID}/${key}`, {
        headers,
    });
    getLatency.add(getRes.timings.duration);
    errorRate.add(getRes.status !== 200);

    check(getRes, {
        'get status 200': (r) => r.status === 200,
        'get returns value': (r) => {
            try {
                return JSON.parse(r.body).value !== undefined;
            } catch {
                return false;
            }
        },
    });

    sleep(0.1);
}
