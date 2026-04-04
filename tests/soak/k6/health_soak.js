// Health endpoint soak test — sustained polling for latency drift detection.
//
// Usage: k6 run --env X0X_API=http://127.0.0.1:12700 --env X0X_TOKEN=<token> health_soak.js
// Short run: k6 run --duration 5m health_soak.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

const BASE_URL = __ENV.X0X_API || 'http://127.0.0.1:12700';
const TOKEN = __ENV.X0X_TOKEN || '';

const errorRate = new Rate('errors');
const healthLatency = new Trend('health_latency');

export const options = {
    scenarios: {
        steady_state: {
            executor: 'constant-arrival-rate',
            rate: 5,
            timeUnit: '1s',
            duration: __ENV.DURATION || '1h',
            preAllocatedVUs: 3,
            maxVUs: 10,
        },
    },
    thresholds: {
        http_req_duration: ['p(95) < 200', 'p(99) < 500'],
        errors: ['rate < 0.01'],
        health_latency: ['p(95) < 150'],
    },
};

const headers = TOKEN
    ? { Authorization: `Bearer ${TOKEN}` }
    : {};

export default function () {
    const res = http.get(`${BASE_URL}/health`, { headers });

    healthLatency.add(res.timings.duration);
    errorRate.add(res.status !== 200);

    check(res, {
        'status is 200': (r) => r.status === 200,
        'has ok field': (r) => {
            try {
                return JSON.parse(r.body).ok === true;
            } catch {
                return false;
            }
        },
        'latency < 500ms': (r) => r.timings.duration < 500,
    });

    sleep(0.1);
}
