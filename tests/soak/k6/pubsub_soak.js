// Publish/subscribe soak test — sustained messaging load.
//
// Usage: k6 run --env X0X_API=http://127.0.0.1:12700 --env X0X_TOKEN=<token> pubsub_soak.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

const BASE_URL = __ENV.X0X_API || 'http://127.0.0.1:12700';
const TOKEN = __ENV.X0X_TOKEN || '';

const errorRate = new Rate('errors');
const publishLatency = new Trend('publish_latency');

export const options = {
    scenarios: {
        steady_publish: {
            executor: 'constant-arrival-rate',
            rate: 10,
            timeUnit: '1s',
            duration: __ENV.DURATION || '1h',
            preAllocatedVUs: 5,
            maxVUs: 20,
        },
    },
    thresholds: {
        http_req_duration: ['p(95) < 200', 'p(99) < 500'],
        errors: ['rate < 0.01'],
        publish_latency: ['p(95) < 150'],
    },
};

const headers = {
    'Content-Type': 'application/json',
    ...(TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {}),
};

export default function () {
    const topic = `soak-test-${__VU}`;
    // Base64-encode a random payload
    const payload = encoding.b64encode(randomString(64));

    const res = http.post(
        `${BASE_URL}/publish`,
        JSON.stringify({ topic, payload }),
        { headers },
    );

    publishLatency.add(res.timings.duration);
    errorRate.add(res.status !== 200);

    check(res, {
        'status is 200': (r) => r.status === 200,
        'latency < 500ms': (r) => r.timings.duration < 500,
    });

    sleep(0.05);
}
