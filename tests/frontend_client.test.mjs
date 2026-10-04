/**
 * UniGuard Frontend Integration Unit Tests (Milestone 14)
 * 
 * Verifies API client methods, query string formatting, error parsing,
 * WebSocket URL generation, and response parsing using Node.js native test runner.
 */

import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { 
  uniguardApi, 
  API_BASE_URL, 
  getWebSocketUrl 
} from '../src/api/client.ts';

describe('UniGuard Centralized Frontend API Client (M14)', () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
  });

  test('API Base URL and WebSocket URL derivation', () => {
    assert.ok(API_BASE_URL, 'API_BASE_URL must be defined');
    const wsUrl = getWebSocketUrl();
    assert.match(wsUrl, /^wss?:\/\//, 'WebSocket URL must use ws:// or wss:// scheme');
    assert.match(wsUrl, /\/api\/ws\/alerts$/, 'WebSocket URL must point to /api/ws/alerts');
  });

  test('uniguardApi exposes all required SOC methods', () => {
    const requiredMethods = [
      'getHealth',
      'getSystemStatus',
      'getOverview',
      'getFlows',
      'getFlowDetail',
      'getAlerts',
      'getAlertDetail',
      'getThreats',
      'getTimeline',
      'getFlowInvestigation',
      'getAlertInvestigation',
      'getFlowReport',
      'getAlertReport',
      'getIngestionStatus',
      'startIngestion',
      'stopIngestion',
      'uploadPcap',
      'getPcapStatus',
    ];

    for (const method of requiredMethods) {
      assert.equal(
        typeof uniguardApi[method], 
        'function', 
        `uniguardApi.${method} must be an exported function`
      );
    }
  });

  test('getFlows builds correct query parameters', async () => {
    let capturedUrl = '';
    global.fetch = async (url) => {
      capturedUrl = String(url);
      return {
        ok: true,
        json: async () => ({
          data: [],
          meta: { page: 2, page_size: 50, total_items: 0, total_pages: 0 },
        }),
      };
    };

    await uniguardApi.getFlows({
      page: 2,
      page_size: 50,
      threat_type: 'DOS_DDOS',
      severity: 'HIGH',
      is_anomaly: true,
      source_ip: '192.168.1.100',
      destination_ip: '10.0.0.1',
    });

    assert.ok(capturedUrl.includes('/api/dashboard/flows'), 'URL must target flows endpoint');
    assert.ok(capturedUrl.includes('page=2'), 'Query param page=2 missing');
    assert.ok(capturedUrl.includes('page_size=50'), 'Query param page_size=50 missing');
    assert.ok(capturedUrl.includes('threat_type=DOS_DDOS'), 'Query param threat_type missing');
    assert.ok(capturedUrl.includes('severity=HIGH'), 'Query param severity missing');
    assert.ok(capturedUrl.includes('is_anomaly=true'), 'Query param is_anomaly missing');
    assert.ok(capturedUrl.includes('source_ip=192.168.1.100'), 'Query param source_ip missing');
    assert.ok(capturedUrl.includes('destination_ip=10.0.0.1'), 'Query param destination_ip missing');
  });

  test('getAlerts builds correct query parameters', async () => {
    let capturedUrl = '';
    global.fetch = async (url) => {
      capturedUrl = String(url);
      return {
        ok: true,
        json: async () => ({
          data: [],
          meta: { page: 1, page_size: 10, total_items: 0, total_pages: 0 },
        }),
      };
    };

    await uniguardApi.getAlerts({
      severity: 'CRITICAL',
      status: 'OPEN',
      threat_type: 'BOTNET_C2',
    });

    assert.ok(capturedUrl.includes('/api/dashboard/alerts'), 'URL must target alerts endpoint');
    assert.ok(capturedUrl.includes('severity=CRITICAL'));
    assert.ok(capturedUrl.includes('status=OPEN'));
    assert.ok(capturedUrl.includes('threat_type=BOTNET_C2'));
  });

  test('Investigation and Report endpoints encode identifiers safely', async () => {
    const urls = [];
    global.fetch = async (url) => {
      urls.push(String(url));
      return {
        ok: true,
        json: async () => ({ report_id: 'rep-test' }),
      };
    };

    const trickyId = 'flow:test/123+special';
    await uniguardApi.getFlowInvestigation(trickyId);
    await uniguardApi.getAlertInvestigation(trickyId);
    await uniguardApi.getFlowReport(trickyId);
    await uniguardApi.getAlertReport(trickyId);

    const encoded = encodeURIComponent(trickyId);
    assert.ok(urls[0].includes(`/api/investigations/flows/${encoded}`));
    assert.ok(urls[1].includes(`/api/investigations/alerts/${encoded}`));
    assert.ok(urls[2].includes(`/api/reports/flows/${encoded}`));
    assert.ok(urls[3].includes(`/api/reports/alerts/${encoded}`));
  });

  test('HTTP error responses properly extract error detail', async () => {
    global.fetch = async () => ({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: async () => ({ detail: 'Requested flow does not exist in database.' }),
    });

    await assert.rejects(
      async () => {
        await uniguardApi.getFlowDetail('missing-flow');
      },
      (err) => {
        assert.match(err.message, /Requested flow does not exist in database/);
        return true;
      }
    );
  });

  test('Ingestion controls formulate POST requests', async () => {
    const methods = [];
    global.fetch = async (url, options) => {
      methods.push({ url: String(url), method: options?.method });
      return {
        ok: true,
        json: async () => ({ state: 'RUNNING', active_flows: 10 }),
      };
    };

    await uniguardApi.startIngestion();
    await uniguardApi.stopIngestion();

    assert.equal(methods[0].method, 'POST');
    assert.ok(methods[0].url.endsWith('/api/ingestion/start'));
    assert.equal(methods[1].method, 'POST');
    assert.ok(methods[1].url.endsWith('/api/ingestion/stop'));
  });
});
