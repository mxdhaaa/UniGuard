/**
 * UniGuard Real-Time Alert WebSocket Hook (Milestone 14)
 * 
 * Subscribes to /api/ws/alerts for real-time HIGH and CRITICAL security alerts.
 * Features automated reconnection with exponential backoff and clean lifecycle teardown.
 */

import { useState, useEffect, useRef, useCallback } from 'react';
import { getWebSocketUrl, type DashboardAlertSummary } from './client';

export type SocketStatus = 'connecting' | 'connected' | 'disconnected' | 'reconnecting' | 'error';

export interface UseAlertSocketOptions {
  onAlertReceived?: (alert: DashboardAlertSummary) => void;
  maxRecentAlerts?: number;
  autoReconnect?: boolean;
}

export function useAlertSocket(options?: UseAlertSocketOptions) {
  const [status, setStatus] = useState<SocketStatus>('disconnected');
  const [recentAlerts, setRecentAlerts] = useState<DashboardAlertSummary[]>([]);
  const [lastAlert, setLastAlert] = useState<DashboardAlertSummary | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);
  const retryCountRef = useRef<number>(0);
  const isUnmountedRef = useRef<boolean>(false);

  const onAlertReceived = options?.onAlertReceived;
  const maxRecent = options?.maxRecentAlerts ?? 20;
  const autoReconnect = options?.autoReconnect ?? true;

  const connect = useCallback(() => {
    if (isUnmountedRef.current) return;

    try {
      const wsUrl = getWebSocketUrl();
      setStatus(retryCountRef.current > 0 ? 'reconnecting' : 'connecting');

      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        if (isUnmountedRef.current) {
          ws.close();
          return;
        }
        setStatus('connected');
        retryCountRef.current = 0;
      };

      ws.onmessage = (event) => {
        if (isUnmountedRef.current) return;
        try {
          const raw = JSON.parse(event.data);
          
          // Map backend broadcast JSON into DashboardAlertSummary format
          const alertItem: DashboardAlertSummary = {
            alert_id: raw.alert_id || raw.id || `alert-${Date.now()}`,
            flow_id: raw.flow_id || 'unknown',
            threat_type: raw.threat_type || raw.threat || 'UNKNOWN',
            risk_score: typeof raw.risk_score === 'number' ? raw.risk_score : 0,
            severity: String(raw.severity || 'HIGH').toUpperCase(),
            status: raw.status || 'OPEN',
            summary: raw.summary || raw.whyDetected || 'Real-time alert broadcast',
            created_at: raw.created_at || raw.timestamp || new Date().toISOString(),
            updated_at: raw.updated_at || new Date().toISOString(),
          };

          setLastAlert(alertItem);
          setRecentAlerts((prev) => [alertItem, ...prev.slice(0, maxRecent - 1)]);

          if (onAlertReceived) {
            onAlertReceived(alertItem);
          }
        } catch (err) {
          console.warn('[UniGuard WebSocket] Failed to parse alert message:', err);
        }
      };

      ws.onerror = () => {
        if (isUnmountedRef.current) return;
        setStatus('error');
      };

      ws.onclose = () => {
        if (isUnmountedRef.current) return;
        setStatus('disconnected');
        socketRef.current = null;

        if (autoReconnect) {
          const delay = Math.min(10000, 1000 * Math.pow(1.5, retryCountRef.current));
          retryCountRef.current += 1;
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, delay);
        }
      };
    } catch (err) {
      console.warn('[UniGuard WebSocket] Connection initiation failed:', err);
      setStatus('error');
    }
  }, [autoReconnect, maxRecent, onAlertReceived]);

  useEffect(() => {
    isUnmountedRef.current = false;
    connect();

    return () => {
      isUnmountedRef.current = true;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [connect]);

  const clearAlerts = useCallback(() => {
    setRecentAlerts([]);
    setLastAlert(null);
  }, []);

  return {
    status,
    recentAlerts,
    lastAlert,
    clearAlerts,
    reconnect: connect,
  };
}
