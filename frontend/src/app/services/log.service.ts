import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Log {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  action: string;
  bytes: number;
  severity: string;
  message: string;
}

export interface Stats {
  total_logs: number;
  high_critical: number;
  deny_count: number;
  by_severity: { severity: string; count: number }[];
  by_action: { action: string; count: number }[];
  by_protocol: { protocol: string; count: number }[];
  top_source_ips: { src_ip: string; count: number }[];
}

@Injectable({ providedIn: 'root' })
export class LogService {
  private base = 'http://localhost:5000/api';

  constructor(private http: HttpClient) {}

  getLogs(filters: any = {}): Observable<Log[]> {
    let params = new HttpParams();
    Object.keys(filters).forEach(k => {
      if (filters[k]) params = params.set(k, filters[k]);
    });
    return this.http.get<Log[]>(`${this.base}/logs`, { params });
  }

  getStats(): Observable<Stats> {
    return this.http.get<Stats>(`${this.base}/stats`);
  }

  searchLogs(q: string): Observable<{ results: Log[]; total: number }> {
    return this.http.get<{ results: Log[]; total: number }>(
      `${this.base}/search`, { params: new HttpParams().set('q', q) }
    );
  }
}
