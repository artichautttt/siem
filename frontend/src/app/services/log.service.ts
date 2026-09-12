import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

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

// Doit correspondre exactement à la réponse JSON de GET /api/stats
// (voir backend/routes/logs.py::get_stats).
export interface Stats {
  total_logs: number;
  high_critical: number;
  by_severity: { severity: string; count: number }[];
  by_action: { action: string; count: number }[];
  top_source_ips: { src_ip: string; count: number }[];
}

@Injectable({ providedIn: 'root' })
export class LogService {
  private base = environment.apiUrl;

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

  getTimeline(): Observable<{ hour: string; total: number; denied: number; threats: number }[]> {
    return this.http.get<any[]>(`${this.base}/stats/timeline`);
  }

  searchLogs(q: string): Observable<{ results: Log[]; total: number }> {
    return this.http.get<{ results: Log[]; total: number }>(
      `${this.base}/search`, { params: new HttpParams().set('q', q) }
    );
  }
}
