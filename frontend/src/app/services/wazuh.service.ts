import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface WazuhAlert {
  id: string;
  timestamp: string;
  rule_name: string;
  src_ip: string;
  severity: string;
  level: number;
  description: string;
  agent: string;
  mitre: any;
  source: 'wazuh';
}

export interface WazuhAlertsResponse {
  alerts: WazuhAlert[];
  total: number;
  available: boolean;
}

@Injectable({ providedIn: 'root' })
export class WazuhService {
  private base = environment.apiUrl;

  constructor(private http: HttpClient) {}

  getAlerts(limit = 20, minLevel = 0): Observable<WazuhAlertsResponse> {
    const params = new HttpParams()
      .set('limit', limit)
      .set('min_level', minLevel);
    return this.http.get<WazuhAlertsResponse>(`${this.base}/wazuh/alerts`, { params });
  }
}
