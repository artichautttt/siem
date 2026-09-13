import { Component, OnInit, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { environment } from '../../environments/environment';
import { WazuhService, WazuhAlert } from '../services/wazuh.service';

interface Alert {
  id:          number;
  timestamp:   string;
  rule_name:   string;
  src_ip:      string;
  severity:    string;
  description: string;
  resolved:    number;
}

interface RiskScore {
  score:  number;
  level:  string;
  events: number;
}

@Component({
  selector: 'app-alerts',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './alerts.component.html',
})
export class AlertsComponent implements OnInit {
  alerts:    Alert[]    = [];
  riskScore: RiskScore  = { score: 0, level: 'NORMAL', events: 0 };
  loading    = false;
  detecting  = false;
  showResolved = false;

  wazuhAlerts:    WazuhAlert[] = [];
  wazuhAvailable  = true;

  private base = environment.apiUrl;
  private authHeaders = new HttpHeaders({ 'X-API-Key': environment.apiKey });

  constructor(private http: HttpClient, private wazuh: WazuhService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadAlerts();
    this.loadRiskScore();
    this.loadWazuhAlerts();
    setInterval(() => { this.loadAlerts(); this.loadRiskScore(); this.loadWazuhAlerts(); }, 15000);
  }

  loadWazuhAlerts(): void {
    this.wazuh.getAlerts(20).subscribe({
      next: res => { this.wazuhAlerts = res.alerts; this.wazuhAvailable = res.available; this.cdr.detectChanges(); },
      error: () => { this.wazuhAlerts = []; this.wazuhAvailable = false; this.cdr.detectChanges(); },
    });
  }

  loadAlerts(): void {
    const url = this.showResolved
      ? `${this.base}/alerts`
      : `${this.base}/alerts?resolved=0`;
    this.http.get<any>(url).subscribe({
      next: res => { this.alerts = res.alerts; this.cdr.detectChanges(); },
      error: err => console.error(err),
    });
  }

  loadRiskScore(): void {
    this.http.get<RiskScore>(`${this.base}/detect/score?window=60`).subscribe({
      next: score => { this.riskScore = score; this.cdr.detectChanges(); },
      error: err  => console.error(err),
    });
  }

  runDetection(): void {
    this.detecting = true;
    this.http.post<any>(`${this.base}/detect`, { window_minutes: 60 }, { headers: this.authHeaders }).subscribe({
      next: res => {
        this.detecting = false;
        this.loadAlerts();
        this.loadRiskScore();
        this.cdr.detectChanges();
      },
      error: err => { console.error(err); this.detecting = false; this.cdr.detectChanges(); },
    });
  }

  resolveAlert(id: number): void {
    this.http.patch(`${this.base}/alerts/${id}/resolve`, {}, { headers: this.authHeaders }).subscribe({
      next: () => { this.loadAlerts(); this.cdr.detectChanges(); },
      error: err => console.error(err),
    });
  }

  toggleResolved(): void {
    this.showResolved = !this.showResolved;
    this.loadAlerts();
  }

  severityClass(sev: string): string {
    return ({ LOW:'badge-low', MEDIUM:'badge-medium', HIGH:'badge-high', CRITICAL:'badge-critical' } as any)[sev] ?? '';
  }

  riskColor(): string {
    const s = this.riskScore.score;
    if (s >= 75) return '#ef4444';
    if (s >= 50) return '#f97316';
    if (s >= 25) return '#eab308';
    return '#22c55e';
  }

  riskBg(): string {
    const s = this.riskScore.score;
    if (s >= 75) return '#450a0a';
    if (s >= 50) return '#431407';
    if (s >= 25) return '#422006';
    return '#052e16';
  }
}
