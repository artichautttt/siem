import { Component, OnInit, OnDestroy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Subscription, interval } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { LogService, Log } from '../services/log.service';

@Component({
  selector: 'app-log-table',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './log-table.component.html',
})
export class LogTableComponent implements OnInit, OnDestroy {
  logs: Log[]     = [];
  searchQuery     = '';
  filterSeverity  = '';
  filterAction    = '';
  filterProtocol  = '';
  filterSrcIp     = '';
  loading         = false;
  showFilters     = false;
  currentPage     = 0;
  pageSize        = 50;
  private sub!: Subscription;

  constructor(private logService: LogService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadLogs();
    this.sub = interval(5000)
      .pipe(switchMap(() => this.logService.getLogs(this.buildFilters())))
      .subscribe({
        next: logs => { this.logs = logs; this.cdr.detectChanges(); },
        error: err  => console.error(err),
      });
  }

  ngOnDestroy(): void { this.sub?.unsubscribe(); }

  buildFilters(): Record<string, string> {
    const f: Record<string, string> = {};
    if (this.filterSeverity)  f['severity'] = this.filterSeverity;
    if (this.filterAction)    f['action']   = this.filterAction;
    if (this.filterProtocol)  f['protocol'] = this.filterProtocol;
    if (this.filterSrcIp)     f['src_ip']   = this.filterSrcIp;
    f['limit']  = String(this.pageSize);
    f['offset'] = String(this.currentPage * this.pageSize);
    return f;
  }

  loadLogs(): void {
    this.loading = true;
    if (this.searchQuery.trim()) {
      this.logService.searchLogs(this.searchQuery).subscribe({
        next: res => { this.logs = res.results; this.loading = false; this.cdr.detectChanges(); },
        error: err => { console.error(err); this.loading = false; this.cdr.detectChanges(); },
      });
    } else {
      this.logService.getLogs(this.buildFilters()).subscribe({
        next: logs => { this.logs = logs; this.loading = false; this.cdr.detectChanges(); },
        error: err  => { console.error(err); this.loading = false; this.cdr.detectChanges(); },
      });
    }
  }

  resetFilters(): void {
    this.filterSeverity = '';
    this.filterAction   = '';
    this.filterProtocol = '';
    this.filterSrcIp    = '';
    this.searchQuery    = '';
    this.currentPage    = 0;
    this.loadLogs();
  }

  nextPage(): void  { this.currentPage++; this.loadLogs(); }
  prevPage(): void  { if (this.currentPage > 0) { this.currentPage--; this.loadLogs(); } }
  onSearch(): void  { this.currentPage = 0; this.loadLogs(); }
  onFilter(): void  { this.currentPage = 0; this.loadLogs(); }

  exportCsv(): void {
    const headers = ['ID','Timestamp','IP Source','IP Dest','Port Src','Port Dst',
                     'Protocole','Action','Octets','Severite','Message'];
    const rows = this.logs.map(l => [
      l.id, l.timestamp, l.src_ip, l.dst_ip, l.src_port, l.dst_port,
      l.protocol, l.action, l.bytes, l.severity,
      '"' + l.message.replace(/"/g, '""') + '"',
    ]);
    const csv  = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'siem-logs-' + new Date().toISOString().slice(0,10) + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  severityClass(sev: string): string {
    return ({ LOW:'badge-low', MEDIUM:'badge-medium', HIGH:'badge-high', CRITICAL:'badge-critical' } as any)[sev] ?? '';
  }
  actionClass(action: string): string {
    return action === 'ALLOW' ? 'badge-allow' : 'badge-deny';
  }
  get activeFilterCount(): number {
    return [this.filterSeverity, this.filterAction, this.filterProtocol, this.filterSrcIp]
      .filter(Boolean).length;
  }
}
