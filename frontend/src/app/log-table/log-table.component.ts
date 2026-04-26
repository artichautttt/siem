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
  logs: Log[] = [];
  searchQuery = '';
  filterSeverity = '';
  filterAction = '';
  loading = false;
  private sub!: Subscription;

  constructor(private logService: LogService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.loadLogs();
    this.sub = interval(5000)
      .pipe(switchMap(() => this.logService.getLogs(this.buildFilters())))
      .subscribe({
        next: logs => {
          this.logs = logs;
          this.cdr.detectChanges();
        },
        error: err => console.error(err)
      });
  }

  ngOnDestroy(): void { this.sub?.unsubscribe(); }

  buildFilters() {
    const f: any = {};
    if (this.filterSeverity) f['severity'] = this.filterSeverity;
    if (this.filterAction)   f['action']   = this.filterAction;
    return f;
  }

  loadLogs(): void {
    this.loading = true;
    this.logService.getLogs(this.buildFilters()).subscribe({
      next: logs => {
        this.logs = logs;
        this.loading = false;
        this.cdr.detectChanges();
      },
      error: err => {
        console.error(err);
        this.loading = false;
        this.cdr.detectChanges();
      }
    });
  }

  onSearch(): void { this.loadLogs(); }
  onFilter(): void { this.loadLogs(); }

  severityClass(sev: string): string {
    return ({ LOW: 'badge-low', MEDIUM: 'badge-medium', HIGH: 'badge-high', CRITICAL: 'badge-critical' } as any)[sev] ?? '';
  }

  actionClass(action: string): string {
    return action === 'ALLOW' ? 'badge-allow' : 'badge-deny';
  }
}