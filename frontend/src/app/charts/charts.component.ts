import { Component, OnInit, AfterViewInit, ElementRef, ViewChild, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LogService } from '../services/log.service';
import { Chart, registerables } from 'chart.js';

Chart.register(...registerables);

@Component({
  selector: 'app-charts',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './charts.component.html',
})
export class ChartsComponent implements OnInit, AfterViewInit {
  @ViewChild('severityChart') severityRef!: ElementRef;
  @ViewChild('actionChart')   actionRef!: ElementRef;
  @ViewChild('topIpsChart')   topIpsRef!: ElementRef;
  @ViewChild('timelineChart') timelineRef!: ElementRef;

  private charts: Chart[] = [];

  constructor(private logService: LogService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {}

  ngAfterViewInit(): void {
    this.loadCharts();
    setInterval(() => this.loadCharts(), 15000);
  }

  loadCharts(): void {
    this.logService.getStats().subscribe({
      next: stats => {
        this.buildSeverityChart(stats.by_severity);
        this.buildActionChart(stats.by_action);
        this.buildTopIpsChart(stats.top_source_ips);
        this.cdr.detectChanges();
      }
    });

    this.logService.getTimeline().subscribe({
      next: data => {
        this.buildTimelineChart(data);
        this.cdr.detectChanges();
      }
    });
  }

  private destroyChart(ref: ElementRef): void {
    const existing = Chart.getChart(ref.nativeElement);
    if (existing) existing.destroy();
  }

  private buildSeverityChart(data: { severity: string; count: number }[]): void {
    this.destroyChart(this.severityRef);
    const colors: Record<string, string> = {
      LOW:      '#22c55e',
      MEDIUM:   '#eab308',
      HIGH:     '#f97316',
      CRITICAL: '#ef4444',
    };
    new Chart(this.severityRef.nativeElement, {
      type: 'doughnut',
      data: {
        labels: data.map(d => d.severity),
        datasets: [{
          data:            data.map(d => d.count),
          backgroundColor: data.map(d => colors[d.severity] ?? '#64748b'),
          borderColor:     '#1a1f2e',
          borderWidth:     3,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94a3b8', font: { size: 12 } } },
          title:  { display: true, text: 'Distribution des sévérités', color: '#e2e8f0', font: { size: 14 } },
        },
      },
    });
  }

  private buildActionChart(data: { action: string; count: number }[]): void {
    this.destroyChart(this.actionRef);
    new Chart(this.actionRef.nativeElement, {
      type: 'bar',
      data: {
        labels: data.map(d => d.action),
        datasets: [{
          label:           'Événements',
          data:            data.map(d => d.count),
          backgroundColor: data.map(d => d.action === 'ALLOW' ? '#22c55e88' : '#ef444488'),
          borderColor:     data.map(d => d.action === 'ALLOW' ? '#22c55e'   : '#ef4444'),
          borderWidth:     2,
          borderRadius:    6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title:  { display: true, text: 'ALLOW vs DENY', color: '#e2e8f0', font: { size: 14 } },
        },
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e2533' } },
          y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e2533' }, beginAtZero: true },
        },
      },
    });
  }

  private buildTopIpsChart(data: { src_ip: string; count: number }[]): void {
    this.destroyChart(this.topIpsRef);
    const top5 = data.slice(0, 5);
    new Chart(this.topIpsRef.nativeElement, {
      type: 'bar',
      data: {
        labels: top5.map(d => d.src_ip),
        datasets: [{
          label:           'Événements',
          data:            top5.map(d => d.count),
          backgroundColor: '#3b82f688',
          borderColor:     '#3b82f6',
          borderWidth:     2,
          borderRadius:    6,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          title:  { display: true, text: 'Top 5 IPs sources', color: '#e2e8f0', font: { size: 14 } },
        },
        scales: {
          x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e2533' }, beginAtZero: true },
          y: { ticks: { color: '#94a3b8', font: { family: 'monospace' } }, grid: { color: '#1e2533' } },
        },
      },
    });
  }

  private buildTimelineChart(data: { hour: string; total: number; denied: number; threats: number }[]): void {
    this.destroyChart(this.timelineRef);
    const labels = data.map(d => d.hour ? d.hour.substring(11, 16) : '');
    new Chart(this.timelineRef.nativeElement, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label:           'Total',
            data:            data.map(d => d.total),
            borderColor:     '#3b82f6',
            backgroundColor: '#3b82f622',
            fill:            true,
            tension:         0.4,
            pointRadius:     3,
          },
          {
            label:           'Bloqués',
            data:            data.map(d => d.denied),
            borderColor:     '#ef4444',
            backgroundColor: '#ef444422',
            fill:            true,
            tension:         0.4,
            pointRadius:     3,
          },
          {
            label:           'Menaces',
            data:            data.map(d => d.threats),
            borderColor:     '#f97316',
            backgroundColor: '#f9731622',
            fill:            true,
            tension:         0.4,
            pointRadius:     3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top', labels: { color: '#94a3b8', font: { size: 11 } } },
          title:  { display: true, text: 'Trafic réseau (24h)', color: '#e2e8f0', font: { size: 14 } },
        },
        scales: {
          x: { ticks: { color: '#94a3b8', maxRotation: 45 }, grid: { color: '#1e2533' } },
          y: { ticks: { color: '#94a3b8' }, grid: { color: '#1e2533' }, beginAtZero: true },
        },
      },
    });
  }
}
