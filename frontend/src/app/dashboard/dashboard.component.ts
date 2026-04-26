import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { LogService, Stats } from '../services/log.service';
import { StatsCardsComponent } from '../stats-cards/stats-cards.component';
import { LogTableComponent } from '../log-table/log-table.component';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, StatsCardsComponent, LogTableComponent],
  templateUrl: './dashboard.component.html',
})
export class DashboardComponent implements OnInit {
  stats: Stats | null = null;
  lastUpdated = new Date();

  constructor(private logService: LogService) {}

  ngOnInit(): void {
    this.loadStats();
    setInterval(() => this.loadStats(), 10000);
  }

  loadStats(): void {
    this.logService.getStats().subscribe(s => {
      this.stats = s;
      this.lastUpdated = new Date();
    });
  }
}