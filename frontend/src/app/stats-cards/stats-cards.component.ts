import { Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Stats } from '../services/log.service';

@Component({
  selector: 'app-stats-cards',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './stats-cards.component.html',
})
export class StatsCardsComponent {
  @Input() stats: Stats | null = null;

  get denyCount(): number {
    return this.stats?.by_action.find(a => a.action === 'DENY')?.count ?? 0;
  }

  get allowCount(): number {
    return (this.stats?.total_logs ?? 0) - this.denyCount;
  }
}