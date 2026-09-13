import { Component } from '@angular/core';
import { DashboardComponent } from './dashboard/dashboard.component';
import { LoginComponent } from './login/login.component';
import { AuthService } from './services/auth.service';

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [DashboardComponent, LoginComponent],
  template: `
    @if (auth.isLoggedIn()) {
      <app-dashboard></app-dashboard>
    } @else {
      <app-login (loggedIn)="onLoggedIn()"></app-login>
    }
  `,
})
export class AppComponent {
  constructor(public auth: AuthService) {}

  // L'émission de (loggedIn) déclenche déjà un cycle de détection de
  // changements (zone.js) qui réévalue auth.isLoggedIn() dans le template —
  // rien à faire ici à part exister pour le binding d'événement.
  onLoggedIn(): void {}
}