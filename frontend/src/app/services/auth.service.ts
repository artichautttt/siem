import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, tap } from 'rxjs';
import { environment } from '../../environments/environment';

export interface LoginResponse {
  token: string;
  username: string;
  role: 'analyst' | 'admin';
}

const STORAGE_KEY = 'mini-siem-auth';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private base = environment.apiUrl;

  constructor(private http: HttpClient) {}

  login(username: string, password: string): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.base}/auth/login`, { username, password }).pipe(
      tap(res => localStorage.setItem(STORAGE_KEY, JSON.stringify(res))),
    );
  }

  logout(): void {
    localStorage.removeItem(STORAGE_KEY);
  }

  private session(): LoginResponse | null {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  isLoggedIn(): boolean {
    return this.session() !== null;
  }

  getToken(): string | null {
    return this.session()?.token ?? null;
  }

  getUsername(): string | null {
    return this.session()?.username ?? null;
  }

  getRole(): string | null {
    return this.session()?.role ?? null;
  }

  isAdmin(): boolean {
    return this.getRole() === 'admin';
  }

  authHeader(): { Authorization: string } | {} {
    const token = this.getToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }
}
