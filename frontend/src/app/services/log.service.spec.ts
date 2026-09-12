import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { LogService } from './log.service';
import { environment } from '../../environments/environment';

describe('LogService', () => {
  let service: LogService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [HttpClientTestingModule],
      providers: [LogService],
    });
    service = TestBed.inject(LogService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('getLogs() should call the API at environment.apiUrl/logs', () => {
    service.getLogs().subscribe();

    const req = httpMock.expectOne(`${environment.apiUrl}/logs`);
    expect(req.request.method).toBe('GET');
    req.flush([]);
  });

  it('getStats() should call the API at environment.apiUrl/stats', () => {
    service.getStats().subscribe();

    const req = httpMock.expectOne(`${environment.apiUrl}/stats`);
    expect(req.request.method).toBe('GET');
    req.flush({
      total_logs: 0,
      high_critical: 0,
      by_severity: [],
      by_action: [],
      top_source_ips: [],
    });
  });
});
