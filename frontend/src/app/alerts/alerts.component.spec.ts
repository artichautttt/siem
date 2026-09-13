import { TestBed } from '@angular/core/testing';
import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { AlertsComponent } from './alerts.component';

describe('AlertsComponent', () => {
  let httpMock: HttpTestingController;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [AlertsComponent, HttpClientTestingModule],
    }).compileComponents();
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpMock.verify();
  });

  it('should create and render "Aucune alerte" when the list is empty', () => {
    const fixture = TestBed.createComponent(AlertsComponent);
    fixture.detectChanges();

    // ngOnInit déclenche loadAlerts(), loadRiskScore() et loadWazuhAlerts()
    httpMock.expectOne(req => req.url.endsWith('/alerts?resolved=0')).flush({
      alerts: [], total: 0, open: 0, resolved: 0,
    });
    httpMock.expectOne(req => req.url.includes('/detect/score')).flush({
      score: 0, level: 'NORMAL', events: 0,
    });
    httpMock.expectOne(req => req.url.includes('/wazuh/alerts')).flush({
      alerts: [], total: 0, available: true,
    });

    fixture.detectChanges();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Aucune alerte active');
  });

  it('should call POST /detect when clicking "Lancer la détection"', () => {
    const fixture = TestBed.createComponent(AlertsComponent);
    fixture.detectChanges();

    // Flush les appels déclenchés par ngOnInit avant d'interagir avec le bouton.
    httpMock.expectOne(req => req.url.endsWith('/alerts?resolved=0')).flush({
      alerts: [], total: 0, open: 0, resolved: 0,
    });
    httpMock.expectOne(req => req.url.includes('/detect/score')).flush({
      score: 0, level: 'NORMAL', events: 0,
    });
    httpMock.expectOne(req => req.url.includes('/wazuh/alerts')).flush({
      alerts: [], total: 0, available: true,
    });
    fixture.detectChanges();

    const button: HTMLButtonElement = fixture.nativeElement.querySelector('.btn-detect');
    button.click();

    const detectReq = httpMock.expectOne(req => req.url.endsWith('/detect') && req.method === 'POST');
    expect(detectReq.request.body).toEqual({ window_minutes: 60 });
    detectReq.flush({ alerts_generated: 0, alerts: [], risk_score: { score: 0, level: 'NORMAL', events: 0 } });

    // runDetection() recharge alertes + score après succès
    httpMock.expectOne(req => req.url.endsWith('/alerts?resolved=0')).flush({
      alerts: [], total: 0, open: 0, resolved: 0,
    });
    httpMock.expectOne(req => req.url.includes('/detect/score')).flush({
      score: 0, level: 'NORMAL', events: 0,
    });
  });
});
