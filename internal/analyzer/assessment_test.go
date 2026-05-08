package analyzer

import (
	"testing"

	"github.com/xalgord/camscan/internal/minimax"
	"github.com/xalgord/camscan/internal/shodan"
)

func TestEnforceReportableAssessmentDowngradesAuthRequiredCVEOnly(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.10",
		Port: 80,
		HTTP: &shodan.HTTP{Status: 401, Title: "Login"},
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel: "Critical",
		RiskScore: 90,
		IsOpen:    false,
		Vulnerabilities: []minimax.Vulnerability{
			{
				ID:       "VULN-001",
				Title:    "Known firmware CVE",
				Severity: "Critical",
				Evidence: "Product banner shows old firmware",
			},
		},
		CveReferences: []string{"CVE-2021-36260"},
		ExploitPaths:  []string{"Attempt exploit after authentication"},
		AuthAnalysis: minimax.AuthAnalysis{
			AuthRequired: true,
			AuthType:     "digest",
		},
	}

	decision := enforceReportableAssessment(camera, assessment)

	if decision.Reportable {
		t.Fatalf("auth-required CVE-only result should not be reportable")
	}
	if assessment.RiskLevel != "Low" || assessment.RiskScore > 20 {
		t.Fatalf("expected downgraded low risk, got %s %d", assessment.RiskLevel, assessment.RiskScore)
	}
	if assessment.IsOpen || assessment.DefaultCreds || assessment.Exploitable {
		t.Fatalf("expected access flags to be cleared")
	}
	if len(assessment.Vulnerabilities) != 0 || len(assessment.CveReferences) != 0 || len(assessment.ExploitPaths) != 0 {
		t.Fatalf("expected non-exploitable findings to be cleared")
	}
}

func TestEnforceReportableAssessmentAllowsConfirmedOpenAccess(t *testing.T) {
	camera := shodan.Camera{
		IP:     "192.0.2.20",
		Port:   554,
		Banner: "RTSP/1.0 200 OK live stream",
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel: "High",
		RiskScore: 70,
		IsOpen:    true,
		Summary:   "Confirmed open RTSP stream with no authentication.",
		AuthAnalysis: minimax.AuthAnalysis{
			AuthRequired: false,
			AuthType:     "none",
		},
	}

	decision := enforceReportableAssessment(camera, assessment)

	if !decision.Reportable {
		t.Fatalf("confirmed open access should be reportable: %s", decision.Reason)
	}
	if assessment.RiskLevel != "High" || !assessment.IsOpen {
		t.Fatalf("expected confirmed open assessment to remain intact")
	}
}

func TestEnforceReportableAssessmentRejectsLikelyDefaultCredentials(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.30",
		Port: 8080,
		HTTP: &shodan.HTTP{Status: 200, Title: "Camera Login"},
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel:    "High",
		RiskScore:    65,
		DefaultCreds: true,
		Summary:      "Login page is exposed and likely default credentials are active.",
		AuthAnalysis: minimax.AuthAnalysis{
			AuthRequired: true,
			AuthType:     "form",
		},
	}

	decision := enforceReportableAssessment(camera, assessment)

	if decision.Reportable {
		t.Fatalf("likely default credentials should not be reportable")
	}
	if assessment.DefaultCreds {
		t.Fatalf("unconfirmed default credentials should be cleared")
	}
}

func TestEnforceReportableAssessmentAllowsConfirmedBypass(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.40",
		Port: 80,
		HTTP: &shodan.HTTP{Status: 401, Title: "Login"},
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel: "Critical",
		RiskScore: 85,
		AuthAnalysis: minimax.AuthAnalysis{
			AuthRequired:   true,
			AuthType:       "digest",
			BypassPossible: true,
			BypassMethod:   "Unauthenticated configuration endpoint is exposed by the banner.",
		},
		Exploitable:     true,
		ExploitEvidence: "HTTP banner exposes unauthenticated configuration download endpoint.",
	}

	decision := enforceReportableAssessment(camera, assessment)

	if !decision.Reportable {
		t.Fatalf("confirmed bypass should be reportable: %s", decision.Reason)
	}
}

func TestEnforceReportableAssessmentRejectsBypassWithoutMethod(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.50",
		Port: 80,
		HTTP: &shodan.HTTP{Status: 401, Title: "Login"},
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel: "High",
		RiskScore: 60,
		AuthAnalysis: minimax.AuthAnalysis{
			AuthRequired:   true,
			AuthType:       "basic",
			BypassPossible: true,
		},
		Vulnerabilities: []minimax.Vulnerability{
			{
				ID:       "VULN-001",
				Title:    "Firmware has historical CVE",
				Severity: "High",
				Evidence: "Product banner shows an old firmware string.",
			},
		},
	}

	decision := enforceReportableAssessment(camera, assessment)

	if decision.Reportable {
		t.Fatalf("bypass without a concrete method should not be reportable")
	}
}
