package analyzer

import (
	"strings"
	"testing"

	"github.com/xalgord/camscan/internal/minimax"
	"github.com/xalgord/camscan/internal/shodan"
	"github.com/xalgord/camscan/internal/validator"
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

func TestApplyHTTPValidationAuthWallSuppressesCandidate(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.60",
		Port: 80,
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel:    "Critical",
		RiskScore:    90,
		IsOpen:       true,
		DefaultCreds: true,
		Exploitable:  true,
		Summary:      "AI believed this was open.",
	}

	applyHTTPValidation(assessment, validator.HTTPValidation{
		Method:        "rod",
		TargetURL:     "http://192.0.2.60/",
		Attempted:     true,
		Reachable:     true,
		AuthRequired:  true,
		LoginDetected: true,
		Evidence:      []string{"Rod rendered a password input"},
	})
	decision := enforceReportableAssessment(camera, assessment)

	if decision.Reportable {
		t.Fatalf("active auth-wall validation should suppress candidate")
	}
	if assessment.IsOpen || assessment.DefaultCreds || assessment.Exploitable {
		t.Fatalf("active auth-wall validation should clear access flags")
	}
	if assessment.ActiveValidation == nil || !assessment.ActiveValidation.AuthRequired {
		t.Fatalf("expected active validation evidence to be attached")
	}
}

func TestApplyHTTPValidationOpenContentConfirmsCandidate(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.70",
		Port: 80,
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel: "Low",
		RiskScore: 10,
		Summary:   "AI was unsure.",
	}

	applyHTTPValidation(assessment, validator.HTTPValidation{
		Method:      "rod",
		TargetURL:   "http://192.0.2.70/",
		Attempted:   true,
		Reachable:   true,
		OpenContent: true,
		Evidence:    []string{"Rod rendered camera-related page content without a login form"},
	})
	decision := enforceReportableAssessment(camera, assessment)

	if !decision.Reportable {
		t.Fatalf("active open-content validation should confirm candidate: %s", decision.Reason)
	}
	if !assessment.IsOpen || !assessment.Exploitable {
		t.Fatalf("expected active validation to set open/exploitable flags")
	}
	if assessment.RiskScore < 60 || assessment.RiskLevel != "High" {
		t.Fatalf("expected active open content to raise risk to high, got %s %d", assessment.RiskLevel, assessment.RiskScore)
	}
}

func TestApplyHTTPValidationLoginSuccessConfirmsCandidate(t *testing.T) {
	camera := shodan.Camera{
		IP:   "192.0.2.80",
		Port: 80,
		HTTP: &shodan.HTTP{Status: 200, Title: "Camera Login"},
	}
	assessment := &minimax.SecurityAssessment{
		RiskLevel: "Low",
		RiskScore: 15,
		Summary:   "AI was unsure.",
		AuthAnalysis: minimax.AuthAnalysis{
			AuthRequired: true,
			AuthType:     "form",
		},
	}

	applyHTTPValidation(assessment, validator.HTTPValidation{
		Method:         "rod",
		TargetURL:      "http://192.0.2.80/",
		Attempted:      true,
		Reachable:      true,
		AuthRequired:   true,
		LoginDetected:  true,
		LoginAttempted: true,
		LoginSucceeded: true,
		LoginUsername:  "admin",
		OpenContent:    true,
		Evidence:       []string{"Rod confirmed camera content after submitting the supplied credential"},
	})
	decision := enforceReportableAssessment(camera, assessment)

	if !decision.Reportable {
		t.Fatalf("successful supplied-credential login should be reportable: %s", decision.Reason)
	}
	if assessment.IsOpen {
		t.Fatalf("authenticated login should not be marked as unauthenticated open access")
	}
	if !assessment.Exploitable {
		t.Fatalf("successful supplied-credential login should set exploitable evidence")
	}
	if assessment.ActiveValidation == nil || !assessment.ActiveValidation.LoginSucceeded {
		t.Fatalf("expected login success evidence to be attached")
	}
	if assessment.RiskScore < 70 || assessment.RiskLevel != "High" {
		t.Fatalf("expected active login success to raise risk to high, got %s %d", assessment.RiskLevel, assessment.RiskScore)
	}
}

func TestBrowserSetupErrorSuppressesFindings(t *testing.T) {
	assessment := &minimax.SecurityAssessment{
		RiskLevel:      "Critical",
		RiskScore:      95,
		IsOpen:         true,
		DefaultCreds:   true,
		Exploitable:    true,
		ExploitEvidence: "AI hallucinated open access",
		Summary:        "AI believed this was wide open.",
	}

	applyHTTPValidation(assessment, validator.HTTPValidation{
		Method:    "rod",
		TargetURL: "http://192.0.2.90/",
		Attempted: true,
		Error:     "Rod browser unavailable: exec: \"google-chrome\": executable file not found in $PATH",
	})

	if assessment.IsOpen {
		t.Fatalf("expected IsOpen to be cleared on Rod failure")
	}
	if assessment.DefaultCreds {
		t.Fatalf("expected DefaultCreds to be cleared on Rod failure")
	}
	if assessment.Exploitable {
		t.Fatalf("expected Exploitable to be cleared on Rod failure")
	}
	if assessment.ExploitEvidence != "" {
		t.Fatalf("expected ExploitEvidence to be cleared on Rod failure")
	}
	if !strings.Contains(assessment.Summary, "Rod/Chromium browser unavailable") {
		t.Fatalf("expected summary to indicate Rod failure, got: %s", assessment.Summary)
	}
}

func TestConfirmationTypeMapping(t *testing.T) {
	tests := []struct {
		name     string
		decision assessmentDecision
		active   *minimax.ActiveValidation
		want     string
	}{
		{
			name:     "not reportable → none",
			decision: assessmentDecision{Reportable: false, Reason: "auth required"},
			want:     "none",
		},
		{
			name:     "active open content → active_open",
			decision: assessmentDecision{Reportable: true, Reason: "confirmed open access"},
			active:   &minimax.ActiveValidation{OpenContent: true},
			want:     "active_open",
		},
		{
			name:     "active login → active_login",
			decision: assessmentDecision{Reportable: true, Reason: "confirmed login with supplied credential"},
			active:   &minimax.ActiveValidation{OpenContent: true, LoginSucceeded: true},
			want:     "active_login",
		},
		{
			name:     "passive bypass → passive_bypass",
			decision: assessmentDecision{Reportable: true, Reason: "confirmed authentication bypass"},
			want:     "passive_bypass",
		},
		{
			name:     "passive default creds → passive_creds",
			decision: assessmentDecision{Reportable: true, Reason: "confirmed working default credentials"},
			want:     "passive_creds",
		},
		{
			name:     "passive exploitable → passive_exploit",
			decision: assessmentDecision{Reportable: true, Reason: "confirmed exploitable issue"},
			want:     "passive_exploit",
		},
		{
			name:     "passive open → passive_open",
			decision: assessmentDecision{Reportable: true, Reason: "confirmed open access"},
			want:     "passive_open",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assessment := &minimax.SecurityAssessment{
				ActiveValidation: tc.active,
			}
			got := confirmationType(tc.decision, assessment)
			if got != tc.want {
				t.Fatalf("confirmationType() = %q, want %q", got, tc.want)
			}
		})
	}
}
