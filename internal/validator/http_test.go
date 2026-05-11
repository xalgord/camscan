package validator

import "testing"

func TestClassifyHTMLDetectsLogin(t *testing.T) {
	result := HTTPValidation{}
	classifyHTML(&result, `<html><title>Camera Login</title><body><form action="/login"><input name="username"><input type="password"></form></body></html>`)

	if !result.AuthRequired || !result.LoginDetected {
		t.Fatalf("expected login/auth detection, got %+v", result)
	}
	if result.OpenContent {
		t.Fatalf("login page must not be open content")
	}
}

func TestClassifyHTMLDetectsOpenCameraContent(t *testing.T) {
	result := HTTPValidation{}
	classifyHTML(&result, `<html><title>Live View</title><body><h1>Network Camera Live View</h1><canvas id="video"></canvas><p>PTZ channel stream snapshot playback controls</p></body></html>`)

	if !result.OpenContent {
		t.Fatalf("expected open camera content, got %+v", result)
	}
	if result.AuthRequired || result.LoginDetected || result.BlankPage {
		t.Fatalf("open camera content should not be classified as auth/blank: %+v", result)
	}
}

func TestClassifyHTMLDoesNotTreatPasswordTextAloneAsLogin(t *testing.T) {
	result := HTTPValidation{}
	classifyHTML(&result, `<html><title>Live View</title><body><h1>Network Camera Live View</h1><canvas id="video"></canvas><p>PTZ channel stream snapshot playback controls change password logout</p></body></html>`)

	if !result.OpenContent {
		t.Fatalf("expected camera content despite settings/password text, got %+v", result)
	}
	if result.AuthRequired || result.LoginDetected {
		t.Fatalf("password text alone should not be classified as a login wall: %+v", result)
	}
}

func TestClassifyHTMLDetectsBlankPage(t *testing.T) {
	result := HTTPValidation{}
	classifyHTML(&result, `<html><body></body></html>`)

	if !result.BlankPage {
		t.Fatalf("expected blank page, got %+v", result)
	}
	if result.OpenContent {
		t.Fatalf("blank page must not be open content")
	}
}

func TestSanitizeCredentialURLAndErrors(t *testing.T) {
	creds := Credentials{Username: "admin", Password: "admin:123"}
	raw := withURLCredentials("http://192.0.2.10:80/", creds)

	if raw == "http://192.0.2.10:80/" {
		t.Fatalf("expected URL credentials to be added")
	}
	if sanitized := sanitizeURL(raw); sanitized != "http://192.0.2.10:80/" {
		t.Fatalf("expected credentials stripped from URL, got %q", sanitized)
	}
	errText := sanitizeCredentialText("failed with admin:123 and admin%3A123", &creds)
	if errText != "failed with ******** and ********" {
		t.Fatalf("expected password to be redacted, got %q", errText)
	}
}
