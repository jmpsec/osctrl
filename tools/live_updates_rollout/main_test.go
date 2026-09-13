package main

import (
	"strings"
	"testing"
)

func TestParseListTrimsAndRejectsEmpty(t *testing.T) {
	got, err := parseList(" http://api-1:9002,https://api-2.example ")
	if err != nil {
		t.Fatalf("parseList: %v", err)
	}
	if len(got) != 2 || got[0] != "http://api-1:9002" || got[1] != "https://api-2.example" {
		t.Fatalf("unexpected list: %#v", got)
	}
	if _, err := parseList(" , "); err == nil {
		t.Fatal("empty list must fail")
	}
}

func TestParseSSEFrameReady(t *testing.T) {
	event, payload, err := parseSSEFrame("event: stream.ready\ndata: {\"environment_uuid\":\"all\",\"replay\":false}\n\n")
	if err != nil {
		t.Fatalf("parseSSEFrame: %v", err)
	}
	if event != "stream.ready" || payload["environment_uuid"] != "all" || payload["replay"] != false {
		t.Fatalf("unexpected parsed frame: event=%q payload=%v", event, payload)
	}
}

func TestParseHealthEventsComponent(t *testing.T) {
	body := []byte(`{
	  "components": [
	    {"id":"database","status":"operational"},
	    {"id":"events","status":"operational","details":{
	      "api":{"enabled":true,"healthy":true,"subscribers":3,"dropped":0},
	      "tls":{"enabled":true,"healthy":true,"subscribers":0,"dropped":0}
	    }}
	  ]
	}`)
	events, err := parseHealthEvents(body)
	if err != nil {
		t.Fatalf("parseHealthEvents: %v", err)
	}
	if events.Status != "operational" || events.API.Subscribers != 3 || !events.TLS.Enabled {
		t.Fatalf("unexpected health events: %+v", events)
	}
}

func TestParseHealthEventsComponentMissing(t *testing.T) {
	_, err := parseHealthEvents([]byte(`{"components":[{"id":"api","status":"operational"}]}`))
	if err == nil || !strings.Contains(err.Error(), "events component") {
		t.Fatalf("expected missing component error, got %v", err)
	}
}
