package evidence

import (
	"reflect"
	"testing"
)

func testEvidence() *Evidence {
	return &Evidence{
		Kind:       KindPE,
		TargetArch: "amd64",
		DepNodes: []Node{
			{Module: "app.exe", Status: "present"},
			{Module: "kernel32.dll", Status: "present", Source: "known"},
			{Module: "vcruntime140.dll", Status: "missing"},
			{Module: "missing.dll", Status: "missing"},
		},
		Events: []Event{
			ProcessStart{Common: Common{EventProcessStart, at(), SourceTrace}},
			ModuleLoaded{Common: Common{EventModuleLoaded, at(), SourceTrace}, Path: "kernel32.dll", Found: true},
			StartFailed{Common: Common{EventStartFailed, at(), SourceCLI}, ErrorCode: 740, Message: "elevation required"},
		},
		Env: Env{OS: "windows", Arch: "amd64"},
	}
}

func TestEvidenceNodeAndMissingNodes(t *testing.T) {
	ev := testEvidence()
	if n, ok := ev.Node("kernel32.dll"); !ok || n.Status != "present" {
		t.Errorf("Node(kernel32.dll) = %+v, %v; want present, true", n, ok)
	}
	if _, ok := ev.Node("absent.dll"); ok {
		t.Error("Node(absent.dll) reported found, want false")
	}
	missing := ev.MissingNodes()
	if len(missing) != 2 {
		t.Fatalf("MissingNodes len = %d, want 2", len(missing))
	}
	if missing[0].Module != "vcruntime140.dll" || missing[1].Module != "missing.dll" {
		t.Errorf("MissingNodes = %+v, want the two missing modules in order", missing)
	}
}

func TestEvidenceStartFailedAndExit(t *testing.T) {
	ev := testEvidence()
	sf, ok := ev.StartFailed()
	if !ok || sf.ErrorCode != 740 {
		t.Errorf("StartFailed = %+v, %v; want code 740, true", sf, ok)
	}
	if _, ok := ev.Exit(); ok {
		t.Error("Exit reported present, want false")
	}

	ex := Exit{Common: Common{EventExit, at(), SourceTrace}, ExitCode: 1, Signal: 0}
	ev.Events = append(ev.Events, ex)
	got, ok := ev.Exit()
	if !ok || got.ExitCode != 1 {
		t.Errorf("Exit = %+v, %v; want code 1, true", got, ok)
	}
}

func TestEvidenceLoaderErrors(t *testing.T) {
	ev := testEvidence()
	if got := ev.LoaderErrors(); len(got) != 0 {
		t.Errorf("LoaderErrors len = %d, want 0", len(got))
	}
	le := LoaderError{Common: Common{EventLoaderError, at(), SourceTrace}, Path: "x", Message: "parse failed"}
	ev.Events = append(ev.Events, le)
	if got := ev.LoaderErrors(); len(got) != 1 || got[0].Message != "parse failed" {
		t.Errorf("LoaderErrors = %+v, want one parse-failed error", got)
	}
}

func TestEvidenceModuleLoaded(t *testing.T) {
	ev := testEvidence()
	got := ev.ModuleLoaded()
	if len(got) != 1 || got[0].Path != "kernel32.dll" {
		t.Errorf("ModuleLoaded = %+v, want one kernel32.dll", got)
	}
}

func TestEvidenceOutputAndOutputContains(t *testing.T) {
	ev := &Evidence{Events: []Event{
		Output{Common: Common{EventOutput, at(), SourceTrace}, Stream: "stdout", Lines: []string{"hello", "world"}},
		Output{Common: Common{EventOutput, at(), SourceTrace}, Stream: "stderr", Lines: []string{"listen tcp :8080: bind: address already in use"}, Truncated: true},
	}}
	text, truncated := ev.Output("stderr")
	if text != "listen tcp :8080: bind: address already in use\n" {
		t.Errorf("Output(stderr) = %q", text)
	}
	if !truncated {
		t.Error("Output(stderr) truncated = false, want true")
	}
	if !ev.OutputContains("address already in use") {
		t.Error("OutputContains did not find address-in-use line")
	}
	if ev.OutputContains("bogus") {
		t.Error("OutputContains found bogus substring")
	}
}

func TestEvidenceFromEventsOfflineRebuild(t *testing.T) {
	env := Env{OS: "linux", Arch: "amd64", CWD: "/tmp"}
	events := []Event{
		GraphSnapshot{
			Common:  Common{EventGraphSnapshot, at(), SourceInspect},
			Kind:    "elf",
			Machine: "amd64",
			Class:   "64",
			Nodes:   []Node{{Module: "app", Status: "present"}, {Module: "libfoo.so.1", Status: "missing"}},
		},
		EnvSnapshot{Common: Common{EventEnvSnapshot, at(), SourceEnv}, Env: env},
	}
	ev := EvidenceFromEvents(events)
	if ev.Kind != KindELF {
		t.Errorf("Kind = %q, want elf", ev.Kind)
	}
	if ev.TargetArch != "amd64" || ev.TargetClass != "64" {
		t.Errorf("TargetArch/TargetClass = %q/%q, want amd64/64", ev.TargetArch, ev.TargetClass)
	}
	if ev.SourcePath != "app" {
		t.Errorf("SourcePath = %q, want app", ev.SourcePath)
	}
	if !reflect.DeepEqual(ev.DepNodes, []Node{{Module: "app", Status: "present"}, {Module: "libfoo.so.1", Status: "missing"}}) {
		t.Errorf("DepNodes = %+v", ev.DepNodes)
	}
	if ev.Env.OS != "linux" || ev.Env.Arch != "amd64" {
		t.Errorf("Env = %+v", ev.Env)
	}
}
