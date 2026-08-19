// doctor.go implements the `why doctor` self-diagnostics: a pass/fail report
// of the host prerequisites why needs to diagnose reliably. doctor takes no
// target; it exits 0 when everything is OK and 1 when a prerequisite is
// missing.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"why/internal/collect"
)

// check is one doctor result.
type check struct {
	name   string
	ok     bool
	detail string
}

// doctorPipeline runs the host self-checks and prints a table. It returns 0
// when all pass, or a tool failure (exit 1) when any prerequisite is missing.
func doctorPipeline(rest []string) (int, error) {
	if len(rest) != 0 {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: doctor: unexpected argument %q", rest[0])}
	}
	env := collect.CollectEnv()

	checks := []check{
		{"operating system", env.OS != "", env.OS + "/" + env.Arch},
		{"working directory", env.CWD != "", env.CWD},
		{"PATH set", len(env.Paths) > 0, "PATH has " + fmt.Sprint(len(env.Paths)) + " entries"},
	}
	// The working directory must be writable (doctor's own temp probe).
	if env.CWD != "" {
		probe := filepath.Join(env.CWD, ".why-doctor-probe")
		if err := os.WriteFile(probe, []byte("ok"), 0o644); err != nil {
			checks[1].ok = false
			checks[1].detail = env.CWD + " (not writable: " + err.Error() + ")"
		} else {
			os.Remove(probe)
		}
	}

	checks = append(checks, platformChecks(env)...)

	failures := 0
	fmt.Printf("why doctor -- %s/%s\n", env.OS, env.Arch)
	for _, c := range checks {
		mark := "[ok]"
		if !c.ok {
			mark = "[fail]"
			failures++
		}
		detail := c.detail
		if detail == "" {
			detail = c.name
		}
		fmt.Printf("%s  %s\n", mark, detail)
	}
	if failures > 0 {
		return 0, &exitError{code: 1, msg: fmt.Sprintf("why: doctor: %d prerequisite problem(s) found", failures)}
	}
	fmt.Println("all prerequisites OK")
	return 0, nil
}
