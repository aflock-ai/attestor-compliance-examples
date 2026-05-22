package cilock.verify

import rego.v1

# Behavioral detection: flag suspicious file access patterns in trace data.
# When cilock evaluates this against a command-run attestation, input = the
# command-run attestation object (processes, stdout, exitcode, cmd).

deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    startswith(file, "/tmp/runner_collected")
    msg := sprintf("Suspicious file access: process %s (PID %d) opened %s — matches credential harvesting pattern",
        [proc.program, proc.processid, file])
}

deny contains msg if {
    some proc in input.processes
    some file in object.keys(proc.openedfiles)
    file == "/proc/self/environ"
    msg := sprintf("Suspicious file access: process %s (PID %d) read /proc/self/environ — environment variable harvesting indicator",
        [proc.program, proc.processid])
}
