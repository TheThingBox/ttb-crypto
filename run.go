package ttb_crypto

import (
	"bytes"
	"os/exec"
)

func run(command string) (resp string, err error) {
	var out bytes.Buffer
	resp = ""
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = &out
	err = cmd.Run()
	if err == nil {
		resp = string(out.Bytes())
	}
	return
}
