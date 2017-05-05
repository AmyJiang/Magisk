package ipc

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type Command struct {
	Bin      []string
	OutFile  *os.File
	Out      []byte
	Shutdown bool
}

const (
	bufSize    = 100
	outputSize = 1 << 24
)

var (
	traceTool = os.Getenv("GOPATH") + "/src/ExecTrace/obj-intel64/exectrace.so"
)

func createMapping(size int) (f *os.File, mem []byte, err error) {
	f, err = ioutil.TempFile("/tmp", "dbg-shm")
	if err != nil {
		err = fmt.Errorf("failed to create temp file: %v", err)
		return
	}

	if err = f.Truncate(int64(size)); err != nil {
		err = fmt.Errorf("failed to truncate shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	f.Close()
	f, err = os.OpenFile(f.Name(), os.O_RDWR, 0)
	if err != nil {
		err = fmt.Errorf("failed to open shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	mem, err = syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		err = fmt.Errorf("failed to mmap shm file: %v", err)
		f.Close()
		os.Remove(f.Name())
		return
	}
	return
}

func closeMapping(f *os.File, mem []byte) error {
	err1 := syscall.Munmap(mem)
	err2 := f.Close()
	err3 := os.Remove(f.Name())
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	default:
		return nil
	}
}

func MakeCommand(pin string, Bin string, pid int) (*Command, error) {
	outf, outmem, err := createMapping(outputSize)
	if err != nil {
		return nil, err
	}
	defer func() {
		if outf != nil {
			closeMapping(outf, outmem)
		}
	}()

	command := &Command{
		// TODO(tracetool? concurrently call?)
		Bin:      []string{pin, "-t", traceTool, "-mem", "0", "-o", "/tmp/exectrace.out", "--", Bin, ""},
		OutFile:  outf,
		Out:      outmem,
		Shutdown: false,
	}

	pidStr := fmt.Sprint(pid)
	// New link for Pin
	binCopy1 := command.Bin[0] + pidStr
	if err := os.Link(command.Bin[0], binCopy1); err == nil || os.IsExist(err) {
		command.Bin[0] = binCopy1
	} else {
		return nil, err
	}

	// New link for Binary (?)
	binCopy2 := command.Bin[8] + pidStr
	if err := os.Link(command.Bin[8], binCopy2); err == nil || os.IsExist(err) {
		command.Bin[8] = binCopy2
	} else {
		return nil, err
	}

	outf = nil
	return command, nil
}

func (command *Command) Close() error {
	var err1, err2, err3 error
	err1 = closeMapping(command.OutFile, command.Out)
	err2 = os.Remove(command.Bin[0])
	err3 = os.Remove(command.Bin[8])
	switch {
	case err1 != nil:
		return err1
	case err2 != nil:
		return err2
	case err3 != nil:
		return err3
	default:
		return nil
	}
}

func RunCommand(bin []string) (string, error) {
	var buf bytes.Buffer
	cmd := exec.Command(bin[0], bin[1:]...)
	cmd.Stderr = ioutil.Discard
	cmd.Stdout = &buf
	err := cmd.Run()
	return string(buf.Bytes()), err
}

func RunCommandAsync(bin []string, timeout time.Duration) error {
	cmd := exec.Command(bin[0], bin[1:]...)
	cmd.Stderr = ioutil.Discard
	cmd.Stdout = ioutil.Discard

	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(timeout):
		if err := cmd.Process.Kill(); err != nil {
			log.Fatal("failed to kill: ", err)
		}
		return fmt.Errorf("process killed as timeout reached %s")
	case err := <-done:
		return err
	}

	return nil
}
