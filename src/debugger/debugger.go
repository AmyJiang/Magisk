package main

import (
	"bytes"
	"exectraces"
	"flag"
	"fmt"
	"io/ioutil"
	"ipc"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

type operation int

const (
	INSERT operation = iota
	QUERY
)

type Report struct {
	input  string
	output int
	op     operation
}

var (
	flagPin     = flag.String("pin", "pin", "path to pin")
	flagBin     = flag.String("bin", "", "path to fuzzed binary")
	flagProcs   = flag.Int("procs", 1, "number of parallel processes")
	flagWorkDir = flag.String("dir", ".", "path to working directory")
	flagInput   = flag.String("input", "", "a single input")
	flagQuery   = flag.String("query", "", "a single query")
	flagSlice   = flag.Bool("slice", false, "call slicer if the flag is set")
	flagLog     = flag.Bool("log", false, "print log")

	Logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)
	traces = exectraces.NewExecTraces()

	statReport uint64
	statInput  uint64
	statQuery  uint64

	inputDir string
	queryDir string
	traceDir string
	sliceDir string
	inputs   []string
	queries  []string
)

const (
	bufSize    = 100
	outputSize = 1 << 24
)

func process(pid int, command *ipc.Command, report *Report) ([]uint64, error) {
	off, err := command.OutFile.Seek(0, 0)
	if err != nil || off != 0 {
		return nil, err
	}

	if report.op == QUERY {
		command.Bin[4] = "1"
		input := filepath.Base(report.input)
		command.Bin[8] = filepath.Join(traceDir, input+".trace")
	}

	command.Bin[11] = report.input
	Logger.Printf("[INFO]: \tRuning process: %v\n", command.Bin)
	cmd := exec.Command(command.Bin[0], command.Bin[1:]...)
	cmd.ExtraFiles = []*os.File{command.OutFile}
	cmd.Env = []string{}
	// required or not?
	var stderr bytes.Buffer
	cmd.Stdout = ioutil.Discard // os.Stdout
	cmd.Stderr = &stderr

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to start tracer binary: %v", stderr.String())
	}

	out := ((*[1 << 24]uint64)(unsafe.Pointer(&command.Out[0])))[:len(command.Out)/int(unsafe.Sizeof(uint64(0)))]
	total := out[0]
	out = out[1:]
	trace := out[:total]
	return trace, nil
}

func insert(trace []uint64, key string) error {
	Logger.Printf("[INFO]: \tInsert trace of %v\n", key)
	if err := traces.Insert(trace, key); err != nil {
		return err
	}
	return nil
}

func addr2line(diff uint64) error {
	hdiff := fmt.Sprintf("%x", diff)
	bin := []string{"addr2line", "-e", *flagBin, hdiff}
	out, err := ipc.RunCommand(bin)
	if err != nil {
		return err
	}
	Logger.Printf("[INFO]: \t\tLast Common BBL = %v\n", out)
	return nil
}

func query(trace []uint64) (bool, int) {
	found, length := traces.Query(trace)
	Logger.Printf("[INFO]: \t\tfound %v, Length %d\n", found, length)

	if !found {
		if err := addr2line(trace[length-1]); err != nil {
			Logger.Printf("[ERROR]: \t\t%v\n", err)
		}
	}

	return found, length
}

func runDebugger() {
	//	outputdir := filepath.Join(*flagWorkdir, "diff-dbg")
	//	os.MkdirAll(outputdir, 0700)

	// Create worker processes
	reports := make(chan *Report, bufSize)
	done := make(chan struct{}, *flagProcs)
	doneTrace := make(chan struct{}, 1)
	cmds := make([]*ipc.Command, *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		command, err := ipc.MakeCommand(*flagPin, *flagBin, pid)
		if err != nil {
			log.Panic(err)
		}
		cmds[pid] = command

		pid := pid
		rt := rand.Int31n(1000)
		Logger.Printf("[INFO]: \tCreated worker %v", pid)
		go func() {
			time.Sleep(time.Duration(rt) * time.Millisecond)
			for report := range reports {
				if command.Shutdown {
					break
				}
				input := filepath.Base(report.input)
				Logger.Printf("[INFO]: \tCreating trace: %v", input)
				trace, err := process(pid, command, report)
				if err != nil {
					atomic.AddUint64(&statInput, 1)
					fmt.Fprintf(os.Stderr, "[ERROR]: %s.trace: %v\n", input, err)
					break
				}
				if report.op == INSERT {
					if err := insert(trace, report.input); err != nil {
						fmt.Fprintf(os.Stderr, "[ERROR]: %s.trace: %v\n", input, err)
						atomic.AddUint64(&statInput, 1)
						break
					}

					if atomic.AddUint64(&statInput, 1) == uint64(len(inputs)) {
						doneTrace <- struct{}{}
					}

				}
				if report.op == QUERY {
					Logger.Printf("[INFO]: \tQuerying %v", report.input)
					if found, length := query(trace); !found {
						fmt.Printf("%v:%v:%v\n", input, found, length)

						if *flagSlice {
							tracefile := filepath.Join(traceDir, input+".trace")
							slicefile := filepath.Join(sliceDir, input+".slice")
							bin := []string{os.Getenv("GOPATH") + "/src/slicer/slicer.py", cmds[pid].Bin[10], tracefile, fmt.Sprint(length), slicefile}
							Logger.Printf("[INFO]: \tExtracting slice\n")
							if err := ipc.RunCommandAsync(bin, 2*time.Minute); err != nil {
								fmt.Fprintf(os.Stderr, "[ERROR]: %s.slice: %s\n", input, err)
							} else {
								Logger.Printf("[INFO]: \tSlice is saved to %s\n", slicefile)
							}
						}
					}
					atomic.AddUint64(&statQuery, 1)
				}
			}
			command.Close()
			done <- struct{}{}
		}()
	}
	Logger.Printf("[INFO]: \tDebugger started (%v processes)\n", *flagProcs)

	// Create server (TODO: RPC/TPC?)

	/*
	 * Main loop, currently get input files from local directory
	 */

	// Load input
	if *flagInput != "" {
		inputs = append(inputs, filepath.Join(*flagWorkDir, *flagInput))
	} else {
		files, err := ioutil.ReadDir(inputDir)
		if err != nil {
			Logger.Panic("failed to read directory: ", inputDir)
		}
		for _, f := range files {
			inputs = append(inputs, filepath.Join(inputDir, f.Name()))
		}
	}
	Logger.Printf("[INFO]: \tLoaded %v inputs from %v\n", len(inputs), *flagWorkDir)

	// Load query
	if *flagQuery != "" {
		queries = append(queries, filepath.Join(*flagWorkDir, *flagQuery))
	} else {
		files, err := ioutil.ReadDir(queryDir)
		if err != nil {
			Logger.Panic("failed to read directory: ", queryDir)
		}
		for _, f := range files {
			queries = append(queries, filepath.Join(queryDir, f.Name()))
		}
	}
	Logger.Printf("[INFO]: \tLoaded %v queries from %v\n", len(queries), *flagWorkDir)

	// main loop, send report to worker processes
	c := make(chan os.Signal, *flagProcs+1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	ticker := time.NewTicker(20 * time.Second).C
	startQuery := false
	doneQuery := make(chan struct{}, 1)
	for i := 0; ; i++ {
		select {
		case <-ticker:
			Logger.Printf("[SUMMARY]: \tFinished %v inputs, %v queries\n", atomic.LoadUint64(&statInput), atomic.LoadUint64(&statQuery))
			break
		case <-c:
			Logger.Printf("[INFO]: \tShutting down processes...\n")
			close(reports)
			for j := 0; j < *flagProcs; j++ {
				cmds[j].Shutdown = true
			}
			for j := 0; j < *flagProcs; j++ {
				<-done
			}
			Logger.Printf("[SUMMARY]: \tFinished %v inputs, %v queries\n", atomic.LoadUint64(&statInput), atomic.LoadUint64(&statQuery))
			return
		case <-doneQuery:
			close(reports)
			Logger.Printf("[INFO]: \tWaiting for query results")
			for j := 0; j < *flagProcs; j++ {
				<-done
			}

			Logger.Printf("[SUMMARY]: \tFinished %v inputs, %v queries\n", atomic.LoadUint64(&statInput), atomic.LoadUint64(&statQuery))
			return
		case <-doneTrace:
			startQuery = true
			break
		default:
			// process input
			if statReport < uint64(len(inputs)) {
				report := &Report{
					input:  inputs[statReport],
					output: 1,
					op:     INSERT,
				}
				reports <- report
				statReport++
			}

			// process query
			if startQuery && statReport < uint64(len(inputs)+len(queries)) {
				report := &Report{
					input:  queries[statReport-uint64(len(inputs))],
					output: 1,
					op:     QUERY,
				}
				reports <- report
				statReport++
			}
			if statReport == uint64(len(inputs)+len(queries)) {
				doneQuery <- struct{}{}
			}
		}
	}
}

func setup() error {
	// set up working directory
	if *flagInput == "" {
		inputDir = filepath.Join(*flagWorkDir, "input")
		if file, err := os.Stat(inputDir); os.IsNotExist(err) || !file.Mode().IsDir() {
			fmt.Errorf("Must specify a single input, or provide a workdir/input/ directory")
			return err
		}
	}
	if *flagQuery == "" {
		queryDir = filepath.Join(*flagWorkDir, "query")
		if file, err := os.Stat(queryDir); os.IsNotExist(err) || !file.Mode().IsDir() {
			fmt.Errorf("Must specify a single input, or provide a workdir/input/ directory")
			return err
		}
	}

	traceDir = filepath.Join(*flagWorkDir, "traces")
	sliceDir = filepath.Join(*flagWorkDir, "slices")
	if err := os.MkdirAll(traceDir, 0776); err != nil {
		return err
	}
	if err := os.MkdirAll(sliceDir, 0776); err != nil {
		return err
	}
	return nil
}

func main() {
	debug.SetGCPercent(50)
	debug.FreeOSMemory()
	flag.Parse()
	if *flagBin == "" {
		fmt.Errorf("Must specify target binary")
		os.Exit(1)
	}
	if *flagWorkDir == "" {
		fmt.Errorf("Must specify work directory")
		os.Exit(1)
	}
	if !*flagLog {
		Logger.SetOutput(ioutil.Discard)
	}

	if err := setup(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	runDebugger()
}
