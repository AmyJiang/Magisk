package main

import (
    "bufio"
	"exectraces"
	"flag"
	"fmt"
	"io/ioutil"
	"ipc"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
	flagPin         = flag.String("pin", "pin", "path to pin")
	flagBin         = flag.String("bin", "", "path to fuzzed binary")
	flagProcs       = flag.Int("procs", 1, "number of parallel processes")
	flagInputDir    = flag.String("inputdir", ".", "directory of input")

	logger = log.New(os.Stdout, "Dbg: ", log.Lshortfile)
	traces = exectraces.NewExecTraces()

	statReport uint64
	statTrace  uint64
	statQuery  uint64
)

const (
	bufSize    = 100
	outputSize = 1 << 24
	traceTool  = "../ExecTrace/obj-intel64/exectrace.so"
)

func process(pid int, command *ipc.Command, report *Report) ([]uint64, error) {
	off, err := command.OutFile.Seek(0, 0)
	if err != nil || off != 0 {
		return nil, err
	}
	command.Bin[5] = report.input
	logger.Printf("command = %v", command.Bin)
	cmd := exec.Command(command.Bin[0], command.Bin[1:]...)
	cmd.ExtraFiles = []*os.File{command.OutFile}
	cmd.Env = []string{}
	// required or not?
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
		Pgid:    0,
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to start tracer binary: %v", err)
	}

	out := ((*[1 << 24]uint64)(unsafe.Pointer(&command.Out[0])))[:len(command.Out)/int(unsafe.Sizeof(uint64(0)))]
	total := out[0]
	out = out[1:]
	trace := out[:total]
    return trace, nil
}

func insert(trace []uint64, key string) error {
	if err := traces.Insert(trace, key); err != nil {
		return err
	}
	return nil
}

func query(trace []uint64) error {
	found, diff := traces.Query(trace)
	logger.Printf("Found = %v, diff = %v\n", found, diff)
    return nil
}


func runDebugger() {
//	outputdir := filepath.Join(*flagWorkdir, "diff-dbg")
//	os.MkdirAll(outputdir, 0700)

	// Create worker processes
	reports := make(chan *Report, bufSize)
	done := make(chan struct{}, *flagProcs)
	cmds := make([]*ipc.Command, *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		command, err := ipc.MakeCommand(*flagPin, *flagBin, pid)
		if err != nil {
			log.Panic(err)
		}
		cmds[pid] = command

		pid := pid
		go func() {
			for report := range reports {
				if command.Shutdown {
					break
				}
				trace, err := process(pid, command, report)
				if err != nil {
					logger.Printf("Process %v exited: %v\n", pid, err)
					break
				}
                if report.op == INSERT {
                    if err := insert(trace, report.input); err != nil {
                        logger.Printf("Insert trace failed")
					    break
                    }
                    atomic.AddUint64(&statTrace, 1)
                }
                if report.op == QUERY {
                    if err := query(trace); err != nil {
                        logger.Printf("Query trace failed")
                        break
                    }
                    atomic.AddUint64(&statQuery, 1)
                }
			}
			command.Close()
			done <- struct{}{}
		}()
	}
	logger.Printf("Debugger started (%v processes)", *flagProcs)

	// Create server (TODO: RPC/TPC?)

	// Main loop, currently input files from local directory
	logger.Printf("Loading input from %v...", *flagInputDir)
	files, err := ioutil.ReadDir(*flagInputDir)
	if err != nil {
		logger.Panic("failed to read diretory: ", *flagInputDir)
	}



	c := make(chan os.Signal, *flagProcs+1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

    queries := make(chan string, bufSize)
    go func() {
        scanner := bufio.NewScanner(os.Stdin)
        for scanner.Scan() {
            queries <-scanner.Text()
        }
        close(queries)
        if err := scanner.Err(); err != nil {
            logger.Printf("Reading stdin failed")
            c <-os.Interrupt
        }
    }()

	ticker := time.NewTicker(20 * time.Second).C
	for i := 0; ; i++ {
		select {
		case <-ticker:
			logger.Printf("Received %v reports, generated %v traces)", statReport, atomic.LoadUint64(&statTrace))
			break
		case <-c:
			logger.Printf("Shutdowning processes...")
			close(reports)
			for j := 0; j < *flagProcs; j++ {
				cmds[j].Shutdown = true
			}
			for j := 0; j < *flagProcs; j++ {
				<-done
			}
			logger.Printf("Received %v reports, generated %v traces)", statReport, atomic.LoadUint64(&statTrace))
			os.Exit(1)
            break
        case q :=<-queries:
            logger.Printf("Received query for %v", q)
            report := &Report{
                input:  q,
                output: 1,
                op:     QUERY,
            }
            reports <- report
            statReport++
            break
		default:
			// load report
			if statReport < uint64(len(files)) {
				filename := filepath.Join(*flagInputDir, files[statReport].Name())
				report := &Report{
					input:  filename,
					output: 1,
                    op:     INSERT,
				}
				reports <- report
				statReport++
			}
		}
	}
}

func main() {
	flag.Parse()
	if *flagBin == "" {
		fmt.Errorf("flag binary is required")
		os.Exit(1)
	}
	runDebugger()
}
