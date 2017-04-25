package main

import (
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	flagDir     = flag.String("dir", "", "slices directory")
	logger      = log.New(os.Stdout, "", 0)
	slice_files []SliceFile
)

type SliceFile struct {
	Name  string
	Link  string
	Slice map[string]([]int)
}

func slice(w http.ResponseWriter, r *http.Request) {
	paths := strings.Split(r.URL.Path, "/")
	if len(paths) != 3 {
		logger.Printf("[ERROR] \tInvalid path: %v", r.URL.Path)
		return
	}
	idx, err := strconv.Atoi(paths[2])
	if err != nil {
		logger.Printf("[ERROR] \t%v", err)
		return
	}

	if err := load_slice(idx); err != nil {
		logger.Printf("[ERROR] \t%v", err)
		return
	}

	if err := generateSliceHtml(w, &slice_files[idx]); err != nil {
		logger.Printf("[ERROR] \t%v", err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	if err := indexTemplate.Execute(w, slice_files); err != nil {
		http.Error(w, fmt.Sprintf("failed to execute template: %v", err), http.StatusInternalServerError)
	}
}

func load_slice(idx int) error {
	if idx < 0 || idx >= len(slice_files) {
		return fmt.Errorf("Slice index %d is out of range", idx)
	}

	if slice_files[idx].Slice != nil {
		return nil
	}

	slice := &slice_files[idx]
	logger.Printf("[INFO] \tLoading slice file %s", filepath.Join(*flagDir, slice.Name))
	content, err := ioutil.ReadFile(filepath.Join(*flagDir, slice.Name))
	if err != nil {
		logger.Printf("[ERROR] \t%v", err)
		return err
	}

	lines := strings.Split(string(content), "\n")
	logger.Printf("[INFO] \tNumber of lines in slice = %v", len(lines)-1)
	slice.Slice = make(map[string]([]int))
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 2 {
			logger.Printf("[ERROR] \tline = %v", line)
			return fmt.Errorf("Unkown slice format")
		}
		f := fields[0]
		if f == "??" {
			continue
		}
		fields[1] = strings.Split(fields[1], " ")[0]
		l, err := strconv.ParseInt(fields[1], 10, 32)
		if err != nil {
			logger.Printf("[ERROR] \t%v", err)
			return err
		}
		slice.Slice[f] = append(slice.Slice[f], int(l))
	}
	return nil
}

func setup() {
	files, err := ioutil.ReadDir(*flagDir)
	if err != nil {
		logger.Panic("failed to read directory: ", *flagDir)
	}

	for idx, f := range files {
		slice_files = append(slice_files, SliceFile{
			Name:  f.Name(),
			Link:  fmt.Sprintf("/%s/%d", "slice", idx),
			Slice: nil,
		})
	}
}

func main() {
	flag.Parse()
	if *flagDir == "" {
		logger.Println("Must specify a slice directory to view")
		os.Exit(1)
	}

	setup()
	http.HandleFunc("/", index)
	http.HandleFunc("/slice/", slice)

	if err := http.ListenAndServe(":5000", nil); err != nil {
		logger.Panic("failed to start server on 5000")
	}
}

var indexTemplate = template.Must(template.New("Index").Parse(addStyle(`
<!doctype html>
<html>
<head>
	<title>magisk</title>
	{{STYLE}}
</head>
<body>
<b>magisk displayer</b>
<br>
<br>

<table>
    <caption>Slice</caption>
    {{range $s := $}}
    <tr>
        <td><a href="{{$s.Link}}">{{$s.Name}}</a></td>
    </tr>
    {{end}}
</table>
<br>
</body></html>
`)))

func addStyle(html string) string {
	return strings.Replace(html, "{{STYLE}}", htmlStyle, -1)
}

const htmlStyle = `
	<style type="text/css" media="screen">
		table {
			border-collapse:collapse;
			border:1px solid;
		}
		table caption {
			font-weight: bold;
		}
		table td {
			border:1px solid;
			padding: 3px;
		}
		table th {
			border:1px solid;
			padding: 3px;
		}
		textarea {
			width:100%;
		}
	</style>
`
