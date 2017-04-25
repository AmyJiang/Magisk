package main

import (
	"bytes"
	"html/template"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type File struct {
	Name  string
	Body  template.HTML
	Lines int
}

type Slice struct {
	Files []*File
	Name  string
}

type FileArray []*File

func (arr FileArray) Len() int {
	return len(arr)
}

func (arr FileArray) Swap(i, j int) {
	arr[i], arr[j] = arr[j], arr[i]
}

func (arr FileArray) Less(i, j int) bool {
	return arr[i].Name < arr[j].Name
}

func parseFile(file string) ([][]byte, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	htmlReplacer := strings.NewReplacer(">", "&gt;", "<", "&lt;", "&", "&amp;", "\t", "    ")
	var lines [][]byte
	for {
		idx := bytes.IndexByte(data, '\n')
		if idx == -1 {
			break
		}
		lines = append(lines, []byte(htmlReplacer.Replace(string(data[:idx]))))
		data = data[idx+1:]
	}
	if len(data) != 0 {
		lines = append(lines, data)
	}
	return lines, nil
}

func generateSliceHtml(w io.Writer, slice_file *SliceFile) error {
	prefix := filepath.Join(os.Getenv("GOPATH"), "libs")

	var slice Slice
	slice.Name = slice_file.Name

	for f, ls := range slice_file.Slice {
		lines, err := parseFile(f)
		if err != nil {
			return err
		}

		var buf bytes.Buffer
		cnt := 0
		for n, l := range lines {
			if cnt < len(ls) && n == ls[cnt]-1 {
				buf.Write([]byte("<span class='in_slice'>"))
				buf.Write(l)
				buf.Write([]byte("</span>\n"))
				cnt++
			} else {
				// buf.Write([]byte("<span class='not_in_slice'>"))
				buf.Write(l)
				buf.Write([]byte("\n"))
				//				buf.Write([]byte("</span>\n"))
			}

		}
		slice.Files = append(slice.Files, &File{
			Name:  f[len(prefix):],
			Body:  template.HTML(buf.String()),
			Lines: len(ls),
		})

	}

	sort.Sort(FileArray(slice.Files))
	if err := sliceTemplate.Execute(w, slice); err != nil {
		return nil
	}
	return nil
}

var sliceTemplate = template.Must(template.New("Slice").Parse(`
<!DOCTYPE html>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
		<style>
			body {
				background: white;
			}
			#topbar {
				background: black;
				position: fixed;
				top: 0; left: 0; right: 0;
				height: 42px;
				border-bottom: 1px solid rgb(70, 70, 70);
			}
			#nav {
				float: left;
				margin-left: 10px;
				margin-top: 10px;
			}
			#content {
				font-family: 'Courier New', Courier, monospace;
				color: rgb(70, 70, 70);
				margin-top: 50px;
			}
			.not_in_slice {
				color: rgb(0, 0, 0);
				font-weight: bold;
			}
			.in_slice {
				color: rgb(255, 0, 0);
				font-weight: bold;
			}
		</style>
	</head>
	<body>
        <h>Slice: </h>
        <br>
		<div id="topbar">
			<div id="nav">
				<select id="files">
				{{range $i, $f := .Files}}
                <option value="file{{$i}}">{{$f.Name}}: {{$f.Lines}} </option>
				{{end}}
				</select>
			</div>
		</div>
		<div id="content">
		{{range $i, $f := .Files}}
		<pre class="file" id="file{{$i}}" {{if $i}}style="display: none"{{end}}>{{$f.Body}}</pre>
		{{end}}
		</div>
	</body>
	<script>
	(function() {
		var files = document.getElementById('files');
		var visible = document.getElementById('file0');
		files.addEventListener('change', onChange, false);
		function onChange() {
			visible.style.display = 'none';
			visible = document.getElementById(files.value);
			visible.style.display = 'block';
			window.scrollTo(0, 0);
		}
	})();
	</script>
</html>
`))
