package main

import (
	"flag"
	"fmt"
	"html/template"
	"net/http"
	"os"

	"github.com/gorilla/handlers"
)

func main() {
	local := flag.String("local", ":3055", "local address to bind to")
	flag.Parse()

	http.Handle("/hello", &helloHandler{})
	http.Handle("/", http.NotFoundHandler())

	handler := handlers.LoggingHandler(os.Stdout, http.DefaultServeMux)
	err := http.ListenAndServe(*local, handler)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

const helloTemplateText = `<head>
  <title>Welcome</title>
</head>

<body>
<h1>Welcome</h1>
<p>Hello {{.Addr}}.</p>
<p>Using SCION {{.SCION}}.</p>
</body>
`

var helloTemplate = template.Must(template.New("foo").Parse(helloTemplateText))

type helloHandler struct{}

func (h *helloHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {

	err := helloTemplate.Execute(w, struct {
		Addr  string
		SCION string
	}{
		Addr: func() string {
			if addr := req.Header.Get("X-Scion-Remote-Addr"); addr != "" {
				return addr
			}
			return req.RemoteAddr
		}(),
		SCION: req.Header.Get("X-Scion"),
	})
	if err != nil {
		panic(err)
	}
}
