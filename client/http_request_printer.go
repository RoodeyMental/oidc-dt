package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	println(formatRequest(r))
}

func main() {
	http.HandleFunc("/callback", callbackHandler)

	server := &http.Server{
		Addr: "localhost:5555",
	}

	log.Fatal(server.ListenAndServe())

}

// formatRequest generates ascii representation of a request
func formatRequest(r *http.Request) string {
	// Create return string
	var request []string // Add the request string
	url := fmt.Sprintf("%v %v %v", r.Method, r.URL, r.Proto)
	request = append(request, url)                             // Add the host
	request = append(request, fmt.Sprintf("Host: %v", r.Host)) // Loop through headers
	for name, headers := range r.Header {
		name = strings.ToLower(name)
		for _, h := range headers {
			request = append(request, fmt.Sprintf("%v: %v", name, h))
		}
	}

	// If this is a POST, add post data
	if r.Method == "POST" {
		r.ParseForm()
		request = append(request, "\n")
		request = append(request, r.Form.Encode())
	} // Return the request as a string
	return strings.Join(request, "\n")
}
