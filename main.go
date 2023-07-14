package main

import (
	"flag"
	"os"
	errorlog "pe-parser/error-log"
	"pe-parser/pe"
)

var (
	filename string
)

func init() {
	flag.StringVar(&filename, "f", "", "specify the file name")
}

func main() {
	flag.Parse()

	if filename == "" {
		errorlog.LogError(errorlog.FILE_NOT_SET)
		os.Exit(1)
	}

	p := pe.NewPE32(filename)
}
