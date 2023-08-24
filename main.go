package main

import (
	"encoding/json"
	"flag"
	"log"
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
	p.Init()
	p.ParseHeader()

	jsonP, err := json.MarshalIndent(p, "", "	")
	if err != nil {
		log.Println("failed to marshal PE32")
		os.Exit(1)
	}
	//fmt.Print(string(jsonP))

	err = os.WriteFile(".\\output.json", jsonP, 0644)
	if err != nil {
		log.Println("failed to write result to file")
		os.Exit(1)
	}
}
