package main

import (
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

	// fileInfo, err := os.Stat(filename)
	// if err != nil {
	// 	log.Println(err)
	// 	os.Exit(1)
	// }

	// fileSize := fileInfo.Size()
	// if fileSize <= 1_000_000 {
	// 	parsePEInMem(filename, &peStruct)
	// } else {
	// 	parsePEinFile(filename, &peStruct)
	// }

	peStruct := &pe.PE32{}

	parsePEInMem(filename, peStruct)
}

func parsePEInMem(filename string, peStruct *pe.PE32) {
	//将整个文件读入内存，加快处理的速度
	content, err := os.ReadFile(filename)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	imageDosHeader := parseImageDosHeader(content)

	peStruct.IDH = imageDosHeader
}

func parseImageDosHeader(content []byte) *pe.IMAGE_DOS_HEADER {
	temp := content[0:2]
	magic := uint16(temp[0])<<8 | uint16(content[1])
	temp = content[0x3c:0x40]
	lfanew := uint32(temp[3])<<24 | uint32(temp[2])<<16 | uint32(temp[1])<<8 | uint32(temp[0])

	ret := &pe.IMAGE_DOS_HEADER{Magic: magic, Lfanew: lfanew}
	return ret
}
