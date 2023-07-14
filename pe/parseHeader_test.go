package pe

import (
	"fmt"
	"testing"
)

func Test_parseDosHeader(t *testing.T) {
	p := NewPE32("..\\example\\example.exe")
	p.Init()
	p.ParseHeader()

	fmt.Printf("%X, %X\n", p.Header.DosHeader.Magic, p.Header.DosHeader.Lfanew)
}
