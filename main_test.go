package main

import (
	"os"
	"pe-parser/pe"
	"testing"
)

func TestParseImageDosHeader(t *testing.T) {
	filename := ".\\example\\example.exe"
	content, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read '%s'\n", filename)
	}

	imageDosHeader := parseImageDosHeader(content)

	if imageDosHeader.Magic != pe.IMAGE_DOS_SIGNATURE {
		t.Errorf("imageDosHeader.Magic is wrong, expected: '%X', got: '%X'",
			pe.IMAGE_DOS_SIGNATURE, imageDosHeader.Magic)
	}

	if imageDosHeader.Lfanew != 0x100 {
		t.Errorf("imageDosHeader.Lfanew is wrong, ecpected: '%X', got '%X'",
			0x100, imageDosHeader.Lfanew)
	}
}
