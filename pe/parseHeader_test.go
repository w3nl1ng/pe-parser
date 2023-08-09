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

func Test_parseFileHeader(t *testing.T) {
	p := NewPE32("..\\example\\example.exe")
	p.Init()
	p.ParseHeader()

	expected := struct {
		NumberOfSection      int16
		SizeOfOptionalHeader int16
	}{5, 224}

	if p.Header.PEHeader.FileHeader.NumberOfSection != expected.NumberOfSection {
		t.Errorf("wrong NumberOfSection expected: %d, got: %d\n", expected.NumberOfSection, p.Header.PEHeader.FileHeader.NumberOfSection)
	}

	if p.Header.PEHeader.FileHeader.SizeOfOptionalHeader != expected.SizeOfOptionalHeader {
		t.Errorf("wrong SizeOfOptionalHeader expected: %x, got: %x\n", expected.SizeOfOptionalHeader, p.Header.PEHeader.FileHeader.SizeOfOptionalHeader)
	}
}

func Test_parseSectionHeaders(t *testing.T) {
	p := NewPE32("..\\example\\example.exe")
	p.Init()
	p.ParseHeader()

	expected := []struct {
		Name             string
		VisualSize       int32
		VisualAddress    int32 //节区的RVA
		SizeOfRawData    int32
		PointerToRawData int32 //节区的文件偏移
		Characteristics  uint32
	}{
		{".text", 3281, 0x1000, 0xe00, 0x400, 0x60000020},
		{".rdata", 2822, 0x2000, 0xc00, 0x1200, 0x40000040},
		{".data", 904, 0x3000, 0x200, 0x1e00, 0xc0000040},
		{".rsrc", 480, 0x4000, 0x200, 0x2000, 0x40000040},
		{".reloc", 348, 0x5000, 0x200, 0x2200, 0x42000040},
	}

	for i := 0; i < len(expected); i++ {
		if expected[i].Name != p.Header.SectionHeaders[i].Name {
			t.Errorf("section Name is wrong, expected: %s, got: %s\n", expected[i].Name, p.Header.SectionHeaders[i].Name)
		}

		if expected[i].VisualSize != p.Header.SectionHeaders[i].VisualSize {
			t.Errorf("section VisualSize is wrong, expected: %x, got: %x\n", expected[i].VisualSize, p.Header.SectionHeaders[i].VisualSize)
		}

		if expected[i].VisualAddress != p.Header.SectionHeaders[i].VisualAddress {
			t.Errorf("section VisualAddress is wrong, expected: %x, got: %x\n", expected[i].VisualAddress, p.Header.SectionHeaders[i].VisualAddress)
		}

		if expected[i].SizeOfRawData != p.Header.SectionHeaders[i].SizeOfRawData {
			t.Errorf("section SizeOfRawData is wrong, expected: %x, got: %x\n", expected[i].SizeOfRawData, p.Header.SectionHeaders[i].SizeOfRawData)
		}

		if expected[i].PointerToRawData != p.Header.SectionHeaders[i].PointerToRawData {
			t.Errorf("section PointerToRawData is wrong, expected: %x, got: %x\n", expected[i].PointerToRawData, p.Header.SectionHeaders[i].PointerToRawData)
		}

		if expected[i].Characteristics != p.Header.SectionHeaders[i].Characteristics {
			t.Errorf("section Characteristics is wrong, expected: %x, got: %x\n", expected[i].Characteristics, p.Header.SectionHeaders[i].Characteristics)
		}
	}
}
