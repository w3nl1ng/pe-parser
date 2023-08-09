package pe

import (
	"log"
	"os"
)

// ParseHeader函数解析PE文件的DOS头，PE头，节区头
func (p *PE32) ParseHeader() {
	p.Header = &IMAGE_HEADER{}
	p.parseDosHeader()
	p.parsePEHeader()
}

// parseDosHeader函数解析DOS头
func (p *PE32) parseDosHeader() {

	p.Header.DosHeader = &IMAGE_DOS_HEADER{}

	dosSignature := p.word(0)
	//检测DOS签名是否是 “MZ”
	if dosSignature != IMAGE_DOS_SIGNATURE {
		log.Printf("pe/parseDosHeader: wrong dosSignature, expected: (%X), got: (%X)\n",
			IMAGE_DOS_SIGNATURE, dosSignature)
		os.Exit(1)
	}

	lfanew := p.dword(0x3C)
	p.Header.DosHeader.Magic = dosSignature
	p.Header.DosHeader.Lfanew = lfanew
}

// parseNTHeader函数解析PE头
func (p *PE32) parsePEHeader() {
	p.Header.PEHeader = &IMAGE_NT_HEADER{}

	// 检测PE签名是否是“PE\00\00”
	peSignature := p.dword(p.Header.DosHeader.Lfanew)
	if peSignature != IMAGE_PE_SIGNATURE {
		log.Printf("pe/parsePEHeader: wrong peSignature, expected: (%X), got: (%X)\n",
			IMAGE_PE_SIGNATURE, peSignature)
	}
	p.parseFileHeader()
	p.parseSectionHeaders()
	p.parseOptionalHeader()

}

// parseFileHeader函数解析映像文件头
func (p *PE32) parseFileHeader() {
	p.Header.PEHeader.FileHeader = &IMAGE_FILE_HEADER{}

	numberOfSections := p.word(p.Header.DosHeader.Lfanew + 6)
	sizeOfOptionalHeader := p.word(p.Header.DosHeader.Lfanew + 0x14)
	p.Header.PEHeader.FileHeader.NumberOfSection = numberOfSections
	p.Header.PEHeader.FileHeader.SizeOfOptionalHeader = sizeOfOptionalHeader
}

// parseOptionalHeader函数解析PE可选头
func (p *PE32) parseOptionalHeader() {
	p.Header.PEHeader.OptionalHeader = &IMAGE_OPTIONAL_HEADER{}

	addressOfEntryPoint := p.dword(p.Header.DosHeader.Lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + 16)
	imageBase := p.dword(p.Header.DosHeader.Lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + 28)
	sectionAlignment := p.dword(p.Header.DosHeader.Lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + 32)
	fileAlignment := p.dword(p.Header.DosHeader.Lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + 36)
	sizeOfHeader := p.dword(p.Header.DosHeader.Lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + 60)

	p.Header.PEHeader.OptionalHeader.AddressOfEntryPoint = addressOfEntryPoint
	p.Header.PEHeader.OptionalHeader.ImageBase = imageBase
	p.Header.PEHeader.OptionalHeader.SectionAlignment = sectionAlignment
	p.Header.PEHeader.OptionalHeader.FileAlignment = fileAlignment
	p.Header.PEHeader.OptionalHeader.SizeOfHeader = sizeOfHeader
}

// parseDataDirectoryArray函数解析PE可选头中的数据目录数组
func (p *PE32) parseDataDirectoryArray() {
	p.Header.PEHeader.OptionalHeader.DataDirectoryArray = make([]*IMAGE_DATA_DIRECTORY, 16)

	//目前只解析导入函数表

}

// parseSectionHeaders函数解析PE文件的节区表
func (p *PE32) parseSectionHeaders() {
	p.Header.SectionHeaders = make([]*IMAGE_SECTION_HEADER, p.Header.PEHeader.FileHeader.NumberOfSection)

	sectionHeadersStart := p.Header.DosHeader.Lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + int32(p.Header.PEHeader.FileHeader.SizeOfOptionalHeader)
	tempPointer := sectionHeadersStart
	for i := 0; i < int(p.Header.PEHeader.FileHeader.NumberOfSection); i++ {
		name := p.string8(tempPointer)
		visualSize := p.dword(tempPointer + 8)
		visualAddress := p.dword(tempPointer + 12)
		sizeOfRawData := p.dword(tempPointer + 16)
		pointerToRawData := p.dword(tempPointer + 20)
		characteristics := p.dword(tempPointer + 36)
		tempSectionHeader := &IMAGE_SECTION_HEADER{
			Name:             name,
			VisualSize:       visualSize,
			VisualAddress:    visualAddress,
			SizeOfRawData:    sizeOfRawData,
			PointerToRawData: pointerToRawData,
			Characteristics:  uint32(characteristics),
		}
		p.Header.SectionHeaders[i] = tempSectionHeader
		tempPointer += 0x28
	}
}
