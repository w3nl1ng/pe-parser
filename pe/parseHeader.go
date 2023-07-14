package pe

import (
	"log"
	"os"
)

// ParseHeader函数解析PE文件的DOS头，PE头，节区头
func (p *PE32) ParseHeader() {
	p.Header = &IMAGE_HEADER{}
	p.parseDosHeader()
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
