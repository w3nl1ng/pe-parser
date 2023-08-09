package pe

import (
	"fmt"
	"log"
)

// RAV2FOA函数将一个RVA转换为FOA
func (pe *PE32) RAV2FOA(rva int32) int32 {
	//如果rva落在文件头范围内，直接返回就可以
	if rva <= pe.Header.PEHeader.OptionalHeader.SizeOfHeader {
		return rva
	}

	//否则需要逐节区查找
	for i := 0; i < int(pe.Header.PEHeader.FileHeader.NumberOfSection); i++ {
		section := pe.Header.SectionHeaders[i]
		sectionRva := section.VisualAddress
		sectionSize := section.SizeOfRawData
		if rva >= sectionRva && rva <= sectionRva+sectionSize {
			//rva在此节区内
			sectionFoa := section.PointerToRawData
			return sectionFoa + (rva - sectionRva)
		}
	}
	//遍历结束依然未返回则说明这个rva是不合法的，没有与之对应的foa
	log.Printf("can not convert RVA(%x) to a FOA\n", rva)
	return -1
}

// byte8函数读取offset偏移处的一个1字节byte
func (p *PE32) byte8(offset int32) int8 {
	return int8(p.Raw[offset])
}

// word函数读取偏移offset处的一个2字节word
func (p *PE32) word(offset int32) int16 {
	return int16(p.Raw[offset]) | (int16(p.Raw[offset+1]) << 8)
}

// dword函数读取offset偏移处的一个4字节dword
func (p *PE32) dword(offset int32) int32 {
	return int32(p.Raw[offset]) | (int32(p.Raw[offset+1]) << 8) |
		(int32(p.Raw[offset+2]) << 16) | (int32(p.Raw[offset+3]) << 24)
}

// string8函数读取offset偏移处的一个字符串，直到遇到\00
func (p *PE32) string8(offset int32) string {
	var ret string
	for {
		ch := p.byte8(offset)
		if ch == 0 {
			break
		}
		ret += fmt.Sprintf("%c", ch)
		offset++
	}
	return ret
}
