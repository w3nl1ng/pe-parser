package pe

// RAV2FOA函数将一个RVA转换为FOA
func (pe *PE32) RAV2FOA(rva int32) int32 {
	return 0
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
