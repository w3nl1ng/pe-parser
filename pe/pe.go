package pe

const (
	IMAGE_DOS_SIGNATURE = 0x4D5A
)

type PE32 struct {
	IDH *IMAGE_DOS_HEADER
}

// 只包含重要的字段
type IMAGE_DOS_HEADER struct {
	Magic  uint16
	Lfanew uint32
}
