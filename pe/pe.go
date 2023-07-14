package pe

import (
	"log"
	"os"
)

const (
	IMAGE_DOS_SIGNATURE = 0x5A4D
)

type PE32 struct {
	Name        string
	Raw         []byte
	Header      *IMAGE_HEADER
	ImportTable []*IMAGE_IMPORT_DESCRIPTOR
}

// DOS头 只包含重要的字段
type IMAGE_DOS_HEADER struct {
	Magic  int16
	Lfanew int32
}

// PE头
type IMAGE_NT_HEADER struct {
	Signature      int32
	FileHeader     *IMAGE_FILE_HEADER
	OptionalHeader *IMAGE_OPTIONAL_HEADER
}

// PE文件头
type IMAGE_FILE_HEADER struct {
	NumberOfSection      int16
	SizeOfOptionalHeader int16
}

// PE可选头
type IMAGE_OPTIONAL_HEADER struct {
	AddressOfEntryPoint int32
	ImageBase           int32
	SectionAlignment    int32
	FileAlignment       int32
	DataDirectory       []*IMAGE_DATA_DIRECTORY
}

// 数据目录项
type IMAGE_DATA_DIRECTORY struct {
	Data interface{}
	Size int32
}

// 节区头
type IMAGE_SECTION_HEADER struct {
	Name             string
	VisualSize       int32
	VisualAddress    int32 //节区的RVA
	SizeOfRawData    int32
	PointerToRawData int32 //节区的文件偏移
	Characteristics  int32
}

type IMAGE_HEADER struct {
	DosHeader     *IMAGE_DOS_HEADER
	PEHeader      *IMAGE_NT_HEADER
	SectionHeader *IMAGE_SECTION_HEADER
}

// NewPE32返回一个PE32对象，并初始化其文件名
func NewPE32(fileName string) *PE32 {
	return &PE32{Name: fileName}
}

// Init函数根据文件名将文件内容读取到Raw中
func (pe *PE32) Init() {
	content, err := os.ReadFile(pe.Name)
	if err != nil {
		log.Printf("pe/Init: %v\n", err)
	}
	pe.Raw = make([]byte, len(content))
	copy(pe.Raw, content) //进行浅拷贝
}
