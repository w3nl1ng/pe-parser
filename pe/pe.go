package pe

import (
	"log"
	"os"
)

const (
	IMAGE_DOS_SIGNATURE          = 0x5A4D
	IMAGE_PE_SIGNATURE           = 0x4550
	IMAGE_SIZEOF_FILE_HEADER     = 20
	IMAGE_SIZEOF_SECTION_HEADER  = 40
	IMAGE_IMPORT_DESCRIPTOR_SIZE = 20 //一个导入描述符的大小
)

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = iota
	IMAGE_DIRECTORY_ENTRY_IMPORT
)

type PE32 struct {
	Name        string                     `json:"filename"`
	Raw         []byte                     `json:"-"`
	Header      *IMAGE_HEADER              `json:"header"`
	ImportTable []*IMAGE_IMPORT_DESCRIPTOR `json:"importTable"`
}

// DOS头 只包含重要的字段
type IMAGE_DOS_HEADER struct {
	Magic  int16 `json:"magic"`
	Lfanew int32 `json:"lfanew"`
}

// PE头
type IMAGE_NT_HEADER struct {
	Signature      int32                  `json:"signature"`
	FileHeader     *IMAGE_FILE_HEADER     `json:"fileHeader"`
	OptionalHeader *IMAGE_OPTIONAL_HEADER `json:"optionalHeader"`
}

// PE文件头
type IMAGE_FILE_HEADER struct {
	NumberOfSection      int16 `json:"numberOfSection"`
	SizeOfOptionalHeader int16 `json:"sizeOfOptionalHeader"`
}

// PE可选头
type IMAGE_OPTIONAL_HEADER struct {
	AddressOfEntryPoint int32                   `json:"addressOfEntryPoint"`
	ImageBase           int32                   `json:"imageBase"`
	SectionAlignment    int32                   `json:"sectionAlignment"`
	FileAlignment       int32                   `json:"fileAlignment"`
	SizeOfHeader        int32                   `json:"sizeOfHeader"`
	DataDirectoryArray  []*IMAGE_DATA_DIRECTORY `json:"dataDirectoryArray"`
}

// 数据目录项
type IMAGE_DATA_DIRECTORY struct {
	Data interface{} `json:"rva"`
	Size int32       `json:"size"`
}

// 节区头
type IMAGE_SECTION_HEADER struct {
	Name             string `json:"name"`
	VisualSize       int32  `json:"visualSize"`
	VisualAddress    int32  `json:"rva"` //节区的RVA
	SizeOfRawData    int32  `json:"sizeOfRawData"`
	PointerToRawData int32  `json:"foa"` //节区的文件偏移
	Characteristics  uint32 `json:"characteristics"`
}

type IMAGE_HEADER struct {
	DosHeader      *IMAGE_DOS_HEADER       `json:"dosHeader"`
	PEHeader       *IMAGE_NT_HEADER        `json:"ntHeader"`
	SectionHeaders []*IMAGE_SECTION_HEADER `json:"sectionHeaders"`
}

type IMAGE_IMPORT_TABLE struct {
	Imports []*IMAGE_IMPORT_DESCRIPTOR
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
