package pe

import (
	"log"
	"os"
)

type IMAGE_IMPORT_DESCRIPTOR struct {
	INT  []*IMAGE_CHUNK_DATA32 `json:"INT"`
	Name string                `json:"name"`
	IAT  []*IMAGE_CHUNK_DATA32 `json:"IAT"`
}

type IMAGE_CHUNK_DATA32 struct {
	Data        *IMAGE_IMPORT_BY_NAME `json:"data"`
	FuncAddress int32                 `json:"funcAddress"`
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint int16  `json:"hint"`
	Name string `json:"name"`
}

func (pe *PE32) ParseImportTable() {
	//从数据目录表定位到导入表的文件偏移和大小
	rva, ok := pe.Header.PEHeader.OptionalHeader.DataDirectoryArray[IMAGE_DIRECTORY_ENTRY_IMPORT].Data.(int32)
	size := pe.Header.PEHeader.OptionalHeader.DataDirectoryArray[IMAGE_DIRECTORY_ENTRY_IMPORT].Size
	if !ok {
		log.Printf("failed to convert %T to int\n", pe.Header.PEHeader.OptionalHeader.DataDirectoryArray[IMAGE_DIRECTORY_ENTRY_IMPORT].Data)
		os.Exit(1)
	}

	//导入表不存在
	if size == 0 {
		return
	}

	foa := pe.RVA2FOA(rva)
	if foa < 0 {
		return
	}

	tempPointer := foa
	pe.ImportTable = []*IMAGE_IMPORT_DESCRIPTOR{}

	for {
		rva2INT := pe.dword(tempPointer)
		rva2DLLName := pe.dword(tempPointer + 12)
		rva2IAT := pe.dword(tempPointer + 16)
		if rva2IAT == 0 {
			break
		}
		tempImportDes := &IMAGE_IMPORT_DESCRIPTOR{}
		tempImportDes.INT = pe.parseINTAndIAT(rva2INT)
		tempImportDes.Name = pe.string8(pe.RVA2FOA(rva2DLLName))
		tempImportDes.IAT = pe.parseINTAndIAT(rva2IAT)

		pe.ImportTable = append(pe.ImportTable, tempImportDes)
		tempPointer += IMAGE_IMPORT_DESCRIPTOR_SIZE
	}

}

func (pe *PE32) parseINTAndIAT(rva int32) []*IMAGE_CHUNK_DATA32 {
	var ret []*IMAGE_CHUNK_DATA32
	tempfoa := pe.RVA2FOA(rva)
	for true {
		if pe.dword(tempfoa) == 0 {
			break
		}
		foa2ImageImportByName := pe.RVA2FOA(pe.dword(tempfoa))
		if foa2ImageImportByName < 0 {
			continue
		}

		imageChunkData32 := &IMAGE_CHUNK_DATA32{}
		ImageImportByName := &IMAGE_IMPORT_BY_NAME{}
		ImageImportByName.Hint = pe.word(foa2ImageImportByName)
		ImageImportByName.Name = pe.string8(foa2ImageImportByName + 2)

		imageChunkData32.Data = ImageImportByName
		ret = append(ret, imageChunkData32)

		tempfoa += 4
	}

	return ret
}
