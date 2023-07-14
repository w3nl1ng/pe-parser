package pe

type IMAGE_IMPORT_DESCRIPTOR struct {
	INT  []*IMAGE_CHUNK_DATA32
	Name string
	IAT  []*IMAGE_CHUNK_DATA32
}

type IMAGE_CHUNK_DATA32 struct {
	Data        *IMAGE_IMPORT_BY_NAME
	FuncAddress int32
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint int16
	Name string
}

func (pe *PE32) ParseImportTable() {

}
