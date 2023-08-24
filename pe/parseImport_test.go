package pe

import (
	"testing"
)

func TestPE32_ParseImportTable(t *testing.T) {
	p := NewPE32("..\\example\\example.exe")
	p.Init()
	p.ParseHeader()

	// 只测试第一组数据
	expected := []struct {
		DllName string
		SymName []string
	}{
		{"VCRUNTIME140.dll", []string{"__current_exception_context", "__current_exception", "memset", "_except_handler4_common"}},
	}

	importTable := p.ImportTable
	for index, expect := range expected {
		if importTable[index].Name != expect.DllName {
			t.Errorf("wrong dll name, expected: %s, got: %s\n", expect.DllName, importTable[index].Name)
		}

		INTs := importTable[index].INT
		for i, exName := range expect.SymName {
			if INTs[i].Data.Name != exName {
				t.Errorf("wrong symbol name, expected: %s, got: %s\n", exName, INTs[i].Data.Name)
			}
		}
	}
}
