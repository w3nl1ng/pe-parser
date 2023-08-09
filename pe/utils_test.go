package pe

import "testing"

func Test_RAV2FOA(t *testing.T) {
	p := NewPE32("..\\example\\example.exe")
	p.Init()
	p.ParseHeader()

	expected := []struct {
		Rva int32
		Foa int32
	}{
		{0x201, 0x201},
		{0x1020, 0x420},
		{0x1fff, -1},
		{0x5010, 0x2210},
		{0x7000, -1},
	}

	for _, ex := range expected {
		if p.RAV2FOA(ex.Rva) != ex.Foa {
			t.Errorf("wrong FOA, expected: %x, got: %x\n", ex.Foa, p.RAV2FOA(ex.Rva))
		}
	}
}
