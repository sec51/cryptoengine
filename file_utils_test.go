package cryptoengine

import (
	"os"
	"testing"
)

func TestFileExists(t *testing.T) {
	if !FileExists("doc.go") {
		t.Fatal("doc.go should always be there")
	}
}

func TestFileUtils(t *testing.T) {
	filename := "temp.txt"
	dataString := "TEST DATA"
	data := []byte(dataString)

	// write a simple file
	err := WriteFile(filename, data)
	if err != nil {
		t.Error(err)
	}

	// rewrite the same file, it should trigger an error
	err = WriteFile(filename, data)
	if err != os.ErrExist {
		t.Errorf("The expected error is: os.ErrExist, instead we've got: %s\n", err)
	}

	// check if the file exists, it should
	if !FileExists(filename) {
		t.Fatal("The file should exist!")
	}

	// read the file back
	storedData, err := ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}

	// read the data back
	storedString := string(storedData)
	if storedString != dataString {
		t.Error("The data in the file is corrupted")
	}

	// delete the file
	if err := DeleteFile(filename); err != nil {
		t.Fatal(err)
	}

}
