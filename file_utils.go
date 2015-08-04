package cryptoengine

import (
	"io/ioutil"
	"os"
)

// Check if a file exists
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// Read the full file into a byte slice
func ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}

// Writes a file with read only permissions
// If the file already exists then it returns the specific error: os.ErrExist
// This is thanks to the flag O_CREATE
func WriteFile(filename string, data []byte) error {

	if FileExists(filename) {
		return os.ErrExist
	}

	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0400)
	if err != nil {
		return err
	}

	_, err = file.Write(data)
	return err

}

// Read the file into a 32 byte array
func ReadKey(filename string) ([32]byte, error) {
	var data32 [32]byte
	data, err := ReadFile(filename)
	copy(data32[:], data[:32])
	return data32, err
}

// Check if the file or directory exists and then deletes it
func DeleteFile(filename string) error {
	if FileExists(filename) {
		return os.Remove(filename)
	}
	return nil
}
