package main

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func merge(slices ...[]byte) []byte {
	totalsize := 0
	for _, slice := range slices {
		totalsize += len(slice)
	}

	merged := make([]byte, totalsize)
	buf_idx := 0
	for _, slice := range slices {
		copy(merged[buf_idx:], slice)
		buf_idx += len(slice)
	}
	return merged
}

func getCryptParams(originalName string) (newfilename string, xor_key [7]byte, dk []byte, iv []byte, file_offset int, key_start_pos int) {
	//md5 filename
	filenamehash := md5.New()
	filenamehash.Write(([]byte(originalName)))
	newfilename = fmt.Sprintf("%x", filenamehash.Sum(nil))

	//xor key
	cryptname := strings.Replace(originalName, "_", "", -1)
	cryptname = cryptname + "1234567"
	cryptname_bytes := []byte(cryptname[:7])
	for i := 0; i < 7; i++ {
		xor_key[i] = cryptname_bytes[i] + byte(i) + 1
	}

	//dk,iv
	iv = []byte("0" + cryptname[0:7])
	dk = []byte(cryptname[1:9])

	//file offset
	file_offset_hash_md5 := md5.New()
	file_offset_hash_md5.Write(xor_key[:])
	file_offset_hash := file_offset_hash_md5.Sum(nil)
	file_offset_word := (uint32(file_offset_hash[0]) | (uint32(file_offset_hash[1]) << 8) | (uint32(file_offset_hash[2]) << 16) | (uint32(file_offset_hash[3]) << 24))
	file_offset = int(file_offset_word % uint32(0x419))

	//xorkey index
	key_start_pos = file_offset * 2

	return
}

func decrypt(originalName string, inFilePath string, outFilePath string) {

	filename, xor_key, dk, iv, calc_file_offset, key_start_pos := getCryptParams(originalName)

	fullfilename := inFilePath + filename
	file_content, err := os.ReadFile(fullfilename)
	if err != nil {
		fmt.Print(err)
		return
	}
	offset_file_content := file_content[calc_file_offset:]

	unxor_file_content := make([]byte, len(offset_file_content))

	for i := 0; i < len(offset_file_content); i++ {
		xor_key_index := (int(key_start_pos) + i) % 7
		unxor_file_content[i] = offset_file_content[i] ^ xor_key[xor_key_index]
	}

	block, _ := des.NewCipher(dk)
	mode := cipher.NewCBCDecrypter(block, iv)

	decryptHeader := make([]byte, 1024)
	mode.CryptBlocks(decryptHeader, unxor_file_content[:1024])

	//Remove the last 8 bytes, since they are not valid data, they are just a string of 8 magic bytes
	full_decrypt_file_content := merge(decryptHeader, unxor_file_content[1024:len(unxor_file_content)-8])

	mkerr := os.MkdirAll(outFilePath, os.ModePerm)
	if mkerr != nil {
		fmt.Print(mkerr)
		return
	}
	wrerr := os.WriteFile(outFilePath+originalName, full_decrypt_file_content, os.ModePerm)
	if wrerr != nil {
		fmt.Print(wrerr)
		return
	}
}

func encrypt(inFile string, outFilePath string) {

	fullfilename := filepath.Base(inFile)
	originalName := strings.TrimSuffix(fullfilename, filepath.Ext(fullfilename))

	newfilename, xor_key, dk, iv, calc_file_offset, data_key_start_pos := getCryptParams(originalName)

	file_key_start_pos := (data_key_start_pos - calc_file_offset) % 7
	file_content, err := os.ReadFile(inFile)
	if err != nil {
		fmt.Print(err)
		return
	}

	block, _ := des.NewCipher(dk)
	mode := cipher.NewCBCEncrypter(block, iv)

	encryptHeader := make([]byte, 1024+8)
	magicBytes := []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}
	mode.CryptBlocks(encryptHeader, merge(file_content[:1024], magicBytes))

	out_file_content := merge(make([]byte, calc_file_offset), encryptHeader[:1024], file_content[1024:], encryptHeader[1024:1024+8])
	xor_out_file_content := make([]byte, len(out_file_content))

	for i := 0; i < len(out_file_content); i++ {
		xor_key_index := (int(file_key_start_pos) + i) % 7
		xor_out_file_content[i] = out_file_content[i] ^ xor_key[xor_key_index]
	}
	mkerr := os.MkdirAll(outFilePath, os.ModePerm)
	if mkerr != nil {
		fmt.Print(mkerr)
	}
	wrerr := os.WriteFile(outFilePath+newfilename, xor_out_file_content, os.ModePerm)
	if wrerr != nil {
		fmt.Print(wrerr)
	}

}

func main() {

	exampleUsageString := "This tool is used to decrypt and encrypt Star Ocean 2 Remake asset files. Example Usage: \n" + `so2rtools.exe decrypt message_en "C:/Program Files (x86)/Steam/steamapps/common/STAR OCEAN THE SECOND STORY R DEMO/SO2R_Demo_Data/StreamingAssets/" "decrypted_assests/"`

	arg := os.Args

	if len(arg) < 2 {
		fmt.Print(exampleUsageString)
		return
	}

	if arg[1] == "decrypt" {
		if len(arg[2:]) < 3 {
			return
		}
		decrypt(arg[2], arg[3], arg[4])
	} else if arg[1] == "encrypt" {
		if len(arg[2:]) < 2 {
			return
		}
		encrypt(arg[2], arg[3])
	} else {
		fmt.Print(exampleUsageString)
		return
	}

}
