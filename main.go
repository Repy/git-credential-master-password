package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"math/rand"
	"os"
	"os/user"
	"strings"
)

type DataList struct {
	Data []Data `json:"data"`
}
type Data struct {
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	mode := os.Args[1]
	stdin := bufio.NewScanner(os.Stdin)
	params := map[string]string{}
	//標準入力からデータ取り出し
	for stdin.Scan() {
		text := stdin.Text()
		if text == "" {
			break
		}
		sp := strings.SplitN(text, "=", 2)
		params[sp[0]] = sp[1]
	}

	list := &DataList{
		Data: []Data{},
	}
	key := readMasterPass()
	dataRaw := decryptFile(key)
	if dataRaw != nil {
		err := json.Unmarshal(dataRaw, list)
		if err != nil {
			panic(err)
		}
	}

	if mode == "get" {
		get(list, params["protocol"], params["host"])
	}
	if mode == "store" {
		store(list, params["protocol"], params["host"], params["username"], params["password"])
	}
	if mode == "erase" {
		erase(list, params["protocol"], params["host"], params["username"])
	}

	dataRaw, err := json.Marshal(list)
	if err != nil {
		panic(err)
	}
	encryptFile(key, dataRaw)
}

func get(list *DataList, protocol string, host string) {
	if list.Data == nil {
		return
	}
	for _, data := range list.Data {
		if data.Host == host && data.Protocol == protocol {
			fmt.Fprintf(os.Stdout, "username=%s\n", data.Username)
			fmt.Fprintf(os.Stdout, "password=%s\n", data.Password)
		}
	}
}

func store(list *DataList, protocol string, host string, username string, password string) {
	list.Data = append(list.Data, Data{
		Protocol: protocol,
		Host:     host,
		Username: username,
		Password: password,
	})
}

func erase(list *DataList, protocol string, host string, username string) {
	if list.Data == nil {
		return
	}
	ret := make([]Data, 0, len(list.Data))
	for _, data := range list.Data {
		if data.Host == host && data.Protocol == protocol && data.Username == username {
			continue
		}
		ret = append(ret, data)
	}
	list.Data = ret
}

func fileName() string {
	user, err := user.Current()
	if err != nil {
		panic(err)
	}
	return user.HomeDir + "/.git-credential-master-password"
}

func decryptFile(key []byte) []byte {
	block, err1 := aes.NewCipher(key)
	if err1 != nil {
		panic(err1)
	}

	iv, data := readFile()
	if iv == nil {
		return nil
	}

	decrypted := make([]byte, len(data))
	decryptStream := cipher.NewCTR(block, iv)
	decryptStream.XORKeyStream(decrypted, data)

	fmt.Fprintf(os.Stderr, "%+v\n", string(decrypted))
	return decrypted
}

func readFile() ([]byte, []byte) {
	file, err1 := os.OpenFile(fileName(), os.O_RDONLY, 0600)
	if err1 != nil {
		switch err1.(type) {
		case *os.PathError:
			return nil, nil
		default:
			panic(err1)
		}
	}

	bytes, err2 := ioutil.ReadAll(file)
	if err2 != nil {
		panic(err2)
	}
	file.Close()

	return bytes[:aes.BlockSize], bytes[aes.BlockSize:]
}

func readMasterPassD() []byte {
	key := sha256.Sum256([]byte("afhkj"))
	return key[:]
}
func readMasterPass() []byte {
	tty, err1 := os.Open("/dev/tty")
	if err1 != nil {
		panic(err1)
	}

	fmt.Fprintf(os.Stderr, "master password:")
	str, err2 := terminal.ReadPassword(int(tty.Fd()))
	if err2 != nil {
		panic(err2)
	}

	key := sha256.Sum256([]byte(str))
	fmt.Fprintf(os.Stderr, "SHA-256 : %x\n", key)
	return key[:]
}

func encryptFile(key []byte, data []byte) {
	fmt.Fprintf(os.Stderr, "%+v\n", string(data))

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		panic(err)
	}

	encrypted := make([]byte, len(data))
	encryptStream := cipher.NewCTR(block, iv)
	encryptStream.XORKeyStream(encrypted, data)
	writeFile(iv, encrypted)
}

func writeFile(iv []byte, encrypted []byte) {
	file, err := os.OpenFile(fileName(), os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	_, err = file.Write(iv)
	if err != nil {
		panic(err)
	}
	_, err = file.Write(encrypted)
	if err != nil {
		panic(err)
	}
	file.Close()
}
