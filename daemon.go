package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func daemon() {
	os.Remove(fileName() + ".lock")
	lock, err := net.Listen("unix", fileName()+".lock")
	defer lock.Close()
	if err != nil {
		panic(err)
	}

	timeout := time.Now().Add(60 * time.Second)
	go func() {
		for timeout.After(time.Now()) {
		}
		lock.Close()
	}()

	master := ""
	for {
		conn, err := lock.Accept()
		if err != nil {
			panic(err)
		}

		go func() {
			reader := bufio.NewReader(conn)

			line, _, err := reader.ReadLine()
			if err != nil {
				panic(err)
			}
			linestr := string(line)
			linestr = strings.TrimSpace(linestr)
			fmt.Fprintf(os.Stderr, linestr)

			if linestr == "read" {
				fmt.Fprintf(os.Stderr, "WriteString\n")
				conn.Write([]byte(master))
				conn.Write([]byte("\n"))
			} else {
				master = string(line)
			}
			conn.Close()
		}()
	}
}
