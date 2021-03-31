package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io/ioutil"
	"log"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: mkwinsyscall [flags] [path ...]\n")
	flag.PrintDefaults()
	os.Exit(1)
}

const (
	marker = "//dsys"
)

var (
	filename       = flag.String("output", "", "output file name (standard output if omitted)")
	printTraceFlag = flag.Bool("trace", false, "generate print statement after every syscall")
	mode           = flag.String("mode", "auto", "Which bananaphone mode to use (default auto, anything not in the following options results in auto) Options: disk,memory,raw")
	noglobal       = flag.Bool("noglobal", false, "Do not use a global var (embed the bananaphone object into each function)")
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Usage = usage
	flag.Parse()
	if len(flag.Args()) <= 0 {
		fmt.Fprintf(os.Stderr, "no files to parse provided\n")
		usage()
	}

	src, err := ParseFiles(flag.Args(), *mode, !*noglobal)
	if err != nil {
		log.Fatal(err)
	}

	var buf bytes.Buffer
	if err := src.Generate(&buf); err != nil {
		log.Println(string(buf.Bytes()))
		log.Fatal(err)
	}
	data, err := format.Source(buf.Bytes())
	if err != nil {
		log.Println(string(buf.Bytes()))
		log.Fatal(err)
	}
	if *filename == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = ioutil.WriteFile(*filename, data, 0644)
	}
	if err != nil {
		log.Fatal(err)
	}

}
