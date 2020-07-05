package main

import (
	"crypto/sha1"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/binject/debug/pe"
)

func main() {
	//again, not sure this should really be in bananaphone, will move/etc when sensible..
	var loc string
	flag.StringVar(&loc, "i", "", "File to get PE hash of")
	flag.Parse()

	if loc == "" {
		panic("need an in file pls")
	}

	fmt.Printf("%x\n", getHash(loc))
}

func getHash(loc string) []byte {

	/*
		https://www.symbolcrash.com/wp-content/uploads/2019/02/Authenticode_PE-1.pdf
		1.	Load the image header into memory.
		2.	Initialize a hash algorithm context.
		3.	Hash the image header from its base to immediately before the start of the checksum address, as specified in Optional Header Windows-Specific Fields.
		4.	Skip over the checksum, which is a 4-byte field.
		5.	Hash everything from the end of the checksum field to immediately before the start of the Certificate Table entry, as specified in Optional Header Data Directories.
		6.	Get the Attribute Certificate Table address and size from the Certificate Table entry. For details, see section 5.7 of the PE/COFF specification.
		7.	Exclude the Certificate Table entry from the calculation and hash everything from the end of the Certificate Table entry to the end of image header, including Section Table (headers).The Certificate Table entry is 8 bytes long, as specified in Optional Header Data Directories.
		8.	Create a counter called SUM_OF_BYTES_HASHED, which is not part of the signature. Set this counter to the SizeOfHeaders field, as specified in Optional Header Windows-Specific Field.
		9.	Build a temporary table of pointers to all of the section headers in the image. The NumberOfSections field of COFF File Header indicates how big the table should be. Do not include any section headers in the table whose SizeOfRawData field is zero.
		10.	Using the PointerToRawData field (offset 20) in the referenced SectionHeader structure as a key, arrange the table's elements in ascending order. In other words, sort the section headers in ascending order according to the disk-file offset of the sections.
		11.	Walk through the sorted table, load the corresponding section into memory, and hash the entire section. Use the SizeOfRawData field in the SectionHeader structure to determine the amount of data to hash.
		12.	Add the section’s SizeOfRawData value to SUM_OF_BYTES_HASHED.
		13.	Repeat steps 11 and 12 for all of the sections in the sorted table.
		14.	Create a value called FILE_SIZE, which is not part of the signature. Set this value to the image’s file size, acquired from the underlying file system. If FILE_SIZE is greater than SUM_OF_BYTES_HASHED, the file contains extra data that must be added to the hash. This data begins at the SUM_OF_BYTES_HASHED file offset, and its length is:
		(File Size) – ((Size of AttributeCertificateTable) + SUM_OF_BYTES_HASHED)


		Note: The size of Attribute Certificate Table is specified in the second ULONG value in the Certificate Table entry (32 bit: offset 132, 64 bit: offset 148) in Optional Header Data Directories.
		15.	Finalize the hash algorithm context.
		Note: This procedure uses offset values from the PE/COFF specification, version 8.1 . For authoritative offset values, refer to the most recent version of the PE/COFF specification.

	*/
	p, e := pe.Open(loc)
	if e != nil {
		panic(e)
	}

	hasher := sha1.New() //todo, pick hashing alg I guess?
	//bb, e := p.Bytes()
	bb, e := ioutil.ReadFile(loc) //todo, work out why binject gives a different value
	if e != nil {
		panic(e)
	}

	ctr := 0
	n, e := hasher.Write(bb[:0xd8])
	if e != nil {
		panic(e)
	}

	ctr = 0xd8 + 4 //skip checksum

	//this shoudl be checked to see if some silly assembler has placed the cert table in a section (it shouldn't, but it would be valid..? probably?)
	//var certTableOffset, certTableSize uint32
	switch p.FileHeader.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		//certTableOffset = p.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.CERTIFICATE_TABLE].VirtualAddress
		//certTableSize = p.OptionalHeader.(*pe.OptionalHeader32).DataDirectory[pe.CERTIFICATE_TABLE].Size
		panic("non x64 not supported soz lol")
	case pe.IMAGE_FILE_MACHINE_AMD64:
		//certTableOffset = p.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.CERTIFICATE_TABLE].VirtualAddress
		//certTableSize = p.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[pe.CERTIFICATE_TABLE].Size
		n, e = hasher.Write(bb[ctr:0x128])
		if e != nil {
			panic(e)
		}

		ctr = 0x128 + 8 //skip cert table entry thing
	default:
		panic(errors.New("architecture not supported"))
	}

	n, e = hasher.Write(bb[ctr:p.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders])
	if e != nil {
		panic(e)
	}

	hashcount := int(p.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders) //this isn't actually used (yet)

	//9 get section headers, sort by raw data offset
	sections := make([]*pe.Section, 0, p.NumberOfSections)
	for _, x := range p.Sections {
		if x.Size != 0 {
			sections = append(sections, x)
		}
	}
	sort.Sort(sortBy(sections))
	for _, sec := range sections {
		n, e = hasher.Write(bb[sec.Offset : sec.Offset+sec.Size])
		hashcount += n
	}
	return hasher.Sum(nil)
}

type sortBy []*pe.Section

func (a sortBy) Len() int           { return len(a) }
func (a sortBy) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a sortBy) Less(i, j int) bool { return a[i].Offset < a[j].Offset }
