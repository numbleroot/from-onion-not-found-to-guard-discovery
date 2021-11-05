package main

import (
	"bytes"
	"crypto/ed25519"
	cryptrand "crypto/rand"
	"encoding/base32"
	"flag"
	"fmt"
	"io/ioutil"
	mathrand "math/rand"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/sha3"
)

var newline = []byte("\n")
var onionLenV2 = 16

var allowedCharsV2 = [32]byte{
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
	'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
	'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
	'y', 'z', '2', '3', '4', '5', '6', '7',
}

func init() {
	mathrand.Seed(20200701)
}

func genOnionV2() []byte {

	address := make([]byte, onionLenV2)

	for i := 0; i < onionLenV2; i++ {

		// Generate new pseudo-random index.
		idx := mathrand.Intn(len(allowedCharsV2))

		// Assign character at idx in allowedCharsV2
		// to current position in address.
		address[i] = allowedCharsV2[idx]
	}

	return address
}

func genOnionV3() []byte {

	checksumArray := make([]byte, 48)
	addressArray := make([]byte, 35)
	address := make([]byte, 56)

	// testKey, _ := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	// var pubKey [32]byte
	// copy(pubKey[:], testKey)

	// Generate fresh ed25519 key pair,
	// but only keep the public key.
	pubKey, _, err := ed25519.GenerateKey(cryptrand.Reader)
	if err != nil {
		fmt.Printf("Error while generating new key pair: %v", err)
		os.Exit(1)
	}

	// Construct the checksum array. It consists of the
	// following fields:
	//   ".onion checksum" (15B) || pubkey (32B) || 3 (1B)
	copy(checksumArray, ".onion checksum")
	copy(checksumArray[15:], pubKey[:])
	checksumArray[47] = 3

	// Calculate the SHA3-256 checksum of the array.
	checksum := sha3.Sum256(checksumArray)

	// Construct the array that makes up the final .onion
	// address. It consists of the following fields:
	//   pubkey (32B) || checksum[0:2] (2B) || 3 (1B)
	copy(addressArray, pubKey[:])
	copy(addressArray[32:], checksum[0:2])
	addressArray[34] = 3

	// Encode the address array as Base32 and convert
	// the whole address to lower-case.
	base32.StdEncoding.Encode(address, addressArray)
	address = bytes.ToLower(address)

	return address
}

func worker(wg *sync.WaitGroup, workerID int, onionVer int, numAddrGen int, outputDir string) {

	defer wg.Done()

	addrList := make([][]byte, numAddrGen)

	for i := 0; i < numAddrGen; i++ {

		// Generate new .onion address.
		if onionVer == 2 {
			addrList[i] = genOnionV2()
		} else if onionVer == 3 {
			addrList[i] = genOnionV3()
		}
	}

	// Collapse slice of address slices into
	// single slice with newline separator.
	addr := bytes.Join(addrList, newline)

	// Construct path to output file.
	addrFilePath := ""
	if onionVer == 2 {
		addrFilePath = filepath.Join(outputDir, fmt.Sprintf("v2_%04d.addr", workerID))
	} else if onionVer == 3 {
		addrFilePath = filepath.Join(outputDir, fmt.Sprintf("v3_%04d.addr", workerID))
	}

	// Write newline-separated list of generated
	// addresses to output file of this worker.
	err := ioutil.WriteFile(addrFilePath, addr, 0644)
	if err != nil {
		fmt.Printf("[worker%d] Could not write to output file for v%d addresses: %v\n", workerID, onionVer, err)
		os.Exit(1)
	}
}

func main() {

	v2Flag := flag.Bool("v2", false, "Append this flag if a file with v2 .onion addresses is supposed to be generated.")
	v3Flag := flag.Bool("v3", false, "Append this flag if a file with v3 .onion addresses is supposed to be generated.")
	numAddrFlag := flag.Int("numAddr", 5000, "Specify a multiple of 5,000 as the number of v2 and/or v3 addresses to generate.")
	outputDirFlag := flag.String("outputDir", "./attack_addr/", "Supply file system location to store the lists.")
	flag.Parse()

	if !*v2Flag && !*v3Flag {
		fmt.Printf("At least one of the flags '-v2' or '-v3' has to be supplied.\n")
		os.Exit(1)
	}

	if (*numAddrFlag % 5000) != 0 {
		fmt.Printf("Number of addresses to generate must be a multiple of 5,000.\n")
		os.Exit(1)
	}

	v2 := *v2Flag
	v3 := *v3Flag
	numAddr := *numAddrFlag
	outputDir := *outputDirFlag

	v2NumJobs := 0
	v3NumJobs := 0

	if v2 {
		v2NumJobs = numAddr / 5000
	}

	if v3 {
		v3NumJobs = numAddr / 5000
	}

	// Create new wait group to enable concurrency.
	wg := &sync.WaitGroup{}

	for id := 0; id < v2NumJobs; id++ {

		wg.Add(1)
		go worker(wg, id, 2, 5000, outputDir)
	}

	for id := 0; id < v3NumJobs; id++ {

		wg.Add(1)
		go worker(wg, id, 3, 5000, outputDir)
	}

	wg.Wait()
}
