# merkle

[![](https://godoc.org/github.com/wilfreddenton/merkle?status.svg)](http://godoc.org/github.com/wilfreddenton/merkle)
[![Build Status](https://travis-ci.org/wilfreddenton/merkle.svg?branch=master)](https://travis-ci.org/wilfreddenton/merkle)
[![codecov](https://codecov.io/gh/wilfreddenton/merkle/branch/master/graph/badge.svg)](https://codecov.io/gh/wilfreddenton/merkle)

<p><a href="https://commons.wikimedia.org/wiki/File:Hash_Tree.svg#/media/File:Hash_Tree.svg"><img src="https://upload.wikimedia.org/wikipedia/commons/9/95/Hash_Tree.svg" alt="Hash Tree.svg" height="764" width="1200"></a><br>By <a href="//commons.wikimedia.org/wiki/User:Azaghal" title="User:Azaghal">Azaghal</a> - <span class="int-own-work" lang="en">Own work</span>, <a href="http://creativecommons.org/publicdomain/zero/1.0/deed.en" title="Creative Commons Zero, Public Domain Dedication">CC0</a>, <a href="https://commons.wikimedia.org/w/index.php?curid=18157888">Link</a></p>

## Usage

```
package main

import (
	"crypto/sha256"
	"log"
	"os"

	"github.com/wilfreddenton/merkle"
)

func main() {
	// create a hash function
	// it's ok to resuse this in merkle calls because it will be reset after use
	h := sha256.New()

	// create an io.Reader
	f, err := os.Open("main.go")
	if err != nil {
		log.Fatal(err)
	}

	// shard the file into segments (1024 byte sized segments in this case)
	preLeaves, err := merkle.Shard(f, 1024)
	if err != nil {
		log.Fatal(err)
	}

	// initialize the tree
	t := merkle.NewTree()

	// compute the root hash from the pre-leaves using the sha256 hash function
	err = t.Hash(preLeaves, h)
	if err != nil {
		log.Fatal(err)
	}

	// use the LeafHash function to convert a pre-leaf into a leaf
	leaf := merkle.LeafHash(preLeaves[0], h)

	// create the merkle path for the leaf
	path := t.MerklePath(leaf)
	if path == nil {
		log.Fatalf("tree does not contain %x", leaf)
	}

	// prove with the path that the tree contains the leaf
	if !merkle.Prove(leaf, t.Root(), path, h) {
		log.Fatalf("tree should container %x", leaf)
	}
}
```

## References

[Tree Hash EXchange format (THEX)](http://adc.sourceforge.net/draft-jchapweske-thex-02.html): This site covers a lot of the implementation details of Merkle Trees.

[Storj Whitepaper](https://storj.io/storj.pdf): Storj is a P2P cloud storage network. The whitepaper details their usage of the Merkle Tree datastructure for validating file shards.

[Mastering Bitcoin - Unlocking Digital Currencies](https://github.com/bitcoinbook/bitcoinbook): Chapter 7 - The Blockchain | Merkle Trees

[Blockchain header: Merkle roots and SPV transaction verification](https://www.youtube.com/watch?v=PGTzuDG5jEA): A great youtube video by [Matt Thomas](https://www.youtube.com/channel/UCbXiy1W_1HSMawmBDfo_TOA) explaining in depth how Merkle Trees are used in the bitcoin blockchain.
