package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/xsleonard/go-merkle"
)

func TestHash(t *testing.T) {
	in := "2B"
	out := "5c19c5dfd9c3b4a25e2d34dc6eac5e5c2d6200aa5e3267e8423ccb679525be61"

	s := hex.EncodeToString(hash([]byte(in)))

	if out != s {
		t.Errorf("got %s; want %s", s, out)
	}
}

func TestGenerate(t *testing.T) {
	f, err := os.Open("./test/test.jpg")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	preLeaves, err := Shard(f, 1024)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	start := time.Now()
	tree := NewTree()
	tree.Generate(preLeaves)
	fmt.Println(hex.EncodeToString(tree.Root()), time.Since(start))
	start = time.Now()
	tree1 := merkle.NewTree()
	tree1.Generate(preLeaves, sha256.New())
	fmt.Println(hex.EncodeToString(tree1.Root().Hash), time.Since(start))
}

func TestShard(t *testing.T) {
	f, err := os.Open("./merkle.go")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	defer f.Close()

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	n := len(buf)

	for i := 1; i <= 10; i += 1 {
		f.Seek(0, 0)

		shards, err := Shard(f, n/i)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		count := 0
		for _, shard := range shards {
			count += len(shard)
		}

		if n != count {
			t.Errorf("got count %d; want %d", count, n)
		}
	}
}

// func (t *Tree) Generate(preLeaves [][]byte) error {
// 	n := len(preLeaves)
//
// 	if n == 0 {
// 		return errors.New("Cannot create tree with 0 pre leaves")
// 	}
//
// 	d := depth(n)
// 	t.levels = make([][][]byte, d+1)
// 	leaves := make([][]byte, n)
//
// 	for i, preLeaf := range preLeaves {
// 		leaves[i] = leafHash(preLeaf)
// 	}
//
// 	t.levels[d] = leaves
//
// 	for i := d; i > 0; i -= 1 {
// 		level := t.levels[i]
// 		levelLen := len(level)
// 		remainder := levelLen % 2
// 		nextLevel := make([][]byte, levelLen/2+remainder)
//
// 		k := 0
// 		for j := 0; j < len(level)-1; j += 2 {
// 			left := level[j]
// 			right := level[j+1]
//
// 			nextLevel[k] = internalHash(append(left, right...))
// 			k += 1
// 		}
//
// 		if remainder != 0 {
// 			nextLevel[k] = level[len(level)-1]
// 		}
//
// 		t.levels[i-1] = nextLevel
// 	}
//
// 	return nil
// }
