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

	total := 0.0
	for i := 0; i < 1000; i += 1 {
		start := time.Now()
		tree := NewTree()
		tree.Generate(preLeaves)
		total += time.Since(start).Seconds()
	}
	fmt.Println(total / 100)
	total = 0.0
	for i := 0; i < 1000; i += 1 {
		start := time.Now()
		tree1 := merkle.NewTree()
		tree1.Generate(preLeaves, sha256.New())
		total += time.Since(start).Seconds()
	}
	fmt.Println(total / 100)
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
//
// 	for _, preLeaf := range preLeaves {
// 		t.levels[d] = append(t.levels[d], leafHash(preLeaf))
// 	}
//
// 	for i := d; i > 0; i -= 1 {
// 		level := t.levels[i]
//
// 		for j := 0; j < len(level)-1; j += 2 {
// 			left := level[j]
// 			right := level[j+1]
//
// 			parent := internalHash(append(left, right...))
// 			t.levels[i-1] = append(t.levels[i-1], parent)
// 		}
//
// 		if len(level)%2 != 0 {
// 			t.levels[i-1] = append(t.levels[i-1], level[len(level)-1])
// 		}
// 	}
//
// 	return nil
// }
