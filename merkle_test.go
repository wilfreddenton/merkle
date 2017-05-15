package merkle

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
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

	tree := NewTree()
	tree.Generate(preLeaves)
	fmt.Println(hex.EncodeToString(tree.Root()))
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
