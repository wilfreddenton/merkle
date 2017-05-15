package merkle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"testing"

	"github.com/xsleonard/go-merkle"
)

var preLeaves [][]byte

func TestMain(m *testing.M) {
	f, err := os.Open("./test/test.gif")
	if err != nil {
		log.Fatal(err)
	}

	preLeaves, err = Shard(f, 1024)
	if err != nil {
		log.Fatal(err)
	}

	code := m.Run()
	os.Exit(code)
}

func TestHash(t *testing.T) {
	in := "2B"
	out := "5c19c5dfd9c3b4a25e2d34dc6eac5e5c2d6200aa5e3267e8423ccb679525be61"

	s := hex.EncodeToString(hash([]byte(in)))

	if out != s {
		t.Errorf("got %s; want %s", s, out)
	}
}

func TestNodeJSON(t *testing.T) {
	data := preLeaves[0]
	dataStr := base64.StdEncoding.EncodeToString(data)

	n := &Node{
		Hash:     data,
		Position: POSITION_LEFT,
	}

	b, err := json.Marshal(n)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	m := make(map[string]interface{})
	err = json.Unmarshal(b, &m)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	if len(m) != 2 {
		t.Errorf("got %d; want %d", len(m), 2)
	}

	if v, ok := m["hash"]; ok {
		if v != dataStr {
			t.Errorf("got %s; want %s", v, dataStr)
		}
	} else {
		t.Errorf("hash key not found in map")
	}

	if v, ok := m["position"]; ok {
		if v != POSITION_LEFT {
			t.Errorf("got %s; want %s", v, POSITION_LEFT)
		}
	} else {
		t.Errorf("position key not found in map")
	}

	n1 := &Node{}
	err = json.Unmarshal(b, n1)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	nHash := hex.EncodeToString(n.Hash)
	n1Hash := hex.EncodeToString(n1.Hash)
	if nHash != n1Hash {
		t.Errorf("got %s; want %s", n1Hash, nHash)
	}

	if n.Position != n1.Position {
		t.Errorf("got %s; want %s", n.Position, n1.Position)
	}
}

func TestGenerate(t *testing.T) {
	tree := NewTree()
	tree.Generate(preLeaves)
	tree1 := merkle.NewTree()
	tree1.Generate(preLeaves, sha256.New())

	root := hex.EncodeToString(tree.Root())
	root1 := hex.EncodeToString(tree1.Root().Hash)
	if root != root1 {
		t.Errorf("got %s; want %s", root, root1)
	}
}

func TestMerklePath(t *testing.T) {
	tree := NewTree()
	tree.Generate(preLeaves)

	tree.MerklePath(preLeaves[0])
}

func TestProve(t *testing.T) {
	tree := NewTree()
	tree.Generate(preLeaves)

	preLeaf := preLeaves[0]
	leaf := leafHash(preLeaf)
	path := tree.MerklePath(leaf)
	b := Prove(leaf, tree.Root(), path)
	if !b {
		t.Errorf("should be true")
	}

	// use preLeaf as invalid hash
	b = Prove(preLeaf, tree.Root(), path)
	if b {
		t.Errorf("should be false")
	}
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
