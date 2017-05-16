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
)

var preLeaves [][]byte

func TestMain(m *testing.M) {
	f, err := os.Open("./test/test.gif")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	preLeaves, err = Shard(f, 1024)
	if err != nil {
		log.Fatal(err)
	}

	code := m.Run()
	os.Exit(code)
}

func TestFindIndex(t *testing.T) {
	tree := NewTree()
	tree.Hash(preLeaves, sha256.New())

	// TEST valid leafs
	for i, preLeaf := range preLeaves {
		leaf := tree.leafHash(preLeaf)
		if tree.findIndex(leaf) < 0 {
			t.Errorf("leaf at index %d should be in tree", i)
		}
	}

	// TEST invalid leafs
	for i := 0; i < 10; i += 1 {
		buf := make([]byte, 64)
		leaf := tree.leafHash(buf)
		if tree.findIndex(leaf) > -1 {
			t.Errorf("leaf at index %d should not be in tree", i)
		}
	}
}

func TestHasher(t *testing.T) {
	tests := []struct {
		in  string
		out string
	}{
		{"2B", "5c19c5dfd9c3b4a25e2d34dc6eac5e5c2d6200aa5e3267e8423ccb679525be61"},
		{"9S", "a9c7d3f3c1a0267175cb4b6fde9c8beabf30ff2b4378728b7b4dd7c3ca5c2232"},
		{"A2", "c8361f9b468e68c86da024270e0949ce139cb704b8d7cce586681b99f3a7ea56"},
	}

	for i, test := range tests {
		s := hex.EncodeToString(hasher([]byte(test.in), sha256.New()))

		if test.out != s {
			t.Errorf("for test index %d: got %s; want %s", i, s, test.out)
		}
	}
}

func TestNodeJSON(t *testing.T) {
	// TEST valid node
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

	// TEST invalid node
	m = map[string]interface{}{
		"hash": 1,
	}
	b, err = json.Marshal(&m)
	if err != nil {
		t.Error(err)
	}

	err = json.Unmarshal(b, n)
	if err == nil {
		t.Error("should be error")
	}

	m = map[string]interface{}{
		"hash": "^^^^^",
	}
	b, err = json.Marshal(&m)
	if err != nil {
		t.Error(err)
	}

	err = json.Unmarshal(b, n)
	if err == nil {
		t.Error("should be error")
	}
}

func TestProve(t *testing.T) {
	tests := []struct {
		leaf []byte
		root []byte
		path []*Node
		out  bool
	}{
		{
			LeafHash([]byte("2B"), sha256.New()),
			LeafHash([]byte("2B"), sha256.New()),
			[]*Node{},
			true,
		},
		{
			[]byte("2B"),
			InternalHash(
				append(
					[]byte("A2"),
					InternalHash(
						append(
							[]byte("2B"),
							[]byte("9S")...,
						),
						sha256.New())...),
				sha256.New(),
			),
			[]*Node{
				&Node{Hash: []byte("9S"), Position: POSITION_RIGHT},
				&Node{Hash: []byte("A2"), Position: POSITION_LEFT},
			},
			true,
		},
		{
			[]byte("Commander"),
			InternalHash(
				append(
					InternalHash(
						append(
							[]byte("Operator 60"),
							[]byte("Commander")...,
						),
						sha256.New()),
					[]byte("Operator 210")...,
				),
				sha256.New(),
			),
			[]*Node{
				&Node{Hash: []byte("Operator 60"), Position: POSITION_LEFT},
				&Node{Hash: []byte("Operator 210"), Position: POSITION_RIGHT},
			},
			true,
		},
		{
			[]byte("2B"),
			InternalHash(
				append(
					[]byte("A2"),
					InternalHash(
						append(
							[]byte("2B"),
							[]byte("9S")...,
						),
						sha256.New())...),
				sha256.New(),
			),
			[]*Node{
				&Node{Hash: []byte("9S"), Position: POSITION_LEFT},
				&Node{Hash: []byte("A2"), Position: POSITION_RIGHT},
			},
			false,
		},
	}

	for i, test := range tests {
		if b := Prove(test.leaf, test.root, test.path, sha256.New()); b != test.out {
			t.Errorf("for test at index %d: got %v; want %v", i, b, test.out)
		}
	}
}

func TestMerklePath(t *testing.T) {
	// hash out tree
	tree := NewTree()
	tree.Hash(preLeaves, sha256.New())

	for _, preLeaf := range preLeaves {
		// create the leaf hash
		leaf := tree.leafHash(preLeaf)

		// get the merkle path
		path := tree.MerklePath(leaf)

		// prove that the leaf exists in the tree using the path
		b := Prove(leaf, tree.Root(), path, sha256.New())
		if !b {
			t.Errorf("should be true")
		}

		// return fails when an invalid leaf is used
		b = Prove(preLeaf, tree.Root(), path, sha256.New())
		if b {
			t.Errorf("should be false")
		}
	}
}

func TestShard(t *testing.T) {
	f, err := os.Open("./merkle.go")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	buf, err := ioutil.ReadAll(f)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	n := len(buf)

	// TEST valid io.Reader
	for i := 1; i <= 10; i += 1 {
		f.Seek(0, 0)

		shards, e := Shard(f, n/i)
		if err != nil {
			t.Error(e)
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

	// TEST invalid io.Reader
	f.Seek(0, 0)
	f.Close()
	_, err = Shard(f, 64)
	if err == nil {
		t.Error("should error")
	}
}

func TestUnhashedTree(t *testing.T) {
	tree := NewTree()

	if tree.Depth() != 0 {
		t.Errorf("got %d; want %d", tree.Depth(), 0)
	}

	if tree.Root() != nil {
		t.Errorf("got %v; want %v", tree.Root(), nil)
	}

	path := tree.MerklePath([]byte("test"))
	if path != nil {
		t.Errorf("got %v; want %v", path, nil)
	}

	err := tree.Hash([][]byte{}, sha256.New())
	if err == nil {
		t.Error("should error")
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
