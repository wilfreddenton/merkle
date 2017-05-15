package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
)

const (
	POSITION_LEFT  = "left"
	POSITION_RIGHT = "right"
)

func depth(n int) int {
	return int(math.Ceil(math.Log2(float64(n))))
}

func hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

func leafHash(data []byte) []byte {
	return hash(append([]byte{0x00}, data...))
}

func internalHash(data []byte) []byte {
	return hash(append([]byte{0x01}, data...))
}

type Node struct {
	Hash     []byte
	Position string
}

type Tree struct {
	levels [][][]byte
}

func (t *Tree) Root() []byte {
	if t.levels == nil {
		return nil
	}

	return t.levels[0][0]
}

func (t *Tree) Depth() int {
	if t.levels == nil {
		return 0
	}

	return len(t.levels) - 1
}

func (t *Tree) MerklePath(index int) []*Node {
	if t.levels == nil {
		return nil
	}

	d := t.Depth()
	var path []*Node

	for i := d; i > 0; i -= 1 {
		level := t.levels[i]
		levelLen := len(level)
		remainder := levelLen % 2
		nextIndex := index / 2

		// if index is the the last item in an odd length level promote
		if index == levelLen-1 && remainder != 0 {
			index = nextIndex
			continue
		}

		// if i is odd we want to get the left sibling
		if index%2 != 0 {
			path = append(path, &Node{Hash: level[index-1], Position: POSITION_LEFT})
		} else {
			path = append(path, &Node{Hash: level[index+1], Position: POSITION_RIGHT})
		}

		index = nextIndex
	}

	return path
}

func (t *Tree) Generate(preLeaves [][]byte) error {
	n := len(preLeaves)

	if n == 0 {
		return errors.New("Cannot create tree with 0 pre leaves")
	}

	d := depth(n)
	t.levels = make([][][]byte, d+1)
	leaves := make([][]byte, n)

	for i, preLeaf := range preLeaves {
		leaves[i] = leafHash(preLeaf)
	}

	t.levels[d] = leaves

	for i := d; i > 0; i -= 1 {
		level := t.levels[i]
		levelLen := len(level)
		remainder := levelLen % 2
		nextLevel := make([][]byte, levelLen/2+remainder)

		k := 0
		for j := 0; j < len(level)-1; j += 2 {
			left := level[j]
			right := level[j+1]

			nextLevel[k] = internalHash(append(left, right...))
			k += 1
		}

		if remainder != 0 {
			nextLevel[k] = level[len(level)-1]
		}

		t.levels[i-1] = nextLevel
	}

	return nil
}

func NewTree() *Tree {
	return &Tree{levels: nil}
}

func Shard(r io.Reader, shardSize int) ([][]byte, error) {
	var shards [][]byte
	shard := make([]byte, 0, shardSize)

	for {
		n, err := r.Read(shard[:cap(shard)])
		if err != nil {
			if err.Error() == "EOF" {
				return shards, nil
			}

			return shards, err
		}

		shard = shard[:n]
		shards = append(shards, shard)
	}
}

func Prove(leaf, root []byte, path []*Node) bool {
	hash := leaf
	for _, node := range path {
		if node.Position == POSITION_LEFT {
			hash = internalHash(append(node.Hash, hash...))
		} else {
			hash = internalHash(append(hash, node.Hash...))
		}
	}

	return hex.EncodeToString(hash) == hex.EncodeToString(root)
}
