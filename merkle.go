package merkle

import (
	"crypto/sha256"
	"errors"
	"io"
	"math"
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

func (t *Tree) Generate(preLeaves [][]byte) error {
	n := len(preLeaves)

	if n == 0 {
		return errors.New("Cannot create tree with 0 pre leaves")
	}

	d := depth(n)
	t.levels = make([][][]byte, d+1)

	for _, preLeaf := range preLeaves {
		t.levels[d] = append(t.levels[d], leafHash(preLeaf))
	}

	for i := d; i > 0; i -= 1 {
		level := t.levels[i]

		for j := 0; j < len(level)-1; j += 2 {
			left := level[j]
			right := level[j+1]

			parent := internalHash(append(left, right...))
			t.levels[i-1] = append(t.levels[i-1], parent)
		}

		if len(level)%2 != 0 {
			t.levels[i-1] = append(t.levels[i-1], level[len(level)-1])
		}
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
