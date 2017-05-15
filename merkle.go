package merkle

import (
	"crypto/sha256"
	"io"
)

func hash(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

type Tree struct {
	levels [][]byte
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
