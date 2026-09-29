// Package tlogstore stores a Merkle tree log on the local filesystem in the
// c2sp.org/tlog-tiles layout, so the directory can be served as is.
//
// A Store has a single writer; callers serialize Append calls, for instance
// with a lock file.
package tlogstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// A Store is a tiled log in a directory:
//
//	<dir>/checkpoint          the latest signed checkpoint
//	<dir>/tile/<L>/<N>[.p/W]  hash tiles
//	<dir>/tile/entries/<N>[.p/W]  entry bundles
//	<dir>/size                the tree size of the stored tiles
//
// The size file is written after the tiles, and the checkpoint after that,
// so a crash leaves at worst unreferenced tiles.
type Store struct {
	dir string
}

// Open returns the Store in dir, creating the directory if needed.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "tile"), 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

// Dir returns the directory of s.
func (s *Store) Dir() string { return s.dir }

// Size returns the number of entries in the log.
func (s *Store) Size() (int64, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "size"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("malformed size file in %s", s.dir)
	}
	return n, nil
}

// tileWidth returns the width of tile n at level l in a tree of size size.
func tileWidth(level int, n, size int64) int {
	count := size >> (uint(level) * torchwood.TileHeight)
	w := count - n*torchwood.TileWidth
	if w > torchwood.TileWidth {
		w = torchwood.TileWidth
	}
	if w < 0 {
		w = 0
	}
	return int(w)
}

func (s *Store) tilePath(t tlog.Tile) string {
	return filepath.Join(s.dir, filepath.FromSlash(torchwood.TilePath(t)))
}

// HashReader returns a tlog.HashReader over a tree of the given size, which
// must not exceed the stored size. Tiles are read from disk without being
// authenticated.
func (s *Store) HashReader(size int64) tlog.HashReader {
	return tlog.HashReaderFunc(func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		cache := map[tlog.Tile][]byte{}
		for i, idx := range indexes {
			t := tlog.TileForIndex(torchwood.TileHeight, idx)
			t.W = tileWidth(t.L, t.N, size)
			if t.W == 0 {
				return nil, fmt.Errorf("hash %d is not in a tree of size %d", idx, size)
			}
			data, ok := cache[t]
			if !ok {
				var err error
				data, err = os.ReadFile(s.tilePath(t))
				if err != nil {
					return nil, err
				}
				cache[t] = data
			}
			h, err := tlog.HashFromTile(t, data, idx)
			if err != nil {
				return nil, err
			}
			out[i] = h
		}
		return out, nil
	})
}

// ReadEntries returns the entries [start, end) of the log.
func (s *Store) ReadEntries(start, end int64) ([][]byte, error) {
	size, err := s.Size()
	if err != nil {
		return nil, err
	}
	if start < 0 || end < start || end > size {
		return nil, fmt.Errorf("entries [%d, %d) out of range for size %d", start, end, size)
	}
	var out [][]byte
	for n := start / torchwood.TileWidth; n*torchwood.TileWidth < end; n++ {
		t := tlog.Tile{H: torchwood.TileHeight, L: -1, N: n, W: tileWidth(0, n, size)}
		data, err := os.ReadFile(s.tilePath(t))
		if err != nil {
			return nil, err
		}
		for i := n * torchwood.TileWidth; len(data) > 0; i++ {
			var entry []byte
			entry, data, err = torchwood.ReadTileEntry(data)
			if err != nil {
				return nil, err
			}
			if i >= start && i < end {
				out = append(out, entry)
			}
		}
	}
	return out, nil
}

// Append adds entries to the log and writes the new tiles. It returns the new
// tree. It does not write a checkpoint.
func (s *Store) Append(entries [][]byte) (tlog.Tree, error) {
	oldSize, err := s.Size()
	if err != nil {
		return tlog.Tree{}, err
	}
	overlay := torchwood.NewHashReaderOverlay(oldSize, s.HashReader(oldSize))
	for _, e := range entries {
		if err := overlay.AppendRecordHash(tlog.RecordHash(e)); err != nil {
			return tlog.Tree{}, err
		}
	}
	newSize := overlay.Size()

	// Entry bundles: start from the stored partial bundle, if any.
	var bundle []byte
	firstBundle := oldSize / torchwood.TileWidth
	if w := tileWidth(0, firstBundle, oldSize); w > 0 {
		t := tlog.Tile{H: torchwood.TileHeight, L: -1, N: firstBundle, W: w}
		bundle, err = os.ReadFile(s.tilePath(t))
		if err != nil {
			return tlog.Tree{}, err
		}
	}
	n := firstBundle
	for i, e := range entries {
		bundle, err = torchwood.AppendTileEntry(bundle, e)
		if err != nil {
			return tlog.Tree{}, err
		}
		index := oldSize + int64(i)
		if (index+1)%torchwood.TileWidth == 0 || index+1 == newSize {
			t := tlog.Tile{H: torchwood.TileHeight, L: -1, N: n, W: tileWidth(0, n, index+1)}
			if err := writeFile(s.tilePath(t), bundle); err != nil {
				return tlog.Tree{}, err
			}
			bundle, n = nil, n+1
		}
	}

	// Hash tiles.
	for _, t := range tlog.NewTiles(torchwood.TileHeight, oldSize, newSize) {
		data, err := tlog.ReadTileData(t, overlay)
		if err != nil {
			return tlog.Tree{}, err
		}
		if err := writeFile(s.tilePath(t), data); err != nil {
			return tlog.Tree{}, err
		}
	}

	root, err := tlog.TreeHash(newSize, overlay)
	if err != nil {
		return tlog.Tree{}, err
	}
	if err := writeFile(filepath.Join(s.dir, "size"), []byte(strconv.FormatInt(newSize, 10)+"\n")); err != nil {
		return tlog.Tree{}, err
	}
	return tlog.Tree{N: newSize, Hash: root}, nil
}

// Tree returns the stored tree.
func (s *Store) Tree() (tlog.Tree, error) {
	size, err := s.Size()
	if err != nil {
		return tlog.Tree{}, err
	}
	h, err := tlog.TreeHash(size, s.HashReader(size))
	if err != nil {
		return tlog.Tree{}, err
	}
	return tlog.Tree{N: size, Hash: h}, nil
}

// WriteCheckpoint signs a checkpoint for tree with origin and the given
// signers, stores it, and returns it.
func (s *Store) WriteCheckpoint(origin string, tree tlog.Tree, signers ...note.Signer) ([]byte, error) {
	c := torchwood.Checkpoint{Origin: origin, Tree: tree}
	signed, err := note.Sign(&note.Note{Text: c.String()}, signers...)
	if err != nil {
		return nil, err
	}
	if err := s.StoreCheckpoint(signed); err != nil {
		return nil, err
	}
	return signed, nil
}

// StoreCheckpoint stores an already signed checkpoint.
func (s *Store) StoreCheckpoint(signed []byte) error {
	return writeFile(filepath.Join(s.dir, "checkpoint"), signed)
}

// Checkpoint returns the stored signed checkpoint, or nil if there is none.
func (s *Store) Checkpoint() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, "checkpoint"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// writeFile atomically replaces path with data, creating parent directories.
func writeFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// WriteFile atomically replaces path with data.
func WriteFile(path string, data []byte) error { return writeFile(path, data) }
