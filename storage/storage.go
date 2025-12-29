package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrKeyNotFound      = fmt.Errorf("key not found")
	ErrKeyAlreadyExists = fmt.Errorf("key already exists")
)

type Storage interface {
	Save(key string, value io.Reader) error
	Load(key string) (io.ReadCloser, error)
	Delete(key string) error
}

type FileStorage struct {
	basePath string // Base directory for file storage
}

func (s *FileStorage) Save(key string, value io.Reader) error {
	p := filepath.Join(s.basePath, key)
	if _, err := os.Stat(p); !os.IsNotExist(err) { // file already exists
		return ErrKeyAlreadyExists
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open file for writing: %w", err)
	}
	defer f.Close()

	if _, err := io.Copy(f, value); err != nil {
		return fmt.Errorf("write to file: %w", err)
	}
	return nil
}

func (s *FileStorage) Load(key string) (io.ReadCloser, error) {
	p := filepath.Join(s.basePath, filepath.Clean(key))
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("open file for reading: %w", err)
	}
	return f, nil
}

func (s *FileStorage) Delete(key string) error {
	p := filepath.Join(s.basePath, key)
	if err := os.Remove(p); err != nil {
		if os.IsNotExist(err) {
			return ErrKeyNotFound
		}
		return fmt.Errorf("delete file: %w", err)
	}
	return nil
}

func NewFileStorage(basePath string) (*FileStorage, error) {
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return nil, fmt.Errorf("create base directory: %w", err)
	}
	return &FileStorage{basePath: basePath}, nil
}
