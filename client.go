package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Client wraps the sftp.Client.
// The sftp.Client represents an SFTP session on a *ssh.ClientConn SSH connection.
// Multiple Clients can be active on a single SSH connection, and a Client
// may be called concurrently from multiple Goroutines.
type Client struct {
	sftpc *sftp.Client
}

// NewClient opens an SFTP session over an existing ssh connection.
func NewClient(conn *ssh.Client) (*Client, error) {
	sc, err := sftp.NewClient(conn)
	if err != nil {
		return nil, fmt.Errorf("start SFTP subsystem: %v", err)
	}

	return &Client{sc}, nil
}

// Close the SFTP client connection.
func (c *Client) Close() error {
	return c.sftpc.Close()
}

// Glob returns the names of all files matching pattern or nil if there is no matching file.
func (c *Client) Glob(pattern string) ([]string, error) {
	return c.sftpc.Glob(pattern)
}

// MkdirAll creates a directory named path, along with any necessary parents,
// and returns nil, or else returns an error.
// If path is already a directory, MkdirAll does nothing and returns nil.
// If path contains a regular file, an error is returned
func (c *Client) MkdirAll(path string) error {
	return c.sftpc.MkdirAll(path)
}

// List directory contents.
func (c *Client) List(remoteDir string) error {
	fmt.Fprintf(os.Stdout, "Listing [%s] ...\n\n", remoteDir)
	files, err := c.sftpc.ReadDir(remoteDir)
	if err != nil {
		return fmt.Errorf("list remote dir: %v", err)
	}

	for _, f := range files {
		name := f.Name()
		modTime := f.ModTime().Format(time.DateTime)
		size := fmt.Sprintf("%12d", f.Size())
		if f.IsDir() {
			name = name + "/"
			modTime = ""
			size = "PRE"
		}
		fmt.Fprintf(os.Stdout, "%19s %12s %s\n", modTime, size, name)
	}
	return nil
}

// Get downloads a file from the sftp server. It returns the number of bytes copied
// and the first error encountered, if any.
func (c *Client) Get(remoteFile, localFile string) (written int64, err error) {
	// Note: SFTP To Go doesn't support O_RDWR mode
	//srcFile, err := sc.OpenFile(remoteFile, (os.O_RDONLY))
	srcFile, err := c.sftpc.Open(remoteFile)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localFile)
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	written, err = io.Copy(dstFile, srcFile)
	return
}

// Put uploads localPath to remotePath on the sftp server.
// It returns the number of bytes copied and the first error encountered, if any.
func (c *Client) Put(localPath, remotePath string) (written int64, err error) {
	if remotePath == "" {
		remotePath = filepath.Base(localPath)
	}

	srcFile, err := os.Open(localPath)
	if err != nil {
		return 0, err
	}
	defer srcFile.Close()

	if dir, _ := filepath.Split(remotePath); dir != "" {
		if err = c.sftpc.MkdirAll(dir); err != nil {
			return
		}
	}

	// Note: SFTP To Go doesn't support O_RDWR mode
	dstFile, err := c.sftpc.OpenFile(remotePath, (os.O_WRONLY | os.O_CREATE | os.O_TRUNC))
	if err != nil {
		return 0, err
	}
	defer dstFile.Close()

	written, err = io.Copy(dstFile, srcFile)
	return
}
