package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

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
		return nil, fmt.Errorf("Could not start SFTP subsystem: %v", err)
	}

	return &Client{sc}, nil
}

// Close the SFTP client connection.
func (c *Client) Close() error {
	return c.sftpc.Close()
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
		return fmt.Errorf("Could not list remote dir: %v", err)
	}

	for _, f := range files {
		name := f.Name()
		modTime := f.ModTime().Format("2006-01-02 15:04:05")
		size := fmt.Sprintf("%12d", f.Size())
		if f.IsDir() {
			name = name + "/"
			modTime = ""
			size = "PRE"
		}
		// Output each file name and size in bytes
		fmt.Fprintf(os.Stdout, "%19s %12s %s\n", modTime, size, name)
	}
	return nil
}

// Get downloads a file from the sftp server.
func (c *Client) Get(remoteFile, localFile string) error {
	fmt.Fprintf(os.Stdout, "GET %s to %s ...\n", remoteFile, localFile)
	// Note: SFTP To Go doesn't support O_RDWR mode
	//srcFile, err := sc.OpenFile(remoteFile, (os.O_RDONLY))
	srcFile, err := c.sftpc.Open(remoteFile)
	if err != nil {
		return fmt.Errorf("Could not open remote file: %v", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("Could not open local file: %v", err)
	}
	defer dstFile.Close()

	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("Could not download remote file: %v", err)
	}
	fmt.Fprintf(os.Stdout, "%d bytes copied\n", bytes)
	return nil
}

// Put uploads localFile to remoteFile on the sftp server.
func (c *Client) Put(localFile, remoteFile string) error {
	if remoteFile == "" {
		remoteFile = filepath.Base(localFile)
	}
	fmt.Fprintf(os.Stdout, "Uploading [%s] to [%s] ...\n", localFile, remoteFile)

	srcFile, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("Could not open local file: %v", err)
	}
	defer srcFile.Close()

	if dir, _ := filepath.Split(remoteFile); dir != "" {
		c.sftpc.MkdirAll(dir)
	}

	// Note: SFTP To Go doesn't support O_RDWR mode
	dstFile, err := c.sftpc.OpenFile(remoteFile, (os.O_WRONLY | os.O_CREATE | os.O_TRUNC))
	if err != nil {
		return fmt.Errorf("Could not open remote file: %v", err)
	}
	defer dstFile.Close()

	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		return fmt.Errorf("Could not upload local file: %v", err)
	}
	fmt.Fprintf(os.Stdout, "%d bytes copied\n", bytes)
	return nil
}
