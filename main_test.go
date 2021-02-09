package main

import (
	"net/url"
	"os"
	"reflect"
	"testing"
)

func Test_getHostKey(t *testing.T) {
	type args struct {
		host string
		port int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := getHostKey(tt.args.host, tt.args.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("getHostKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_connectSSH(t *testing.T) {
	rawURL := os.Getenv("GDCSFTP_URL")
	if rawURL == "" {
		t.Fatalf("no sftp URL given")
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Failed to parse URL: %s: %v", rawURL, err)
	}

	conn := ConnectSSH(parsedURL)
	defer conn.Close()
}

func Test_resolveUploads(t *testing.T) {
	type args struct {
		localPath  string
		remotePath string
	}
	tests := []struct {
		name        string
		args        args
		wantCouples []fileCouple
		wantErr     bool
	}{
		{name: "no glob",
			args:        args{"testdata/file1.txt", ""},
			wantCouples: []fileCouple{{"testdata/file1.txt", "file1.txt"}},
			wantErr:     false,
		},
		{name: "no glob, one local and remote path",
			args:        args{"testdata/file1.txt", "mistfile.txt"},
			wantCouples: []fileCouple{{"testdata/file1.txt", "mistfile.txt"}},
			wantErr:     false,
		},
		{name: "no glob, remote path",
			args:        args{"testdata/file1.txt", "EUREF/"},
			wantCouples: []fileCouple{{"testdata/file1.txt", "EUREF/file1.txt"}},
			wantErr:     false,
		},
		{name: "glob, no remote path",
			args:        args{"testdata/file?.txt", ""},
			wantCouples: []fileCouple{{"testdata/file1.txt", "file1.txt"}, {"testdata/file2.txt", "file2.txt"}},
			wantErr:     false,
		},
		{name: "glob, with remote path",
			args:        args{"testdata/file?.txt", "SomeDir/"},
			wantCouples: []fileCouple{{"testdata/file1.txt", "SomeDir/file1.txt"}, {"testdata/file2.txt", "SomeDir/file2.txt"}},
			wantErr:     false,
		},
		{name: "glob, with remote path w/o slash",
			args:        args{"testdata/file?.txt", "SomeDir"},
			wantCouples: []fileCouple{{"testdata/file1.txt", "SomeDir/file1.txt"}, {"testdata/file2.txt", "SomeDir/file2.txt"}},
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCouples, err := resolveUploads(tt.args.localPath, tt.args.remotePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("resolveUploads() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCouples, tt.wantCouples) {
				t.Errorf("resolveUploads() = %v, want %v", gotCouples, tt.wantCouples)
			}
		})
	}
}
