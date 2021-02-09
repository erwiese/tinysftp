package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/urfave/cli/v2"
)

const (
	version = "0.1.0"
)

var (
	// SSH option StrictHostKeyChecking
	insecureIgnoreHostKey bool
)

// A fileCouple is a couple of a local and remote file.
type fileCouple struct {
	localPath  string
	remotePath string
}

func main() {
	var rawURL string
	//var conn *ssh.Client

	app := &cli.App{
		Version:   "v" + version,
		Compiled:  time.Now(),
		Authors:   []*cli.Author{{Name: "Erwin Wiesensarter", Email: "Erwin.Wiesensarter@bkg.bund.de"}},
		Copyright: "(c) 2021 BKG Frankfurt",
		HelpName:  "tinysftp",
		Usage:     "simple SFTP client",
		//UsageText: "contrive - demonstrating the available API",
		ArgsUsage: "[args...]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "URI",
				Aliases:     []string{"U"},
				Destination: &rawURL,
				// man sftp: The destination may be specified either as [user@]host[:path] or as a URI in the form sftp://[user@]host[:port][/path].
				Usage:    "SFTP Server URL in the form sftp://user:pass@server.sftp.com:port, as you may know it from sftp",
				EnvVars:  []string{"SFTPGO_URL", "GDCSFTP_URL"},
				Required: true,
			},
			&cli.BoolFlag{
				Name:        "ignoreHostKey",
				Aliases:     []string{"z"},
				Destination: &insecureIgnoreHostKey,
				Usage:       "Accept any host key. This should not be used for production",
			},
		},
		Commands: []*cli.Command{
			{
				Name:        "ls",
				Usage:       "list directory contents on a remote SFTP server",
				UsageText:   "tinysftp ls [path]",
				Description: "Display the remote directory listing of either path or the current directory if path is not specified.",
				ArgsUsage:   "remote path",
				Action: func(c *cli.Context) error {
					remotePath := "."
					if c.NArg() == 1 {
						remotePath = c.Args().First()
					}

					parsedURL, err := url.Parse(rawURL)
					if err != nil {
						log.Fatalf("Failed to parse URL: %s: %v", rawURL, err)
					}

					conn := ConnectSSH(parsedURL)
					defer conn.Close()

					sc, err := NewClient(conn)
					if err != nil {
						log.Fatal(err)
					}
					defer sc.Close()

					err = sc.List(remotePath)
					fmt.Fprintf(os.Stdout, "\n")
					return err
				},
				OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
					fmt.Fprintf(c.App.Writer, "for shame\n")
					return err
				},
			},
			{
				Name:  "get",
				Usage: "retrieve remote file(s)",
				UsageText: `tinysftp get remote-path [local-path]

EXAMPLE: 
		# Quote remote-path if you use globbing
		tinysftp -U sftp://user:pass@server.sftp.com:port get "testfile*.txt" localDir
				
		tinysftp -U sftp://user:pass@server.sftp.com:port get file1.txt localDir/file2.txt
				   `,
				Description: `Retrieve the remote-path and store it on the local machine.  
If the local-path name is not specified, it is given the same name it has on the remote
machine. Remote-path may contain glob characters and may match multiple files. 
If it does and local-path is specified, then local-path must specify a directory.
				`,
				ArgsUsage: "remote file(s)",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						fmt.Fprintf(c.App.Writer, "no remote-path given\n\n")
						cli.ShowCommandHelpAndExit(c, "get", 1)
					}
					remotePath := c.Args().Get(0)
					localPath := c.Args().Get(1)

					parsedURL, err := url.Parse(rawURL)
					if err != nil {
						log.Fatalf("Failed to parse URL: %s: %v", rawURL, err)
					}

					conn := ConnectSSH(parsedURL)
					defer conn.Close()
					sc, err := NewClient(conn)
					if err != nil {
						log.Fatal(err)
					}
					defer sc.Close()

					remotePaths, err := sc.Glob(remotePath)
					if len(remotePaths) == 0 {
						fmt.Fprintf(c.App.Writer, "No remote-path found named %q\n\n", remotePath)
						os.Exit(0)
					}

					couples, err := resolveDownloads(remotePaths, localPath)
					if err != nil {
						return err
					}

					for _, couple := range couples {
						if _, err := os.Stat(couple.localPath); !os.IsNotExist(err) {
							log.Printf("W! local-path already exists - no overwrite: %s", couple.localPath)
							continue
						}
						starttime := time.Now()
						written, err := sc.Get(couple.remotePath, couple.localPath)
						dur := time.Since(starttime)
						if err != nil {
							log.Printf("W! GET %s to %s Failed: %s", couple.remotePath, couple.localPath, err)
							continue
						}
						log.Printf("D! GET %s to %s OK %d %s", couple.remotePath, couple.localPath, written, dur)
					}
					return nil
				},
			},
			{
				Name:  "put",
				Usage: "upload local file(s) to a remote server",
				UsageText: `tinysftp put [opts] local-path [remote-path]

EXAMPLE: 
   # Quote local-path if you use globbing
   tinysftp -U sftp://user:pass@server.sftp.com:port put "testfile*.txt" RemoteDir/

   tinysftp -U sftp://user:pass@server.sftp.com:port put file1.txt RemoteDir/file2.txt
   `,
				Description: `Upload local-path and store it on the remote machine. If
the remote-path name is not specified, it is given the same
name it has on the local machine. local-path may contain
glob characters and may match multiple files. If it does 
and remote-path is specified, then remote-path must
specify a directory.`,
				ArgsUsage: "local file(s)",
				// Flags: []cli.Flag{
				// 	&cli.BoolFlag{
				// 		Name: "r",
				// 		//Destination: &insecureIgnoreHostKey,
				// 		Usage: "Recursively copy entire directories when uploading and downloading. Note that sftp does not follow symbolic links encountered in the tree traversal.",
				// 	},
				// },
				// -E      Delete source files after successful transfer (dangerous)
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						fmt.Fprintf(c.App.Writer, "no local-path given\n\n")
						cli.ShowCommandHelpAndExit(c, "put", 1)
					}
					//fmt.Println(c.Args().Slice())

					localPath := c.Args().Get(0)

					parsedURL, err := url.Parse(rawURL)
					if err != nil {
						log.Fatalf("Failed to parse URL: %s: %v", rawURL, err)
					}

					remotePath := parsedURL.Path
					// command args overwrite URL
					if c.Args().Get(1) != "" {
						remotePath = c.Args().Get(1)
					}

					couples, err := resolveUploads(localPath, remotePath)
					if err != nil {
						return err
					}

					conn := ConnectSSH(parsedURL)
					defer conn.Close()
					sc, err := NewClient(conn)
					if err != nil {
						log.Fatal(err)
					}
					defer sc.Close()

					for _, couple := range couples {
						starttime := time.Now()
						written, err := sc.Put(couple.localPath, couple.remotePath)
						dur := time.Since(starttime)
						if err != nil {
							log.Printf("W! PUT %s to %s Failed: %s", couple.localPath, couple.remotePath, err)
							continue
						}
						log.Printf("D! PUT %s to %s OK %d %s", couple.localPath, couple.remotePath, written, dur)
					}
					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

// ConnectSSH starts a client connection to the SSH server given by rawURL.
func ConnectSSH(parsedURL *url.URL) *ssh.Client {
	user := parsedURL.User.Username()
	pass, _ := parsedURL.User.Password()
	host := parsedURL.Hostname()
	port := 22
	if parsedURL.Port() != "" {
		if p, err := strconv.Atoi(parsedURL.Port()); err == nil {
			port = p
		}
	}

	var auths []ssh.AuthMethod

	// Try to use $SSH_AUTH_SOCK which contains the path of the unix file socket that the sshd agent uses
	// for communication with other processes.
	if aconn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(aconn).Signers))
	}
	if pass != "" {
		auths = append(auths, ssh.Password(pass))
	}

	config := ssh.ClientConfig{
		User:    user,
		Auth:    auths,
		Timeout: time.Second * 30,
	}

	if insecureIgnoreHostKey {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		hostKey, err := getHostKey(host, port)
		if err != nil {
			log.Fatalf("E: SSH host key: %v", err)
		}
		config.HostKeyCallback = ssh.FixedHostKey(hostKey)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("I! Connecting to %s ...", addr)
	conn, err := ssh.Dial("tcp", addr, &config)
	//conn, _, _, err := ssh.NewClientConn("tcp", addr, &config)
	if err != nil {
		log.Fatalf("E: Failed to connect to %s: %v", addr, err)
	}

	return conn
}

// Get host key from local known hosts
func getHostKey(hostname string, port int) (ssh.PublicKey, error) {
	// parse OpenSSH known_hosts file
	// ssh or use ssh-keyscan to get initial key
	homedir, _ := os.UserHomeDir()
	file, err := os.Open(filepath.Join(homedir, ".ssh", "known_hosts"))
	if err != nil {
		return nil, fmt.Errorf("Could not read known_hosts file: %v", err)
	}
	defer file.Close()

	// see golang.org/x/crypto/ssh/knownhosts Normalize()
	host := hostname
	if port != 22 {
		host = fmt.Sprintf("[%s]:%d", host, port)
	}

	scanner := bufio.NewScanner(file)
	var hostKey ssh.PublicKey
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) != 3 {
			continue
		}
		if strings.Contains(fields[0], host) {
			var err error
			hostKey, _, _, _, err = ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				return nil, fmt.Errorf("Error parsing %q: %v", fields[2], err)
			}
			break
		}
	}

	if hostKey == nil {
		return nil, fmt.Errorf("No hostkey found for %s", host)
	}

	return hostKey, nil
}

// resolveDownloads forms pairs of local- and remote files for download.
func resolveDownloads(remotePaths []string, localPath string) (couples []fileCouple, err error) {
	if localPath == "" {
		for _, rpath := range remotePaths {
			couples = append(couples, fileCouple{filepath.Base(rpath), rpath})
		}
		return
	}

	// local-path given and exists
	if fi, err := os.Stat(localPath); !os.IsNotExist(err) {
		if fi.IsDir() {
			for _, rpath := range remotePaths {
				lpath := filepath.Join(localPath, filepath.Base(rpath))
				couples = append(couples, fileCouple{lpath, rpath})
			}
			return couples, nil
		}

		if len(remotePaths) > 1 {
			return couples, fmt.Errorf("E! local-path is not a directy: %s", localPath)
		}

		// It is a existing file
		couples = append(couples, fileCouple{localPath, remotePaths[0]})
		return couples, nil
	}

	// local-path given but does not exist
	if len(remotePaths) > 1 {
		return couples, fmt.Errorf("E! local-path is not an existing directy: %s", localPath)
	}

	couples = append(couples, fileCouple{localPath, remotePaths[0]})
	return
}

// resolveUploads forms pairs of local- and remote files for upload.
func resolveUploads(localPath, remotePath string) (couples []fileCouple, err error) {
	localFiles, err := filepath.Glob(localPath)
	if err != nil {
		return couples, fmt.Errorf("E! invalid local-path: %s", err)
	}
	if len(localFiles) < 1 {
		return couples, fmt.Errorf("E! local files do not exist")
	}

	sep := string(filepath.Separator)

	// the given local-path did not contain globs
	if len(localFiles) == 1 && localFiles[0] == localPath {
		if remotePath == "" {
			remotePath = filepath.Base(localPath)
		} else if strings.HasSuffix(remotePath, sep) { // remotePath is a dir
			remotePath = filepath.Join(remotePath, filepath.Base(localPath))
		}
		couples = append(couples, fileCouple{localPath, remotePath})
		return
	}

	// globs i.e. remote-path must specify a directory

	// if remotePath != "" && !strings.HasSuffix(remotePath, sep) {
	// 	err = fmt.Errorf("E! local-path contains glob characters hence remote-path must be empty or specify a directory that must end with a slash")
	// 	return
	// }
	for _, lfile := range localFiles {
		remPath := filepath.Join(remotePath, filepath.Base(lfile))
		couples = append(couples, fileCouple{lfile, remPath})
	}
	return
}
