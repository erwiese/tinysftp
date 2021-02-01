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
	insecureIgnoreHostKey bool // SSH option StrictHostKeyChecking
)

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
				// man sftp The destination may be specified either as [user@]host[:path] or as a URI in the form sftp://[user@]host[:port][/path].
				Name:        "URI",
				Aliases:     []string{"U"},
				Destination: &rawURL,
				Usage:       "SFTP Server URL in the form sftp://user:pass@server.sftp.com:port",
				EnvVars:     []string{"SFTP_URL", "GDCSFTP_URL"},
				Required:    true,
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

				/* 				ls [-1afhlnrSt] [path]
				   				Display a remote directory listing of either path or the current directory if path is not specified.  path may contain glob(7) characters and may
				   				match multiple files.

				   				The following flags are recognized and alter the behaviour of ls accordingly:
				   				-1      Produce single columnar output.
				   				-a      List files beginning with a dot (‘.’).
				   				-f      Do not sort the listing.  The default sort order is lexicographical.
				   				-h      When used with a long format option, use unit suffixes: Byte, Kilobyte, Megabyte, Gigabyte, Terabyte, Petabyte, and Exabyte in order to
				   						reduce the number of digits to four or fewer using powers of 2 for sizes (K=1024, M=1048576, etc.).
				   				-l      Display additional details including permissions and ownership information.
				   				-n      Produce a long listing with user and group information presented numerically.
				   				-r      Reverse the sort order of the listing.
				   				-S      Sort the listing by file size.
				   				-t      Sort the listing by last modification time. */

				// Flags: []cli.Flag{
				// 	&cli.BoolFlag{Name: "forever", Aliases: []string{"forevvarr"}},
				// },
				//SkipFlagParsing: false,
				//HideHelp:        false,
				//Hidden:          false,
				//HelpName:        "puti",
				// BashComplete: func(c *cli.Context) {
				// 	fmt.Fprintf(c.App.Writer, "--better\n")
				// },
				Action: func(c *cli.Context) error {
					// c.Command.FullName()
					// c.Command.HasName("wop")
					// c.Command.Names()
					// c.Command.VisibleFlags()
					// fmt.Fprintf(c.App.Writer, "dodododododoodododddooooododododooo\n")
					// if c.Bool("forever") {
					//   c.Command.Run(c)
					// }
					remotePath := "."
					if c.NArg() == 1 {
						remotePath = c.Args().First()
						// fmt.Fprintf(c.App.Writer, "ERROR: no local files given for upload\n\n")
						//cli.ShowCommandHelpAndExit(c, "ls", 1)
					}

					conn := ConnectSSH(rawURL)
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
				Name:        "get",
				Usage:       "download file(s) from a remote SFTP server",
				UsageText:   "tinysftp get remote-path [local-path]",
				Description: "The downloaded",
				ArgsUsage:   "remote file(s)",
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						fmt.Fprintf(c.App.Writer, "ERROR: no files given for download\n\n")
						cli.ShowCommandHelpAndExit(c, "get", 1)
					}

					conn := ConnectSSH(rawURL)
					defer conn.Close()
					sc, err := NewClient(conn)
					if err != nil {
						log.Fatal(err)
					}
					defer sc.Close()

					for _, rfile := range c.Args().Slice() {
						//downloadFile(*sc, "./remote.txt", "./download.txt")
						sc.Get(rfile, filepath.Base(rfile))
						if err != nil {
							log.Printf("Could not download %s: %v", rfile, err)
						}
					}
					return nil
				},
				OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
					fmt.Fprintf(c.App.Writer, "for shame\n")
					return err
				},
			},
			{
				Name:      "put",
				Usage:     "upload local files to a remote SFTP server",
				UsageText: "tinysftp put [opts] local-path [remote-path]",
				Description: `Upload local-path and store it on the remote machine. If
the remote path name is not specified, it is given the same
name it has on the local machine. local-path may contain
glob characters and may match multiple files. If it does 
and remote-path is specified, then remote-path must
specify a directory.`,
				ArgsUsage: "local file(s)",
				// Flags: []cli.Flag{
				// 	&cli.BoolFlag{Name: "forever", Aliases: []string{"forevvarr"}},
				// },
				Action: func(c *cli.Context) error {
					if c.NArg() < 1 {
						fmt.Fprintf(c.App.Writer, "ERROR: no local files given for upload\n\n")
						cli.ShowCommandHelpAndExit(c, "put", 1)
					}

					conn := ConnectSSH(rawURL)
					defer conn.Close()
					sc, err := NewClient(conn)
					if err != nil {
						log.Fatal(err)
					}
					defer sc.Close()

					localPath := c.Args().Get(0)
					localFiles, err := filepath.Glob(localPath)
					if err != nil {
						return fmt.Errorf("invalid local-path: %s", err)
					}
					if len(localFiles) < 1 {
						return fmt.Errorf("no local files found: %s", localPath)
					}

					remotePath := c.Args().Get(1)

					if len(localFiles) == 1 && localFiles[0] == localPath {
						// no globbing
						if remotePath == "" {
							remotePath = filepath.Base(localPath)
						}
						//uploadFile(sc, "./local.txt", "./remote.txt")
						err := sc.Put(localPath, remotePath)
						if err != nil {
							return fmt.Errorf("Could not upload %s: %v", localPath, err)
						}
					} else {
						// globbing i.e. remote-path must specify a directory
						for _, lfile := range localFiles {
							remotePath = filepath.Join(remotePath, filepath.Base(lfile))
							err := sc.Put(lfile, remotePath)
							if err != nil {
								log.Printf("Could not upload %s: %v", lfile, err)
							}
						}
					}
					return nil
				},
				OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
					fmt.Fprintf(c.App.Writer, "for shame\n")
					return err
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
func ConnectSSH(rawURL string) *ssh.Client {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		log.Fatalf("Failed to parse URL: %s: %v", rawURL, err)
	}

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
			log.Fatalf("SSH host key: %v", err)
		}
		config.HostKeyCallback = ssh.FixedHostKey(hostKey)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("Connecting to %s ...", addr)
	conn, err := ssh.Dial("tcp", addr, &config)
	//conn, _, _, err := ssh.NewClientConn("tcp", addr, &config)
	if err != nil {
		log.Fatalf("Failed to connect to %s: %v", addr, err)
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
