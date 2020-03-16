// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Command mkcert is a simple zero-config tool to make development certificates.
package mkcert

import (
	"crypto"
	"crypto/x509"
	"github.com/pubgo/antproxy/cmds/cnst"
	"github.com/pubgo/g/xerror"
	"github.com/pubgo/xcmd/xcmd"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
)

const rootName = cnst.RootName
const rootKeyName = cnst.RootKeyName

func Init() *xcmd.Command {
	var (
		install   = false
		uninstall = false
	)
	args := xcmd.Args(func(cmd *xcmd.Command) {
		cmd.Flags().BoolVarP(&install, "install", "i", install, "install root ca")
		cmd.Flags().BoolVarP(&uninstall, "uninstall", "u", uninstall, "uninstall root ca")
	})

	return args(&xcmd.Command{
		Use:   "cert",
		Short: "root cert gen",
		RunE: func(cmd *xcmd.Command, args []string) (err error) {
			defer xerror.RespErr(&err)
			(&mkcert{installMode: install, uninstallMode: uninstall}).Run()
			return
		},
	})
}

type mkcert struct {
	installMode, uninstallMode bool
	ecdsa                      bool

	CAROOT string
	caCert *x509.Certificate
	caKey  crypto.PrivateKey

	// The system cert pool is only loaded once. After installing the root, checks
	// will keep failing until the next execution. TODO: maybe execve?
	// https://github.com/golang/go/issues/24540 (thanks, myself)
	ignoreCheckFailure bool
}

func (m *mkcert) Run() {
	m.CAROOT = cnst.GetCAROOT()
	if m.CAROOT == "" {
		log.Fatalln("ERROR: failed to find the default CA location, set one as the CAROOT env var")
	}
	fatalIfErr(os.MkdirAll(m.CAROOT, 0755), "failed to create the CAROOT")
	m.loadCA()

	if m.installMode {
		m.install()
		return
	}

	if m.uninstallMode {
		m.uninstall()
		return
	}
}

func (m *mkcert) install() {
	if storeEnabled("system") {
		if m.checkPlatform() {
			log.Print("The local CA is already installed in the system trust store! 👍")
		} else {
			if m.installPlatform() {
				log.Print("The local CA is now installed in the system trust store! ⚡️")
			}
			m.ignoreCheckFailure = true // TODO: replace with a check for a successful install
		}
	}
	if storeEnabled("nss") && hasNSS {
		if m.checkNSS() {
			log.Printf("The local CA is already installed in the %s trust store! 👍", NSSBrowsers)
		} else {
			if hasCertutil && m.installNSS() {
				log.Printf("The local CA is now installed in the %s trust store (requires browser restart)! 🦊", NSSBrowsers)
			} else if CertutilInstallHelp == "" {
				log.Printf(`Note: %s support is not available on your platform. ℹ️`, NSSBrowsers)
			} else if !hasCertutil {
				log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically installed in %s! ⚠️`, NSSBrowsers)
				log.Printf(`Install "certutil" with "%s" and re-run "mkcert -install" 👈`, CertutilInstallHelp)
			}
		}
	}
	if storeEnabled("java") && hasJava {
		if m.checkJava() {
			log.Println("The local CA is already installed in Java's trust store! 👍")
		} else {
			if hasKeytool {
				m.installJava()
				log.Println("The local CA is now installed in Java's trust store! ☕️")
			} else {
				log.Println(`Warning: "keytool" is not available, so the CA can't be automatically installed in Java's trust store! ⚠️`)
			}
		}
	}
	log.Print("")
}

func (m *mkcert) uninstall() {
	if storeEnabled("nss") && hasNSS {
		if hasCertutil {
			m.uninstallNSS()
		} else if CertutilInstallHelp != "" {
			log.Print("")
			log.Printf(`Warning: "certutil" is not available, so the CA can't be automatically uninstalled from %s (if it was ever installed)! ⚠️`, NSSBrowsers)
			log.Printf(`You can install "certutil" with "%s" and re-run "mkcert -uninstall" 👈`, CertutilInstallHelp)
			log.Print("")
		}
	}
	if storeEnabled("java") && hasJava {
		if hasKeytool {
			m.uninstallJava()
		} else {
			log.Print("")
			log.Println(`Warning: "keytool" is not available, so the CA can't be automatically uninstalled from Java's trust store (if it was ever installed)! ⚠️`)
			log.Print("")
		}
	}
	if storeEnabled("system") && m.uninstallPlatform() {
		log.Print("The local CA is now uninstalled from the system trust store(s)! 👋")
		log.Print("")
	} else if storeEnabled("nss") && hasCertutil {
		log.Printf("The local CA is now uninstalled from the %s trust store(s)! 👋", NSSBrowsers)
		log.Print("")
	}
}

func (m *mkcert) checkPlatform() bool {
	if m.ignoreCheckFailure {
		return true
	}

	_, err := m.caCert.Verify(x509.VerifyOptions{})
	return err == nil
}

func storeEnabled(name string) bool {
	stores := os.Getenv("TRUST_STORES")
	if stores == "" {
		return true
	}
	for _, store := range strings.Split(stores, ",") {
		if store == name {
			return true
		}
	}
	return false
}

func fatalIfErr(err error, msg string) {
	if err != nil {
		log.Fatalf("ERROR: %s: %s", msg, err)
	}
}

func fatalIfCmdErr(err error, cmd string, out []byte) {
	if err != nil {
		log.Fatalf("ERROR: failed to execute \"%s\": %s\n\n%s\n", cmd, err, out)
	}
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func binaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

var sudoWarningOnce sync.Once

func commandWithSudo(cmd ...string) *exec.Cmd {
	if u, err := user.Current(); err == nil && u.Uid == "0" {
		return exec.Command(cmd[0], cmd[1:]...)
	}
	if !binaryExists("sudo") {
		sudoWarningOnce.Do(func() {
			log.Println(`Warning: "sudo" is not available, and mkcert is not running as root. The (un)install operation might fail. ⚠️`)
		})
		return exec.Command(cmd[0], cmd[1:]...)
	}
	return exec.Command("sudo", append([]string{"--prompt=Sudo password:", "--"}, cmd...)...)
}
