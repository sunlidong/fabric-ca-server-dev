package cmd

/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

                 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"caserver/lib"
	calog "caserver/lib/common/log"
	"caserver/lib/metadata"
	"caserver/util"

	golog "log"

	"github.com/cloudflare/cfssl/log"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RunMain is the fabric-ca server main
func RunMain(args []string) error {
	golog.Println("----- main 100000001002")
	// Save the os.Args
	saveOsArgs := os.Args
	os.Args = args

	cmdName := ""
	if len(args) > 1 {
		// ./main init -b ldsun:123456  这里获取的是  init 的内容
		cmdName = args[1]
	}

	scmd := NewCommand(cmdName, blockingStart)

	// Execute the command
	err := scmd.Execute()

	// Restore original os.Args
	os.Args = saveOsArgs

	return err
}

// NewCommand returns new ServerCmd ready for running
func NewCommand(name string, blockingStart bool) *ServerCmd {
	s := &ServerCmd{
		name:          name,
		blockingStart: blockingStart,
		myViper:       viper.New(),
	}
	s.init()
	return s
}

// Execute runs this ServerCmd
func (s *ServerCmd) Execute() error {
	return s.rootCmd.Execute()
}

// init initializes the ServerCmd instance
// It intializes the cobra root and sub commands and
// registers command flgs with viper
func (s *ServerCmd) init() {
	// root command
	rootCmd := &cobra.Command{
		Use:   cmdName,
		Short: longName,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			err := s.configInit()
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			util.CmdRunBegin(s.myViper)
			return nil
		},
	}
	s.rootCmd = rootCmd

	// initCmd represents the server init command
	initCmd := &cobra.Command{
		Use:   "init",
		Short: fmt.Sprintf("Initialize the %s", shortName),
		Long:  "Generate the key material needed by the server if it doesn't already exist",
	}
	initCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, initCmd.UsageString())
		}
		err := s.getServer().Init(false)
		if err != nil {
			util.Fatal("Initialization failure: %s", err)
		}
		log.Info("Initialization was successful")
		return nil
	}
	s.rootCmd.AddCommand(initCmd)

	// startCmd represents the server start command
	startCmd := &cobra.Command{
		Use:   "start",
		Short: fmt.Sprintf("Start the %s", shortName),
	}

	startCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return errors.Errorf(extraArgsError, args, startCmd.UsageString())
		}
		err := s.getServer().Start()
		if err != nil {
			return err
		}
		return nil
	}
	s.rootCmd.AddCommand(startCmd)

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Prints Fabric CA Server version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(metadata.GetVersionInfo(cmdName))
		},
	}
	s.rootCmd.AddCommand(versionCmd)
	s.registerFlags()
}

// registerFlags registers command flags with viper
func (s *ServerCmd) registerFlags() {
	// Get the default config file path
	cfg := util.GetDefaultConfigFile(cmdName)

	// All env variables must be prefixed
	s.myViper.SetEnvPrefix(envVarPrefix)
	s.myViper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set specific global flags used by all commands
	pflags := s.rootCmd.PersistentFlags()
	pflags.StringVarP(&s.cfgFileName, "config", "c", "", "Configuration file")
	pflags.MarkHidden("config")
	// Don't want to use the default parameter for StringVarP. Need to be able to identify if home directory was explicitly set
	pflags.StringVarP(&s.homeDirectory, "home", "H", "", fmt.Sprintf("Server's home directory (default \"%s\")", filepath.Dir(cfg)))
	util.FlagString(s.myViper, pflags, "boot", "b", "",
		"The user:pass for bootstrap admin which is required to build default config file")

	// Register flags for all tagged and exported fields in the config
	s.cfg = &lib.ServerConfig{}
	tags := map[string]string{
		"help.csr.cn":           "The common name field of the certificate signing request to a parent fabric-ca-server",
		"help.csr.serialnumber": "The serial number in a certificate signing request to a parent fabric-ca-server",
		"help.csr.hosts":        "A list of comma-separated host names in a certificate signing request to a parent fabric-ca-server",
	}
	err := util.RegisterFlags(s.myViper, pflags, s.cfg, nil)
	if err != nil {
		panic(err)
	}
	caCfg := &lib.CAConfig{}
	err = util.RegisterFlags(s.myViper, pflags, caCfg, tags)
	if err != nil {
		panic(err)
	}
}

// Configuration file is not required for some commands like version
func (s *ServerCmd) configRequired() bool {
	return s.name != version
}

// getServer returns a lib.Server for the init and start commands
func (s *ServerCmd) getServer() *lib.Server {
	return &lib.Server{
		HomeDir:       s.homeDirectory,
		Config:        s.cfg,
		BlockingStart: s.blockingStart,
		CA: lib.CA{
			Config:         &s.cfg.CAcfg,
			ConfigFilePath: s.cfgFileName,
		},
	}
}

// Initialize config
func (s *ServerCmd) configInit() (err error) {
	if !s.configRequired() {
		return nil
	}

	s.cfgFileName, s.homeDirectory, err = util.ValidateAndReturnAbsConf(s.cfgFileName, s.homeDirectory, cmdName)
	if err != nil {
		return err
	}

	s.myViper.AutomaticEnv() // read in environment variables that match
	logLevel := s.myViper.GetString("loglevel")
	debug := s.myViper.GetBool("debug")
	calog.SetLogLevel(logLevel, debug)

	log.Debugf("Home directory: %s", s.homeDirectory)

	// If the config file doesn't exist, create a default one
	if !util.FileExists(s.cfgFileName) {
		err = s.createDefaultConfigFile()
		if err != nil {
			return errors.WithMessage(err, "Failed to create default configuration file")
		}
		log.Infof("Created default configuration file at %s", s.cfgFileName)
	} else {
		log.Infof("Configuration file location: %s", s.cfgFileName)
	}

	// Read the config
	err = lib.UnmarshalConfig(s.cfg, s.myViper, s.cfgFileName, true)
	if err != nil {
		return err
	}

	// Read operations tls files
	if s.myViper.GetBool("operations.tls.enabled") {
		cf := s.myViper.GetString("operations.tls.cert.file")
		if cf == "" {
			cf = s.cfg.Operations.TLS.CertFile
		}
		if !filepath.IsAbs(cf) {
			cf = filepath.Join(s.homeDirectory, cf)
		}
		if !util.FileExists(cf) {
			return errors.Errorf("failed to read certificate file: %s", cf)
		}
		s.cfg.Operations.TLS.CertFile = cf

		kf := s.myViper.GetString("operations.tls.key.file")
		if kf == "" {
			kf = s.cfg.Operations.TLS.KeyFile
		}
		if !filepath.IsAbs(kf) {
			kf = filepath.Join(s.homeDirectory, kf)
		}
		if !util.FileExists(kf) {
			return errors.Errorf("failed to read key file: %s", kf)
		}
		s.cfg.Operations.TLS.KeyFile = kf
	}

	// The pathlength field controls how deep the CA hierarchy when requesting
	// certificates. If it is explicitly set to 0, set the PathLenZero field to
	// true as CFSSL expects.
	pl := "csr.ca.pathlength"
	if s.myViper.IsSet(pl) && s.myViper.GetInt(pl) == 0 {
		s.cfg.CAcfg.CSR.CA.PathLenZero = true
	}
	// The maxpathlen field controls how deep the CA hierarchy when issuing
	// a CA certificate. If it is explicitly set to 0, set the PathLenZero
	// field to true as CFSSL expects.
	pl = "signing.profiles.ca.caconstraint.maxpathlen"
	if s.myViper.IsSet(pl) && s.myViper.GetInt(pl) == 0 {
		s.cfg.CAcfg.Signing.Profiles["ca"].CAConstraint.MaxPathLenZero = true
	}

	return nil
}

func (s *ServerCmd) createDefaultConfigFile() error {
	var user, pass string
	// If LDAP is enabled, authentication of enrollment requests are performed
	// by using LDAP authentication; therefore, no bootstrap username and password
	// are required.
	ldapEnabled := s.myViper.GetBool("ldap.enabled")
	if !ldapEnabled {
		// When LDAP is disabled, the fabric-ca-server functions as its own
		// identity registry; therefore, we require that the default configuration
		// file have a bootstrap username and password that is used to enroll a
		// bootstrap administrator.  Other identities can be dynamically registered.
		// Create the default config, but only if they provided this bootstrap
		// username and password.
		up := s.myViper.GetString("boot")
		if up == "" {
			return errors.New("The '-b user:pass' option is required")
		}
		ups := strings.Split(up, ":")
		if len(ups) < 2 {
			return errors.Errorf("The value '%s' on the command line is missing a colon separator", up)
		}
		if len(ups) > 2 {
			ups = []string{ups[0], strings.Join(ups[1:], ":")}
		}
		user = ups[0]
		pass = ups[1]
		if len(user) >= 1024 {
			return errors.Errorf("The identity name must be less than 1024 characters: '%s'", user)
		}
		if len(pass) == 0 {
			return errors.New("An empty password in the '-b user:pass' option is not permitted")
		}
	}

	var myhost string
	var err error
	myhost, err = os.Hostname()
	if err != nil {
		return err
	}

	// Do string subtitution to get the default config
	cfg := strings.Replace(defaultCfgTemplate, "<<<VERSION>>>", metadata.Version, 1)
	cfg = strings.Replace(cfg, "<<<ADMIN>>>", user, 1)
	cfg = strings.Replace(cfg, "<<<ADMINPW>>>", pass, 1)
	cfg = strings.Replace(cfg, "<<<MYHOST>>>", myhost, 1)
	purl := s.myViper.GetString("intermediate.parentserver.url")
	log.Debugf("parent server URL: '%s'", util.GetMaskedURL(purl))
	if purl == "" {
		// This is a root CA
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", "fabric-ca-server", 1)
		cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "1", 1)
	} else {
		// This is an intermediate CA
		cfg = strings.Replace(cfg, "<<<COMMONNAME>>>", "", 1)
		cfg = strings.Replace(cfg, "<<<PATHLENGTH>>>", "0", 1)
	}

	// Now write the file
	cfgDir := filepath.Dir(s.cfgFileName)
	err = os.MkdirAll(cfgDir, 0755)
	if err != nil {
		return err
	}

	// Now write the file
	return ioutil.WriteFile(s.cfgFileName, []byte(cfg), 0644)
}
