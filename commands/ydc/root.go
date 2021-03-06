// Copyright (c) 2018 YouDealChain Authors.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package ydc

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/YouDealChain/YouDealChain/commands/ydc/ctl"
	"github.com/YouDealChain/YouDealChain/commands/ydc/wallet"
	"github.com/YouDealChain/YouDealChain/log"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// logger
var logger = log.NewLogger("ydc")

// root command
var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ydc",
	Short: "YouDealChain command-line interface",
	Long: `YouDealChain, a lightweight blockchain built for processing
			transacitons on personal service market.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger.Error(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ydc.yaml)")

	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringP("network", "n", "mainnet", "network name (default mainnet)")
	rootCmd.PersistentFlags().String("workspace", "", "work directory for ydcd (default ~/.ydcd)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level [debug|info|warn|error|fatal]")

	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("network", rootCmd.PersistentFlags().Lookup("network"))
	viper.BindPFlag("workspace", rootCmd.PersistentFlags().Lookup("workspace"))

	// init subcommand
	ctl.Init(rootCmd)
	wallet.Init(rootCmd)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// Find home directory.
	home, err := homedir.Dir()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Search config in home directory or current directory with name ".ydc" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigName(".ydc")
	}

	viper.SetEnvPrefix("ydc")
	viper.SetEnvKeyReplacer(strings.NewReplacer("_", "."))
	viper.AutomaticEnv() // read in environment variables that match

	viper.SetDefault("workspace", path.Join(home, ".ydcd"))

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
}

////////// viper config //////////
// log:
//     level: debug|info|warn|error
// verbose: true|false
// node:
//     addpeer: [multiaddr]
//     listen:
//         port: 19199
//         address: 127.0.0.1
