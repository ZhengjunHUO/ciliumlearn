/*
Copyright © 2022 ZhengjunHUO <firelouiszj@hotmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"fmt"
	"os"
	"net"

	"github.com/spf13/cobra"
	"github.com/ZhengjunHUO/ciliumlearn/ebpf/ctnctl/pkg"
)

// blockCmd represents the block command
var blockCmd = &cobra.Command{
	Use:   "block [flags] <IP> <CONTAINER_NAME|CONTAINER_ID>",
	Short: "Add an ip to container's blacklist",
	Long: `Add an ip to container's blacklist`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		// wait a -i or -e flag
		if isIngress == isEgress {
			fmt.Println("Need to specifiy ONE flag -i or -e!")
			os.Exit(1)
		}

		// check the input "ip" is valid
		if ip := net.ParseIP(args[0]); ip == nil {
			fmt.Println("Not a valid IP!")
			os.Exit(1)
		}

		// Create and Pin / Load pinned bpf resources
		if err := pkg.CreateLinkIfNotExit(args[1]); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Add IP to firewall
		var err error
		if isIngress {
			err = pkg.AddIP(args[0], args[1], true)
		}

		if isEgress {
			err = pkg.AddIP(args[0], args[1], false)
		}

		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	},
}

var (
	isIngress bool
	isEgress bool
)

func init() {
	rootCmd.AddCommand(blockCmd)
	blockCmd.Flags().BoolVarP(&isIngress, "ingress", "i", false, "update the ingress table")
	blockCmd.Flags().BoolVarP(&isEgress, "egress", "e", false, "update the egress table")
	//blockCmd.MarkFlagRequired("ingress")
}
