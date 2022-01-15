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

	"github.com/spf13/cobra"
)

// unblockCmd represents the unblock command
var unblockCmd = &cobra.Command{
	Use:   "unblock [flags] <IP> <CONTAINER_NAME|CONTAINER_ID>",
	Short: "Remove an ip from container's blacklist",
	Long: `Remove an ip from container's blacklist`,
	Args: cobra.MinimumNArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("unblock called: %v, %v\n", isIngress, isEgress)
	},
}

func init() {
	rootCmd.AddCommand(unblockCmd)
	unblockCmd.Flags().BoolVarP(&isIngress, "ingress", "i", false, "update the ingress table")
	unblockCmd.Flags().BoolVarP(&isEgress, "egress", "e", false, "update the egress table")
}
