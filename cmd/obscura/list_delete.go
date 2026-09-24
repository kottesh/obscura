package main

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/kottesh/obscura/internal/keystore"
	"github.com/kottesh/obscura/internal/sshclient"
)

// cmdList implements 'obscura list [--sent | --received]' (spec 7). The listing
// table (or one JSON object) goes to stdout; progress goes to stderr.
func cmdList(ctx context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("list")
	var sent, received bool
	fs.BoolVar(&sent, "sent", false, "only records this identity sent")
	fs.BoolVar(&received, "received", false, "only records this identity received")
	if err := parseCmd(fs, args, 0, 0); err != nil {
		return err
	}
	if sent && received {
		return usagef("list: --sent and --received are mutually exclusive")
	}
	filter := ""
	switch {
	case sent:
		filter = "sent"
	case received:
		filter = "received"
	}

	self, err := keystore.Load(env.g.configDir)
	if err != nil {
		return err
	}
	server, err := env.g.requireServer()
	if err != nil {
		return err
	}
	hostCB, err := env.g.hostKeyCallback(env.r, server)
	if err != nil {
		return err
	}

	env.r.Stage("Listing over SSH", "querying accessible records")

	client, err := sshclient.New(server, self.SignPriv, hostCB.callback)
	if err != nil {
		return err
	}
	client.SetPostDialHook(hostCB.commitHostKey)
	rows, err := client.List(ctx, filter)
	if err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		items := make([]map[string]any, 0, len(rows))
		for _, row := range rows {
			items = append(items, map[string]any{
				"id":         row.ID,
				"size":       row.Size,
				"created_at": row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
				"direction":  row.Direction,
				"carrier":    row.Carrier,
				"name":       row.Name,
			})
		}
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "list",
			"records": items,
		})
	}

	writeListingTable(env, rows)
	return nil
}

// writeListingTable renders the listing rows to stdout as an aligned,
// tab-separated table. When there are no rows it writes nothing to stdout and
// reports the empty result to stderr, preserving stream discipline (spec 8.3).
func writeListingTable(env *cmdEnv, rows []sshclient.ListRow) {
	if len(rows) == 0 {
		env.r.Stage("No records", "nothing to list")
		return
	}
	tw := tabwriter.NewWriter(env.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSIZE\tCREATED\tDIRECTION\tCARRIER\tNAME")
	for _, row := range rows {
		name := row.Name
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n",
			row.ID,
			row.Size,
			row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			row.Direction,
			row.Carrier,
			strings.ReplaceAll(name, "\t", " "),
		)
	}
	_ = tw.Flush()
}

// cmdDelete implements 'obscura delete <file_id>' (spec 7). It deletes an owned
// server record. Nothing is written to stdout on success in normal mode; JSON
// mode emits one confirmation object.
func cmdDelete(ctx context.Context, env *cmdEnv, args []string) error {
	fs := newFlagSet("delete")
	// The file id is the sole positional; pull it out before flag parsing so an
	// id starting with '-' (a valid storage-alphabet character) is not mistaken
	// for a flag.
	fileID, flagArgs := extractLeadingID(fs, args)
	if err := parseCmd(fs, flagArgs, 0, 0); err != nil {
		return err
	}
	if fileID == "" {
		return usagef("delete: expected <file_id>")
	}

	self, err := keystore.Load(env.g.configDir)
	if err != nil {
		return err
	}
	server, err := env.g.requireServer()
	if err != nil {
		return err
	}
	hostCB, err := env.g.hostKeyCallback(env.r, server)
	if err != nil {
		return err
	}

	env.r.Stage("Deleting over SSH", fmt.Sprintf("id: %s", fileID))

	client, err := sshclient.New(server, self.SignPriv, hostCB.callback)
	if err != nil {
		return err
	}
	client.SetPostDialHook(hostCB.commitHostKey)
	if err := client.Delete(ctx, fileID); err != nil {
		return err
	}

	if env.g.mode == modeJSON() {
		return writeJSON(env.stdout, map[string]any{
			"version": jsonVersion,
			"command": "delete",
			"file_id": fileID,
			"deleted": true,
		})
	}

	env.r.Success("File deleted", fmt.Sprintf("id: %s", fileID))
	return nil
}
