// Command example provisions a workspace end to end against a running
// ObjectIO, then tears it down. It is the Go mirror of the README walkthrough.
//
//	go run ./example -endpoint http://127.0.0.1:9000 -access-key AKIA… -secret-key …
package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/object-io/objectio/sdk/go/objectio"
)

func main() {
	endpoint := flag.String("endpoint", "http://127.0.0.1:9000", "gateway base URL")
	ak := flag.String("access-key", "", "system admin access key")
	sk := flag.String("secret-key", "", "system admin secret key")
	flag.Parse()

	ctx := context.Background()
	root, err := objectio.New(objectio.Config{Endpoint: *endpoint, AccessKey: *ak, SecretKey: *sk})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("== as system admin ==")
	if _, err := root.CreateTenant(ctx, objectio.Tenant{Name: "platform", DisplayName: "Platform", Enabled: true}); err != nil && !objectio.IsAlreadyExists(err) {
		log.Fatal(err)
	}
	tenants, err := root.ListTenants(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print("  tenants          : ")
	for _, t := range tenants {
		fmt.Print(t.Name, " ")
	}
	fmt.Println()

	prov, err := root.CreateUser(ctx, "csi-provisioner-go", "platform")
	if err != nil {
		log.Fatal(err)
	}
	if err := root.AddTenantAdmin(ctx, "platform", prov.UserID); err != nil {
		log.Fatal(err)
	}
	pk, err := root.CreateAccessKey(ctx, prov.UserID, objectio.CreateAccessKeyInput{})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  provisioner user : %s\n  provisioner key  : %s scoped=%v\n",
		prov.UserID, pk.AccessKeyID, pk.Scoped())

	fmt.Println("== as the provisioner ==")
	app, err := objectio.New(objectio.Config{Endpoint: *endpoint, AccessKey: pk.AccessKeyID, SecretKey: pk.SecretKey})
	if err != nil {
		log.Fatal(err)
	}
	ws, err := app.ProvisionWorkspace(ctx, objectio.ProvisionWorkspaceInput{
		Bucket:            "ws-go",
		ProvisionerUserID: prov.UserID,
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("  workspace        : bucket=%s key=%s scope=%s\n", ws.Bucket, ws.AccessKeyID, ws.Scope)

	buckets, err := app.ListBuckets(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print("  buckets it sees  : ")
	for _, b := range buckets {
		fmt.Printf("%s(owner %.8s) ", b.Name, b.Owner)
	}
	fmt.Println()

	fmt.Println("== the workspace credential is confined ==")
	wsc, err := objectio.New(objectio.Config{Endpoint: *endpoint, AccessKey: ws.AccessKeyID, SecretKey: ws.SecretKey})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := wsc.ListBuckets(ctx); err == nil {
		fmt.Println("  management API   : ALLOWED  <-- would be a bug")
	} else {
		fmt.Printf("  management API   : refused, forbidden=%v\n    %v\n", objectio.IsForbidden(err), err)
	}

	fmt.Println("== deprovision ==")
	if err := app.DeprovisionWorkspace(ctx, prov.UserID, "ws-go"); err != nil {
		log.Fatal(err)
	}
	left, _ := app.ListBuckets(ctx)
	fmt.Printf("  buckets now      : %d\n", len(left))

	// tidy up the provisioner itself
	_ = root.DeleteAccessKey(ctx, pk.AccessKeyID)
	_ = root.DeleteUser(ctx, prov.UserID)
}
