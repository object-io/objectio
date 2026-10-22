//! Who may call what on the data lake APIs: the Iceberg REST catalog, Unity
//! Catalog and the Delta Sharing admin surface, with auth on.
//!
//! Each of these sits outside the S3 authorization layer and makes its own
//! decisions, so each is tested here from the outside: a request without a
//! credential, one with a bad credential, a caller of another tenant, and a
//! caller whose policies allow less than everything.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};

/// A user's ARN and access key.
struct Key {
    arn: String,
    ak: String,
    sk: String,
}

/// Create a tenant with an admin user, returning the admin's key.
fn provision_tenant_admin(c: &Cluster, tenant: &str) -> Key {
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": tenant, "display_name": tenant, "enabled": true}),
    )
    .expect_ok();
    let (user_id, key) = provision_user(c, tenant, &format!("{tenant}-admin"));
    c.json(
        "POST",
        &format!("/_admin/tenants/{tenant}/admins"),
        json!({"user_id": user_id}),
    )
    .expect_ok();
    key
}

/// Create a plain (non-admin) user in `tenant`, returning its id and key.
fn provision_user(c: &Cluster, tenant: &str, name: &str) -> (String, Key) {
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": name, "tenant": tenant}),
    );
    user.expect_ok();
    let u = user.json();
    let user_id = u["user_id"].as_str().expect("user_id").to_string();
    let arn = u["arn"].as_str().expect("arn").to_string();
    let key = c.json(
        "POST",
        &format!("/_admin/users/{user_id}/access-keys"),
        json!({}),
    );
    key.expect_ok();
    let k = key.json();
    (
        user_id,
        Key {
            arn,
            ak: k["access_key_id"].as_str().unwrap().to_string(),
            sk: k["secret_access_key"].as_str().unwrap().to_string(),
        },
    )
}

/// A request with no credential at all; a body is sent as JSON.
fn unsigned(c: &Cluster, method: &str, path: &str, body: &[u8]) -> Response {
    let client = reqwest::blocking::Client::new();
    let mut req = client.request(
        method.parse().expect("method"),
        format!("{}{path}", c.endpoint),
    );
    if !body.is_empty() {
        req = req
            .header("Content-Type", "application/json")
            .body(body.to_vec());
    }
    Response::from(req.send().expect("request"))
}

/// Send `body` as JSON, signed with this key.
fn json_as(c: &Cluster, method: &str, path: &str, body: &Value, ak: &str, sk: &str) -> Response {
    c.request_as(method, path, body.to_string().as_bytes(), ak, sk)
}

/// A warehouse created by `(ak, sk)` through the admin API.
fn create_warehouse(c: &Cluster, name: &str, ak: &str, sk: &str) {
    json_as(
        c,
        "POST",
        "/_admin/warehouses",
        &json!({"name": name}),
        ak,
        sk,
    )
    .expect_ok();
}

/// Namespace `db` and table `db.events` in `warehouse`, made by `(ak, sk)`.
fn create_table(c: &Cluster, warehouse: &str, ak: &str, sk: &str) {
    json_as(
        c,
        "POST",
        &format!("/iceberg/v1/namespaces?warehouse={warehouse}"),
        &json!({"namespace": ["db"]}),
        ak,
        sk,
    )
    .expect_ok();
    json_as(
        c,
        "POST",
        &format!("/iceberg/v1/namespaces/db/tables?warehouse={warehouse}"),
        &json!({"name": "events", "schema": {"type": "struct", "fields": []}}),
        ak,
        sk,
    )
    .expect_ok();
}

/// An Iceberg policy document granting `actions` on everything to `arn`.
fn allow(arn: &str, actions: &[&str]) -> Value {
    json!({"policy": json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"OBIO": [arn]},
            "Action": actions,
            "Resource": ["arn:obio:iceberg:::*"]
        }]
    }).to_string()})
}

/// The operation a vended session token carries: "R" or "RW".
fn vended_operation(config: &Value) -> String {
    let token = config["s3.session-token"].as_str().expect("session token");
    let raw = String::from_utf8(B64.decode(token).expect("token is base64")).unwrap();
    // sts|{user}|{scope}|{operation}|...|{signature}
    raw.split('|').nth(3).expect("operation").to_string()
}

/// No credential, or a credential that fails, is a 401 on every lake API.
/// They used to run the request as `--no-auth` would, with no identity, and
/// the handlers read no identity as "allowed".
#[test]
fn lake_apis_refuse_missing_and_bad_credentials() {
    let c = Cluster::start();
    create_warehouse(&c, "open", &c.access_key, &c.secret_key);

    for path in [
        "/iceberg/v1/config?warehouse=open",
        "/iceberg/v1/namespaces?warehouse=open",
        "/api/2.1/unity-catalog/catalogs",
        "/api/2.1/unity-catalog/me",
    ] {
        let r = unsigned(&c, "GET", path, &[]);
        assert_eq!(
            r.status,
            401,
            "unsigned GET {path}: {} {}",
            r.status,
            r.text()
        );

        let r = c.request_as("GET", path, &[], &c.access_key, "not-the-secret");
        assert_eq!(
            r.status,
            401,
            "badly signed GET {path}: {} {}",
            r.status,
            r.text()
        );

        let r = c.fetch_with_headers(
            "GET",
            &format!("{}{path}", c.endpoint),
            &[("Authorization", "Bearer not-a-token")],
        );
        assert_eq!(
            r.status,
            401,
            "bearer GET {path}: {} {}",
            r.status,
            r.text()
        );
    }

    let r = unsigned(
        &c,
        "POST",
        "/iceberg/v1/namespaces?warehouse=open",
        json!({"namespace": ["sneaky"]}).to_string().as_bytes(),
    );
    assert_eq!(r.status, 401, "unsigned CreateNamespace: {}", r.text());

    // The root key still works, on the warehouse-prefixed paths clients
    // use after /v1/config too: the signature covers the path as sent,
    // not as the gateway rewrites it.
    c.request("GET", "/iceberg/v1/config?warehouse=open", &[])
        .expect(200);
    c.request("GET", "/iceberg/v1/ws/open/namespaces", &[])
        .expect(200);
    let r = c.request_as(
        "GET",
        "/iceberg/v1/ws/open/namespaces",
        &[],
        &c.access_key,
        "wrong",
    );
    assert_eq!(r.status, 401, "badly signed prefixed path: {}", r.text());
    c.request("GET", "/api/2.1/unity-catalog/catalogs", &[])
        .expect(200);
}

/// The Delta Sharing management routes under `/_admin/delta-sharing/` were
/// mounted with no authentication at all; they are gone, and the console's
/// operations live on the authenticated admin API.
#[test]
fn delta_sharing_management_needs_an_administrator() {
    let c = Cluster::start();

    for (method, path, body) in [
        ("GET", "/_admin/delta-sharing/shares", json!({})),
        ("POST", "/_admin/delta-sharing/shares", json!({"name": "s"})),
        (
            "POST",
            "/_admin/delta-sharing/recipients",
            json!({"name": "r", "shares": []}),
        ),
        ("DELETE", "/_admin/delta-sharing/shares/s", json!({})),
    ] {
        let r = unsigned(&c, method, path, body.to_string().as_bytes());
        assert!(
            r.status == 404 || r.status == 401,
            "unsigned {method} {path}: {} {}",
            r.status,
            r.text()
        );
    }

    // The same operations, on the admin API.
    for (method, path, body) in [
        (
            "POST",
            "/_admin/recipients",
            json!({"name": "r", "shares": []}),
        ),
        ("DELETE", "/_admin/shares/s", json!({})),
        ("GET", "/_admin/shares/s/tables", json!({})),
        (
            "POST",
            "/_admin/shares/s/tables",
            json!({"schema": "x", "name": "t", "table_type": "delta", "bucket": "b"}),
        ),
    ] {
        let r = unsigned(&c, method, path, body.to_string().as_bytes());
        assert_eq!(r.status, 401, "unsigned {method} {path}: {}", r.text());
    }

    // An administrator manages a share end to end.
    c.request("PUT", "/lake-data", &[]).expect_ok();
    c.json("POST", "/_admin/shares", json!({"name": "s"}))
        .expect_ok();
    c.json(
        "POST",
        "/_admin/shares/s/tables",
        json!({"schema": "sales", "name": "events", "table_type": "delta",
               "bucket": "lake-data", "path": "events/"}),
    )
    .expect_ok();
    // A share serves Delta tables only: an Iceberg one, which it would
    // serve as files no client can read, is refused.
    for table_type in ["iceberg", "uniform", ""] {
        let r = c.json(
            "POST",
            "/_admin/shares/s/tables",
            json!({"schema": "sales", "name": "ice", "table_type": table_type,
                   "warehouse": "w", "namespace": "db"}),
        );
        assert_eq!(r.status, 400, "{table_type:?}: {}", r.text());
        assert!(r.text().contains("Iceberg table"), "{}", r.text());
    }
    let tables = c.request("GET", "/_admin/shares/s/tables", &[]);
    tables.expect(200);
    assert_eq!(tables.json()["tables"].as_array().map(Vec::len), Some(1));
    assert_eq!(tables.json()["tables"][0]["name"], "events");
    let recipient = c.json(
        "POST",
        "/_admin/recipients",
        json!({"name": "r", "shares": ["s"]}),
    );
    recipient.expect_ok();
    assert!(recipient.json()["bearer_token"].as_str().is_some());
    c.request(
        "DELETE",
        "/_admin/shares/s/schemas/sales/tables/events",
        &[],
    )
    .expect_ok();
    c.request("DELETE", "/_admin/recipients/r", &[]).expect_ok();
    c.request("DELETE", "/_admin/shares/s", &[]).expect_ok();
}

/// A tenant admin shares only its own tenant's data, and hands out
/// recipients only for its own shares.
#[test]
fn a_tenant_admin_shares_only_its_own_data() {
    let c = Cluster::start();
    let acme = provision_tenant_admin(&c, "acme");
    let globex = provision_tenant_admin(&c, "globex");
    json_as(
        &c,
        "POST",
        "/_admin/buckets",
        &json!({"name": "acme-lake"}),
        &acme.ak,
        &acme.sk,
    )
    .expect_ok();
    json_as(
        &c,
        "POST",
        "/_admin/buckets",
        &json!({"name": "globex-lake"}),
        &globex.ak,
        &globex.sk,
    )
    .expect_ok();
    json_as(
        &c,
        "POST",
        "/_admin/shares",
        &json!({"name": "acme-share"}),
        &acme.ak,
        &acme.sk,
    )
    .expect_ok();
    json_as(
        &c,
        "POST",
        "/_admin/shares",
        &json!({"name": "globex-share"}),
        &globex.ak,
        &globex.sk,
    )
    .expect_ok();

    let table = |bucket: &str| json!({"schema": "s", "name": bucket, "table_type": "delta", "bucket": bucket, "path": "t/"});

    // Its own bucket, into its own share.
    json_as(
        &c,
        "POST",
        "/_admin/shares/acme-share/tables",
        &table("acme-lake"),
        &acme.ak,
        &acme.sk,
    )
    .expect_ok();

    // Another tenant's bucket, into its own share.
    let r = json_as(
        &c,
        "POST",
        "/_admin/shares/acme-share/tables",
        &table("globex-lake"),
        &acme.ak,
        &acme.sk,
    );
    assert_eq!(r.status, 403, "acme shared globex's bucket: {}", r.text());

    // Anything, into another tenant's share.
    let r = json_as(
        &c,
        "POST",
        "/_admin/shares/globex-share/tables",
        &table("acme-lake"),
        &acme.ak,
        &acme.sk,
    );
    assert_eq!(r.status, 403, "acme added to globex's share: {}", r.text());
    let r = c.request_as(
        "DELETE",
        "/_admin/shares/globex-share",
        &[],
        &acme.ak,
        &acme.sk,
    );
    assert_eq!(r.status, 403, "acme dropped globex's share: {}", r.text());

    // A recipient for another tenant's share.
    let r = json_as(
        &c,
        "POST",
        "/_admin/recipients",
        &json!({"name": "spy", "shares": ["globex-share"]}),
        &acme.ak,
        &acme.sk,
    );
    assert_eq!(
        r.status,
        403,
        "acme made a recipient of globex's share: {}",
        r.text()
    );

    // The system admin may share across tenants, as documented.
    c.json(
        "POST",
        "/_admin/shares/acme-share/tables",
        table("globex-lake"),
    )
    .expect_ok();
}

/// The warehouse routes on the Iceberg API took no credential at all: anyone
/// could create a warehouse or delete one together with its bucket. The
/// admin API's `/_admin/warehouses` is the one way to manage them.
#[test]
fn warehouses_are_managed_only_through_the_admin_api() {
    let c = Cluster::start();
    create_warehouse(&c, "kept", &c.access_key, &c.secret_key);

    let r = unsigned(
        &c,
        "POST",
        "/iceberg/v1/warehouses",
        json!({"name": "planted"}).to_string().as_bytes(),
    );
    assert!(
        r.status == 401 || r.status == 404,
        "unsigned create: {} {}",
        r.status,
        r.text()
    );
    let r = unsigned(&c, "DELETE", "/iceberg/v1/warehouses/kept", &[]);
    assert!(
        r.status == 401 || r.status == 404,
        "unsigned delete: {} {}",
        r.status,
        r.text()
    );
    let r = unsigned(&c, "GET", "/iceberg/v1/warehouses", &[]);
    assert!(
        r.status == 401 || r.status == 404,
        "unsigned list: {} {}",
        r.status,
        r.text()
    );

    let listed = c.request("GET", "/_admin/warehouses", &[]);
    listed.expect(200);
    let names: Vec<String> = listed.json()["warehouses"]
        .as_array()
        .expect("warehouses")
        .iter()
        .filter_map(|w| w["name"].as_str().map(String::from))
        .collect();
    assert!(
        names.contains(&"kept".to_string()),
        "warehouse deleted: {names:?}"
    );
    assert!(
        !names.contains(&"planted".to_string()),
        "warehouse planted: {names:?}"
    );
    c.request("HEAD", "/iceberg-kept", &[]).expect(200);
}

/// A warehouse whose bucket holds data is not deleted: deleting it would
/// drop the bucket's record and strand every object in it.
#[test]
fn a_warehouse_holding_data_is_not_deleted() {
    let c = Cluster::start();
    create_warehouse(&c, "full", &c.access_key, &c.secret_key);
    c.request(
        "PUT",
        "/iceberg-full/db/events/data/part-0.parquet",
        b"rows",
    )
    .expect_ok();

    let r = c.request("DELETE", "/_admin/warehouses/full", &[]);
    assert!(
        r.status == 409 || r.status == 400,
        "a warehouse with data was deleted: {} {}",
        r.status,
        r.text()
    );
    c.request("HEAD", "/iceberg-full", &[]).expect(200);
    let got = c.request("GET", "/iceberg-full/db/events/data/part-0.parquet", &[]);
    got.expect(200);
    assert_eq!(got.bytes, b"rows");

    // Emptied, it goes.
    c.request("DELETE", "/iceberg-full/db/events/data/part-0.parquet", &[])
        .expect_ok();
    c.request("DELETE", "/_admin/warehouses/full", &[])
        .expect_ok();
}

/// A tenant's callers see and use their own tenant's warehouses and
/// catalogs only.
#[test]
fn a_tenant_sees_only_its_own_warehouses_and_catalogs() {
    let c = Cluster::start();
    let north = provision_tenant_admin(&c, "north");
    let south = provision_tenant_admin(&c, "south");
    create_warehouse(&c, "north-wh", &north.ak, &north.sk);
    create_table(&c, "north-wh", &north.ak, &north.sk);

    for path in [
        "/iceberg/v1/config?warehouse=north-wh",
        "/iceberg/v1/namespaces?warehouse=north-wh",
        "/iceberg/v1/namespaces/db/tables/events?warehouse=north-wh",
    ] {
        let r = c.request_as("GET", path, &[], &south.ak, &south.sk);
        assert!(
            r.status == 404 || r.status == 403 || r.status == 400,
            "south reached north's warehouse at {path}: {} {}",
            r.status,
            r.text()
        );
    }
    let r = json_as(
        &c,
        "POST",
        "/iceberg/v1/namespaces?warehouse=north-wh",
        &json!({"namespace": ["planted"]}),
        &south.ak,
        &south.sk,
    );
    assert!(
        r.status >= 400,
        "south created a namespace in north: {}",
        r.text()
    );

    // Unity: a tenant admin's catalog belongs to its tenant.
    json_as(
        &c,
        "POST",
        "/api/2.1/unity-catalog/catalogs",
        &json!({"name": "northcat"}),
        &north.ak,
        &north.sk,
    )
    .expect_ok();
    let mine = c.request_as(
        "GET",
        "/api/2.1/unity-catalog/catalogs",
        &[],
        &north.ak,
        &north.sk,
    );
    mine.expect(200);
    assert!(
        mine.text().contains("northcat"),
        "north lost its catalog: {}",
        mine.text()
    );
    let theirs = c.request_as(
        "GET",
        "/api/2.1/unity-catalog/catalogs",
        &[],
        &south.ak,
        &south.sk,
    );
    theirs.expect(200);
    assert!(
        !theirs.text().contains("northcat"),
        "south listed north's catalog: {}",
        theirs.text()
    );
    let r = c.request_as(
        "GET",
        "/api/2.1/unity-catalog/catalogs/northcat",
        &[],
        &south.ak,
        &south.sk,
    );
    assert!(
        r.status == 404 || r.status == 403,
        "south read north's catalog: {} {}",
        r.status,
        r.text()
    );
}

/// `LoadTable`: no grant, or a Deny, is a 403 with no credentials; a reader
/// is vended read-only credentials, a writer read-write ones.
#[test]
fn load_table_is_authorized_and_vends_what_the_caller_may_do() {
    let c = Cluster::start();
    let admin = provision_tenant_admin(&c, "lake");
    let (_, reader) = provision_user(&c, "lake", "reader");
    let (_, writer) = provision_user(&c, "lake", "writer");
    create_warehouse(&c, "lakewh", &admin.ak, &admin.sk);
    create_table(&c, "lakewh", &admin.ak, &admin.sk);
    let load = "/iceberg/v1/namespaces/db/tables/events?warehouse=lakewh";

    // No policy grants the reader anything yet.
    let r = c.request_as("GET", load, &[], &reader.ak, &reader.sk);
    assert_eq!(r.status, 403, "LoadTable with no grant: {}", r.text());
    assert!(
        !r.text().contains("s3.access-key-id"),
        "credentials vended on a 403"
    );

    // The tenant admin grants: the reader may load, the writer may also commit.
    json_as(
        &c,
        "PUT",
        "/iceberg/v1/namespaces/db/policy?warehouse=lakewh",
        &json!({"policy": json!({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"OBIO": [reader.arn]},
                 "Action": ["iceberg:LoadTable"], "Resource": ["arn:obio:iceberg:::db/*"]},
                {"Effect": "Allow", "Principal": {"OBIO": [writer.arn]},
                 "Action": ["iceberg:LoadTable", "iceberg:UpdateTable"],
                 "Resource": ["arn:obio:iceberg:::db/*"]}
            ]
        }).to_string()}),
        &admin.ak,
        &admin.sk,
    )
    .expect_ok();

    let r = c.request_as("GET", load, &[], &reader.ak, &reader.sk);
    r.expect(200);
    let config = r.json()["config"].clone();
    assert_eq!(vended_operation(&config), "R", "reader got {config}");
    // And the read-only session can't write into the table.
    let creds = (
        config["s3.access-key-id"].as_str().unwrap(),
        config["s3.secret-access-key"].as_str().unwrap(),
        config["s3.session-token"].as_str().unwrap(),
    );
    let w = c.request_as_session(
        "PUT",
        "/iceberg-lakewh/db/events/data/x.parquet",
        b"x",
        creds,
    );
    assert_eq!(w.status, 403, "a read-only session wrote: {}", w.text());

    let r = c.request_as("GET", load, &[], &writer.ak, &writer.sk);
    r.expect(200);
    assert_eq!(vended_operation(&r.json()["config"]), "RW");

    // A table policy that denies the writer wins over the namespace's Allow.
    json_as(
        &c,
        "PUT",
        "/iceberg/v1/namespaces/db/tables/events/policy?warehouse=lakewh",
        &json!({"policy": json!({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Deny", "Principal": {"OBIO": [writer.arn]},
                           "Action": ["iceberg:LoadTable"],
                           "Resource": ["arn:obio:iceberg:::db/events"]}]
        }).to_string()}),
        &admin.ak,
        &admin.sk,
    )
    .expect_ok();
    let r = c.request_as("GET", load, &[], &writer.ak, &writer.sk);
    assert_eq!(r.status, 403, "LoadTable denied by policy: {}", r.text());
    assert!(
        !r.text().contains("s3.access-key-id"),
        "credentials vended on a deny"
    );

    // Policies are an administrator's: the reader can't grant itself more.
    let r = json_as(
        &c,
        "PUT",
        "/iceberg/v1/namespaces/db/policy?warehouse=lakewh",
        &allow(&reader.arn, &["iceberg:*"]),
        &reader.ak,
        &reader.sk,
    );
    assert_eq!(
        r.status,
        403,
        "a reader set a namespace policy: {}",
        r.text()
    );
}

/// A table's location stays inside its warehouse, where its vended
/// credentials are scoped: a table pointed at another bucket would get
/// credentials for that bucket.
#[test]
fn table_locations_stay_inside_their_warehouse() {
    let c = Cluster::start();
    let admin = provision_tenant_admin(&c, "loc");
    create_warehouse(&c, "locwh", &admin.ak, &admin.sk);
    json_as(
        &c,
        "POST",
        "/_admin/buckets",
        &json!({"name": "loc-private"}),
        &admin.ak,
        &admin.sk,
    )
    .expect_ok();
    json_as(
        &c,
        "POST",
        "/iceberg/v1/namespaces?warehouse=locwh",
        &json!({"namespace": ["db"]}),
        &admin.ak,
        &admin.sk,
    )
    .expect_ok();

    for location in [
        "s3://loc-private/stolen",
        "s3://iceberg-locwh-other/t",
        "s3://iceberg-locwhx/t",
    ] {
        let r = json_as(
            &c,
            "POST",
            "/iceberg/v1/namespaces/db/tables?warehouse=locwh",
            &json!({"name": "t", "location": location, "schema": {"type": "struct", "fields": []}}),
            &admin.ak,
            &admin.sk,
        );
        assert_eq!(r.status, 400, "table created at {location}: {}", r.text());
    }

    // Inside the warehouse is fine.
    json_as(
        &c,
        "POST",
        "/iceberg/v1/namespaces/db/tables?warehouse=locwh",
        &json!({"name": "t", "location": "s3://iceberg-locwh/custom/t",
                "schema": {"type": "struct", "fields": []}}),
        &admin.ak,
        &admin.sk,
    )
    .expect_ok();

    // And a commit can't move it out.
    let r = json_as(
        &c,
        "POST",
        "/iceberg/v1/namespaces/db/tables/t?warehouse=locwh",
        &json!({"requirements": [], "updates": [
            {"action": "set-location", "location": "s3://loc-private/moved"}
        ]}),
        &admin.ak,
        &admin.sk,
    );
    assert_eq!(r.status, 400, "a commit moved the table out: {}", r.text());
}

/// Unity's external tables and volumes stay inside their catalog's
/// storage, where their vended credentials are scoped, and those credentials
/// stay in the catalog's tenant. An external table over another tenant's
/// bucket used to get credentials that a grant there to the vending user
/// honoured.
#[test]
fn unity_storage_stays_in_its_catalog_and_its_tenant() {
    let c = Cluster::start();
    let acme = provision_tenant_admin(&c, "acme");
    let globex = provision_tenant_admin(&c, "globex");

    // Globex's bucket, with a grant naming acme's admin: across the tenant
    // boundary, which no grant opens.
    c.request_as("PUT", "/globex-secret", &[], &globex.ak, &globex.sk)
        .expect_ok();
    c.request_as(
        "PUT",
        "/globex-secret/s.txt",
        b"secret",
        &globex.ak,
        &globex.sk,
    )
    .expect_ok();
    let policy = json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"OBIO": [acme.arn]},
                       "Action": ["s3:GetObject"],
                       "Resource": ["arn:obio:s3:::globex-secret/*"]}]
    });
    c.request_as(
        "PUT",
        "/globex-secret?policy",
        policy.to_string().as_bytes(),
        &globex.ak,
        &globex.sk,
    )
    .expect_ok();
    let r = c.request_as("GET", "/globex-secret/s.txt", &[], &acme.ak, &acme.sk);
    assert_eq!(
        r.status,
        403,
        "acme read globex's bucket directly: {}",
        r.text()
    );
    // And a bucket of acme's own, outside the catalog.
    c.request_as("PUT", "/acme-other", &[], &acme.ak, &acme.sk)
        .expect_ok();

    let uc = "/api/2.1/unity-catalog";
    json_as(
        &c,
        "POST",
        &format!("{uc}/catalogs"),
        &json!({"name": "acat"}),
        &acme.ak,
        &acme.sk,
    )
    .expect_ok();
    json_as(
        &c,
        "POST",
        &format!("{uc}/schemas"),
        &json!({"name": "s", "catalog_name": "acat"}),
        &acme.ak,
        &acme.sk,
    )
    .expect_ok();

    // Outside the catalog's bucket: refused, whoever's bucket it is.
    for location in [
        "s3://globex-secret/",
        "s3://acme-other/t/",
        "s3://unity-acat/../globex-secret/",
    ] {
        let r = json_as(
            &c,
            "POST",
            &format!("{uc}/tables"),
            &json!({"name": "t", "catalog_name": "acat", "schema_name": "s",
                    "table_type": "EXTERNAL", "storage_location": location}),
            &acme.ak,
            &acme.sk,
        );
        assert_eq!(r.status, 400, "external table at {location}: {}", r.text());
        let r = json_as(
            &c,
            "POST",
            &format!("{uc}/volumes"),
            &json!({"name": "v", "catalog_name": "acat", "schema_name": "s",
                    "volume_type": "EXTERNAL", "storage_location": location}),
            &acme.ak,
            &acme.sk,
        );
        assert_eq!(r.status, 400, "external volume at {location}: {}", r.text());
    }

    // Inside it, fine; and the session vended for it gets nothing in
    // globex's bucket.
    let table = json_as(
        &c,
        "POST",
        &format!("{uc}/tables"),
        &json!({"name": "t", "catalog_name": "acat", "schema_name": "s",
                "table_type": "EXTERNAL", "storage_location": "s3://unity-acat/ext/t/"}),
        &acme.ak,
        &acme.sk,
    );
    table.expect_ok();
    let table_id = table.json()["table_id"].as_str().unwrap().to_string();
    let vended = json_as(
        &c,
        "POST",
        &format!("{uc}/temporary-table-credentials"),
        &json!({"table_id": table_id, "operation": "READ"}),
        &acme.ak,
        &acme.sk,
    );
    vended.expect(200);
    let v = vended.json();
    let creds = &v["aws_temp_credentials"];
    let session = (
        creds["access_key_id"].as_str().unwrap(),
        creds["secret_access_key"].as_str().unwrap(),
        creds["session_token"].as_str().unwrap(),
    );
    let r = c.request_as_session("GET", "/globex-secret/s.txt", &[], session);
    assert_eq!(
        r.status,
        403,
        "a session vended in acme read globex's bucket: {}",
        r.text()
    );
}
