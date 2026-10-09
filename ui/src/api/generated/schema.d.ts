// Types of the Tenko DDI API, derived from the OpenAPI document (docs/api/openapi.json).
// Regenerate with `npm run api:types`; do not edit.

export interface paths {
    "/api/v1/addresses": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List addresses */
        get: operations["list_addresses"];
        put?: never;
        /** Create an address */
        post: operations["create_address"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/addresses/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several addresses in one request */
        post: operations["bulk_addresses"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/addresses/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one address */
        get: operations["get_address"];
        put?: never;
        post?: never;
        /** Delete an address */
        delete: operations["delete_address"];
        options?: never;
        head?: never;
        /** Update an address */
        patch: operations["update_address"];
        trace?: never;
    };
    "/api/v1/addresses/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one address */
        get: operations["get_address_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/addresses/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted address */
        post: operations["restore_address"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/audit": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List audit records
         * @description Newest first unless `order=asc`. Filters combine with AND. `principal` is a subject such as `user:<uuid>`, `token:<uuid>` or `system:api`; `action` is exact or, when it ends with a dot, a namespace prefix such as `ipam.prefix.`; `object` is a kind such as `prefix`, or `kind:uuid`. Records are read in sequence order and a request examines at most 20,000 of them: when that runs out first, the page holds the matches found so far, possibly none, and `next_cursor` continues the scan. `next_cursor` is null only when the scan reached the end of the log.
         */
        get: operations["list_audit"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/audit/verify": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Verify the hash chain of the audit log
         * @description Walks the whole chain from record 1 and reports the first record that does not verify: a gap in the sequence, a record that does not link to its predecessor, or one whose hash no longer matches its content. `checked` counts the records that did verify, `head` is the last of them and `store_head` the newest record of the log. Reads the whole log; on a long log it takes a while.
         */
        get: operations["verify_audit"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/audit/{seq}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one audit record */
        get: operations["get_audit_record"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/login/password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Log in with a user name and password */
        post: operations["login_password"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/login/recovery": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Complete a login with a recovery code */
        post: operations["login_recovery"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/login/totp": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Complete a login with a TOTP code */
        post: operations["login_totp"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/logout": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** End the current session */
        post: operations["logout"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/password": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change the password of the current user */
        post: operations["change_password"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/password/check": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Check a candidate password against the live policy and breach lists */
        post: operations["check_password"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/recovery-codes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Generate a new set of recovery codes, shown once */
        post: operations["regenerate_recovery_codes"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/session": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Describe the current session: principal, roles, strength and expiry */
        get: operations["get_session"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/sessions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the sessions of the current user */
        get: operations["list_sessions"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/sessions/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Revoke one session of the current user */
        delete: operations["revoke_session"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/tokens": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the personal API tokens of the current user */
        get: operations["list_tokens"];
        put?: never;
        /** Create a personal API token, shown once */
        post: operations["create_token"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/tokens/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Revoke one personal API token */
        delete: operations["revoke_token"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/totp": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove the TOTP factor of the current user */
        delete: operations["remove_totp"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/totp/enroll/finish": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Finish TOTP enrolment with a first code */
        post: operations["totp_enroll_finish"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/totp/enroll/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Start TOTP enrolment and return the provisioning data */
        post: operations["totp_enroll_start"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/webauthn/credentials": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the WebAuthn credentials of the current user */
        get: operations["list_webauthn_credentials"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/webauthn/credentials/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Delete one WebAuthn credential of the current user */
        delete: operations["delete_webauthn_credential"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/webauthn/login/finish": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Finish a WebAuthn login with the signed assertion */
        post: operations["webauthn_login_finish"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/webauthn/login/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Start a WebAuthn login and return the challenge */
        post: operations["webauthn_login_start"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/webauthn/register/finish": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Finish registering a WebAuthn credential with the attestation */
        post: operations["webauthn_register_finish"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/auth/webauthn/register/start": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Start registering a WebAuthn credential and return the challenge */
        post: operations["webauthn_register_start"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/custom-fields": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List custom field definitions */
        get: operations["list_custom_fields"];
        put?: never;
        /** Create a custom field definition */
        post: operations["create_custom_field"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/custom-fields/{key}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one custom field definition */
        get: operations["get_custom_field"];
        put?: never;
        post?: never;
        /** Delete a custom field definition */
        delete: operations["delete_custom_field"];
        options?: never;
        head?: never;
        /** Update a custom field definition */
        patch: operations["update_custom_field"];
        trace?: never;
    };
    "/api/v1/events": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Subscribe to server-sent events
         * @description A `text/event-stream`. Data events have the topic as event name, the store revision as id and an `EventData` document as data. `reset` (data `ResetData`) tells the client to reload at the given revision; `shutdown` ends the stream. A `: keep-alive` comment arrives every 15 seconds.
         */
        get: operations["events"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exports/addresses.csv": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Export addresses as CSV */
        get: operations["export_addresses_csv"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exports/hosts.csv": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Export hosts as CSV */
        get: operations["export_hosts_csv"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/exports/prefixes.csv": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Export prefixes as CSV */
        get: operations["export_prefixes_csv"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/health": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Liveness probe */
        get: operations["health"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/health/ready": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Readiness probe */
        get: operations["ready"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/hosts": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List hosts */
        get: operations["list_hosts"];
        put?: never;
        /** Create a host */
        post: operations["create_host"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/hosts/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several hosts in one request */
        post: operations["bulk_hosts"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/hosts/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one host */
        get: operations["get_host"];
        put?: never;
        post?: never;
        /** Delete a host */
        delete: operations["delete_host"];
        options?: never;
        head?: never;
        /** Update a host */
        patch: operations["update_host"];
        trace?: never;
    };
    "/api/v1/hosts/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one host */
        get: operations["get_host_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/hosts/{id}/interfaces": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the interfaces of a host */
        get: operations["list_host_interfaces"];
        put?: never;
        /** Add an interface to a host */
        post: operations["create_interface"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/hosts/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted host */
        post: operations["restore_host"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/imports": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Upload a file to import */
        post: operations["create_import"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/imports/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get an upload with its sheets, columns and suggested mapping */
        get: operations["get_import"];
        put?: never;
        post?: never;
        /** Discard an upload */
        delete: operations["delete_import"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/imports/{id}/apply": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Apply an import as a job */
        post: operations["apply_import"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/imports/{id}/mapping": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Set the column mapping, transforms and conflict policy */
        put: operations["set_import_mapping"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/imports/{id}/preview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Preview the changes of an import: summary, rows and loss report */
        get: operations["preview_import"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/interfaces/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several interfaces in one request */
        post: operations["bulk_interfaces"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/interfaces/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one interface */
        get: operations["get_interface"];
        put?: never;
        post?: never;
        /** Delete an interface */
        delete: operations["delete_interface"];
        options?: never;
        head?: never;
        /** Update an interface */
        patch: operations["update_interface"];
        trace?: never;
    };
    "/api/v1/interfaces/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one interface */
        get: operations["get_interface_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/interfaces/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted interface */
        post: operations["restore_interface"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/jobs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List jobs
         * @description Filter by state, kind or target object. The answer carries the revision it was read at,
         *     so that a client can follow up with the event stream from there, and a cursor for the
         *     next page while there is one. Without permission to read jobs the list is empty.
         */
        get: operations["list_jobs"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/jobs/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get one job with its steps
         * @description `at_least=<revision>` waits until the store has reached the revision, so that a client
         *     reads its own writes.
         */
        get: operations["get_job"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/jobs/{id}/cancel": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Cancel a job
         * @description A queued job is cancelled at once. A running or waiting job is marked: the runner stops
         *     it at the next step boundary, rolls back what ran and ends it as `cancelled`; the answer
         *     shows `cancel_requested: true` until then. Cancelling twice is harmless. A job that is
         *     rolling back or finished cannot be cancelled.
         */
        post: operations["cancel_job"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/jobs/{id}/steps/{index}/complete": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Complete a manual step of a job
         * @description The step must be waiting for a person. The optional note is kept in the transition log
         *     and the audit record. The job continues with its next step. The body may be empty.
         */
        post: operations["complete_job_step"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/metrics": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Metrics in the OpenMetrics text format; needs a token with the metrics scope */
        get: operations["metrics"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/openapi.json": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the OpenAPI document of this API */
        get: operations["openapi_document"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List prefixes
         * @description Filter by `status`, `vrf`, `within` (prefixes inside a network), `site`, `role`, `tag`
         *     (all tags must match) and `q` (text over the network, tags and description); sort with
         *     `sort=-updated,cidr`; `deleted=only` shows the restore view. The answer carries the
         *     revision it was read at, and a cursor for the next page while there is one.
         */
        get: operations["list_prefixes"];
        put?: never;
        /**
         * Create a prefix
         * @description Without `vrf` the prefix goes into the VRF `default`, which is created on first use.
         *     Without `role` the prefix becomes a supernet when it contains existing prefixes, else a
         *     network. Prefixes nest only inside supernets: a duplicate, a prefix inside a network and
         *     a network around other prefixes are refused (`ipam.prefix.overlap`, IPAM-23). An IPv6
         *     prefix off a nibble boundary (IPAM-06) is refused with `ipam.plan.unacknowledged` until
         *     the request acknowledges the warning with `?acknowledge=ipam.prefix.nibble_boundary`;
         *     `dry_run=true` shows the warning and the plan instead.
         */
        post: operations["create_prefix"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several prefixes in one request */
        post: operations["bulk_prefixes"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/tree": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * Get the prefix tree with utilization and alarms
         * @description Every node carries its parent, depth, number of child prefixes, the utilization
         *     (`capacity`, `used`, `reserved`, `free`, `covered` as decimal strings, and `percent`)
         *     and the alarm `level`. `children` counts all direct child prefixes, also those that
         *     `depth` leaves out, so that the UI knows which nodes can be opened. Without `vrf` the tree
         *     of the VRF `default` is shown.
         */
        get: operations["get_prefix_tree"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one prefix */
        get: operations["get_prefix"];
        put?: never;
        post?: never;
        /**
         * Delete a prefix
         * @description A prefix with ranges is refused (409 `ipam.in_use`) unless `cascade=true` deletes them
         *     with it. Its addresses move to the parent prefix; without a parent they block the delete
         *     the same way, and `cascade=true` deletes them instead. Child prefixes stay and belong to
         *     the next prefix up. The answer shows the deleted prefix.
         */
        delete: operations["delete_prefix"];
        options?: never;
        head?: never;
        /**
         * Update a prefix
         * @description The body is a merge patch: an absent member stays, `null` clears an optional member. The
         *     VRF cannot change. Children, addresses and ranges must still fit a new network
         *     (`ipam.prefix.resize_orphans`), and status changes follow IPAM-05
         *     (`ipam.status.transition`). Send `If-Match` with the `ETag` that was read to refuse a
         *     change over a newer one (412 `ipam.revision_mismatch`).
         */
        patch: operations["update_prefix"];
        trace?: never;
    };
    "/api/v1/prefixes/{id}/addresses": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List the addresses of a prefix, optionally with the free ones
         * @description Each item is `{ "type": "address", "data": <address> }` or
         *     `{ "type": "free", "data": { first, last, size } }`; `size` is a decimal string. The gaps
         *     cover the assignable addresses of a network (IPv4 without network and broadcast address)
         *     and are counted in the page size like addresses. The cursor stays valid across the
         *     boundary between an address and a gap.
         */
        get: operations["list_prefix_addresses"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one prefix */
        get: operations["get_prefix_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/{id}/next-free-address": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Allocate the next free address in a prefix
         * @description The address is the lowest (or, with `policy=highest`, the highest) free address outside
         *     the ranges of the prefix, or inside the given `range`. Consecutive calls give consecutive
         *     addresses. `dry_run=true` shows the candidate in `item` without creating it. The body is
         *     optional.
         */
        post: operations["next_free_address"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/{id}/next-free-prefix": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /**
         * Allocate the next free child prefix of a prefix
         * @description The new prefix has the given `length`. It is the lowest (or, with `policy=highest`, the
         *     highest) block of that length inside the supernet that no other prefix touches. A network
         *     prefix cannot be the parent (`ipam.prefix.overlap`), a length that is not longer than the
         *     parent's or beyond the address size is invalid (`ipam.validation`), and a full parent
         *     answers `ipam.prefix.full`.
         */
        post: operations["next_free_prefix"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/{id}/ranges": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /**
         * List the ranges of a prefix
         * @description Filter by `role`, `status`, `tag` and `q`; sort with `sort=-first`; `deleted=only` shows
         *     deleted ranges.
         */
        get: operations["list_prefix_ranges"];
        put?: never;
        /**
         * Create a range in a prefix
         * @description The range lies inside the prefix (`ipam.range.outside_prefix`), does not overlap another
         *     range of the prefix (`ipam.range.overlap`) and a DHCP pool must not cover the address of
         *     a host with a DHCP reservation (`ipam.range.covers_reservation`). Ranges belong to
         *     network prefixes only (`ipam.range.not_in_network`).
         */
        post: operations["create_range"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/prefixes/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted prefix */
        post: operations["restore_prefix"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several ranges in one request */
        post: operations["bulk_ranges"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one range */
        get: operations["get_range"];
        put?: never;
        post?: never;
        /** Delete a range */
        delete: operations["delete_range"];
        options?: never;
        head?: never;
        /**
         * Update a range
         * @description The body is a merge patch. The prefix of a range cannot change. The same rules as for a
         *     new range apply to the changed one. Send `If-Match` with the `ETag` that was read to
         *     refuse a change over a newer one (412 `ipam.revision_mismatch`).
         */
        patch: operations["update_range"];
        trace?: never;
    };
    "/api/v1/ranges/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one range */
        get: operations["get_range_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/ranges/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted range */
        post: operations["restore_range"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/roles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the available roles */
        get: operations["list_roles"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/search": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Search prefixes, addresses and hosts */
        get: operations["search"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/settings/security": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the security profile, toggles and deviations */
        get: operations["get_security_settings"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        /** Change the security profile, toggles or deviations */
        patch: operations["update_security_settings"];
        trace?: never;
    };
    "/api/v1/setup": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Report whether first-run setup is still open */
        get: operations["get_setup"];
        put?: never;
        /** Complete first-run setup and start a session */
        post: operations["complete_setup"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sites": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List sites */
        get: operations["list_sites"];
        put?: never;
        /** Create a site */
        post: operations["create_site"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sites/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several sites in one request */
        post: operations["bulk_sites"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sites/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one site */
        get: operations["get_site"];
        put?: never;
        post?: never;
        /** Delete a site */
        delete: operations["delete_site"];
        options?: never;
        head?: never;
        /** Update a site */
        patch: operations["update_site"];
        trace?: never;
    };
    "/api/v1/sites/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one site */
        get: operations["get_site_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/sites/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted site */
        post: operations["restore_site"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/break-glass": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Configure break-glass access; needs fresh authentication */
        put: operations["set_break_glass"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/status": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the status of the installation: version, store, certificates and warnings */
        get: operations["system_status"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/tags": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the tags in use */
        get: operations["list_tags"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/tenants": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List tenants */
        get: operations["list_tenants"];
        put?: never;
        /** Create a tenant */
        post: operations["create_tenant"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/tenants/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several tenants in one request */
        post: operations["bulk_tenants"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/tenants/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one tenant */
        get: operations["get_tenant"];
        put?: never;
        post?: never;
        /** Delete a tenant */
        delete: operations["delete_tenant"];
        options?: never;
        head?: never;
        /** Update a tenant */
        patch: operations["update_tenant"];
        trace?: never;
    };
    "/api/v1/tenants/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one tenant */
        get: operations["get_tenant_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/tenants/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted tenant */
        post: operations["restore_tenant"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/users": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List users */
        get: operations["list_users"];
        put?: never;
        /** Create a user */
        post: operations["create_user"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/users/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one user */
        get: operations["get_user"];
        put?: never;
        post?: never;
        /** Delete a user */
        delete: operations["delete_user"];
        options?: never;
        head?: never;
        /** Update a user */
        patch: operations["update_user"];
        trace?: never;
    };
    "/api/v1/users/{id}/roles": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Replace the roles of a user */
        put: operations["set_user_roles"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/users/{id}/sessions": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Revoke every session of a user */
        delete: operations["revoke_user_sessions"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/users/{id}/unlock": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Lift the lockout of a user */
        post: operations["unlock_user"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vlans": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List VLANs */
        get: operations["list_vlans"];
        put?: never;
        /** Create a VLAN */
        post: operations["create_vlan"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vlans/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several vlans in one request */
        post: operations["bulk_vlans"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vlans/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one VLAN */
        get: operations["get_vlan"];
        put?: never;
        post?: never;
        /** Delete a VLAN */
        delete: operations["delete_vlan"];
        options?: never;
        head?: never;
        /** Update a VLAN */
        patch: operations["update_vlan"];
        trace?: never;
    };
    "/api/v1/vlans/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one VLAN */
        get: operations["get_vlan_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vlans/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted VLAN */
        post: operations["restore_vlan"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vrfs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List VRFs */
        get: operations["list_vrfs"];
        put?: never;
        /** Create a VRF */
        post: operations["create_vrf"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vrfs/bulk": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Change several vrfs in one request */
        post: operations["bulk_vrfs"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vrfs/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one VRF */
        get: operations["get_vrf"];
        put?: never;
        post?: never;
        /** Delete a VRF */
        delete: operations["delete_vrf"];
        options?: never;
        head?: never;
        /** Update a VRF */
        patch: operations["update_vrf"];
        trace?: never;
    };
    "/api/v1/vrfs/{id}/history": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the change history of one VRF */
        get: operations["get_vrf_history"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/vrfs/{id}/restore": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Restore one deleted VRF */
        post: operations["restore_vrf"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
}
export type webhooks = Record<string, never>;
export interface components {
    schemas: {
        /** @description A persisted lock (IAM-05, TGL-07). */
        AccountLock: {
            /** @description When the lock started. */
            since: components["schemas"]["Timestamp"];
            /** @description When it lifts by itself. */
            until: components["schemas"]["Timestamp"];
            /** @description Whether only an administrator should lift it early (Hardened). */
            until_unlock: boolean;
        };
        /** @description An IP address object. */
        Address: {
            dns_name?: components["schemas"]["Fqdn"] | null;
            /** @description Identifier. */
            id: components["schemas"]["AddressId"];
            interface?: components["schemas"]["InterfaceId"] | null;
            /**
             * @description The address.
             * @example 192.0.2.10
             */
            ip: string;
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description The most specific prefix containing the address. */
            prefix: components["schemas"]["PrefixId"];
            /** @description Lifecycle status. */
            status: components["schemas"]["Status"];
            /** @description The VRF. */
            vrf: components["schemas"]["VrfId"];
        };
        /** Format: uuid */
        AddressId: string;
        /** @description A new address. */
        AddressInput: {
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            dns_name?: components["schemas"]["Fqdn"] | null;
            id?: components["schemas"]["AddressId"] | null;
            interface?: components["schemas"]["InterfaceId"] | null;
            /**
             * @description The address; its most specific prefix in the VRF becomes its prefix.
             * @example 192.0.2.10
             */
            ip: string;
            status?: components["schemas"]["Status"] | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
            vrf?: components["schemas"]["VrfId"] | null;
        };
        /** @description Changes to an address. The VRF cannot change. */
        AddressPatch: {
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New DNS name; `null` clears it. */
            dns_name?: string | null;
            /** @description New interface; `null` unassigns the address. */
            interface?: string | null;
            /** @description New address (renumber); the prefix is recomputed. */
            ip?: string | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /**
         * @description Alarm level of a prefix.
         * @enum {string}
         */
        AlarmLevel: "normal" | "warning" | "critical";
        /**
         * @description Which end of a prefix next-free allocation starts from (IPAM-07).
         * @enum {string}
         */
        AllocPolicy: "lowest" | "highest";
        /** @description Allocates the next free address of a prefix (IPAM-07) and creates it. */
        AllocateAddress: {
            /** @description Custom field values of the new address. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Description of the new address. */
            description?: string | null;
            dns_name?: components["schemas"]["Fqdn"] | null;
            /**
             * @description A candidate from the prefix tree. The plan uses it when it is free in the read
             *     view and searches the view otherwise; callers normally leave it out.
             */
            hint?: string | null;
            id?: components["schemas"]["AddressId"] | null;
            interface?: components["schemas"]["InterfaceId"] | null;
            policy?: components["schemas"]["AllocPolicy"] | null;
            /** @description The prefix to allocate from. */
            prefix: components["schemas"]["PrefixId"];
            range?: components["schemas"]["RangeId"] | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Tags of the new address. */
            tags?: components["schemas"]["Tag"][];
        };
        /** @description Allocates the next free child prefix of a given length (IPAM-07) and creates it. */
        AllocatePrefix: {
            alarm?: components["schemas"]["UtilizationAlarm"] | null;
            /** @description Custom field values of the new prefix. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Description of the new prefix. */
            description?: string | null;
            /** @description A candidate from the prefix tree, verified against the read view. */
            hint?: string | null;
            id?: components["schemas"]["PrefixId"] | null;
            /**
             * Format: int32
             * @description Prefix length of the new prefix.
             */
            length: number;
            /** @description The supernet to allocate from. */
            parent: components["schemas"]["PrefixId"];
            policy?: components["schemas"]["AllocPolicy"] | null;
            role?: components["schemas"]["PrefixRole"] | null;
            site?: components["schemas"]["SiteId"] | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Tags of the new prefix. */
            tags?: components["schemas"]["Tag"][];
            vlan?: components["schemas"]["VlanId"] | null;
        };
        /** Format: uuid */
        ApiTokenId: string;
        /** @description The `response` member of an assertion (`AuthenticatorAssertionResponseJSON`). */
        AssertionResponse: {
            /** @description The authenticator data, base64url. */
            authenticatorData: string;
            /** @description `clientDataJSON`, base64url. */
            clientDataJSON: string;
            /** @description The signature, base64url. */
            signature: string;
            /** @description The user handle, base64url; present for discoverable credentials. */
            userHandle?: string | null;
        };
        /**
         * @description What IPAM may do when a host's intent changes (IPAM-14, ADR 0005).
         * @enum {string}
         */
        AssignmentMode: "static" | "reserved" | "dynamic" | "unmanaged";
        /** @description What the attestation of a credential proved. */
        AttestationKind: {
            /** @enum {string} */
            kind: "none";
        } | {
            /** @enum {string} */
            kind: "self_attestation";
        } | {
            /** @description Whether the chain ends at a configured trust anchor. */
            anchored: boolean;
            /** @description SHA-256 of the attestation certificate, hexadecimal. */
            certificate_sha256: string;
            /** @enum {string} */
            kind: "certificate";
            /** @description The common name of the attestation certificate. */
            subject: string;
        };
        /** @description The `response` member of a registration (`AuthenticatorAttestationResponseJSON`). */
        AttestationResponse: {
            /** @description The CBOR attestation object, base64url. */
            attestationObject: string;
            /** @description `clientDataJSON`, base64url. */
            clientDataJSON: string;
            /** @description Transports reported by the client. */
            transports?: string[];
        };
        /** @description Namespaced audit action */
        AuditAction: string;
        /** @description The first break found in the audit chain. */
        AuditBreak: {
            /**
             * @description Stable code: `sys.audit.gap`, `sys.audit.broken_link`, `sys.audit.bad_hash` or a
             *     codec error.
             */
            code: string;
            /** @description English explanation. */
            detail: string;
            /** @description Sequence number of the record where the chain breaks. */
            seq: components["schemas"]["AuditSeq"];
        };
        /**
         * @description Details of an audited action: field changes and free-form context. Never contains
         *     secrets (a changed secret is recorded as a change without values).
         */
        AuditDetails: {
            /** @description Changed fields. */
            changes?: components["schemas"]["FieldChange"][];
            /** @description Context such as the attempted user name of a failed login. */
            context?: {
                [key: string]: string;
            };
        };
        /** @description An audit entry as the proposer writes it into a batch. */
        AuditDraft: {
            /** @description What was done. */
            action: components["schemas"]["AuditAction"];
            /** @description Diff and context. */
            details?: components["schemas"]["AuditDetails"];
            /** @description The objects concerned. */
            objects?: components["schemas"]["ObjectRef"][];
            /** @description The outcome. */
            outcome: components["schemas"]["AuditOutcome"];
            /** @description The client address. */
            source_ip?: string | null;
        };
        /** @description The outcome of an audited action. */
        AuditOutcome: {
            /** @enum {string} */
            kind: "success";
        } | {
            /** @enum {string} */
            kind: "denied";
        } | {
            /** @description The stable error code. */
            code: string;
            /** @enum {string} */
            kind: "failed";
        };
        /** @description A sealed audit record, stored in `sys.audit` under its sequence number. */
        AuditRecord: {
            /** @description The proposer's time of the batch. */
            at: components["schemas"]["Timestamp"];
            /** @description The audited action. */
            draft: components["schemas"]["AuditDraft"];
            /** @description SHA-256 over the canonical CBOR of every field above. */
            hash: components["schemas"]["Digest"];
            /** @description Hash of the previous record ([`Digest::ZERO`] for the first). */
            prev: components["schemas"]["Digest"];
            /** @description Who acted. */
            principal: components["schemas"]["Principal"];
            request?: components["schemas"]["RequestId"] | null;
            /** @description The store revision that committed the record with its change. */
            revision: components["schemas"]["Revision"];
            /** @description Position in the chain, gap-free from 1. */
            seq: components["schemas"]["AuditSeq"];
        };
        /**
         * Format: int64
         * @description Position in the audit chain: gap-free, starting at 1 (IAM-18).
         */
        AuditSeq: number;
        /** @description Result of `GET /audit/verify`: the hash chain walked from the first record. */
        AuditVerifyReport: {
            /**
             * Format: int64
             * @description Number of records verified before the first break, or all of them.
             */
            checked: number;
            first_break?: components["schemas"]["AuditBreak"] | null;
            /** @description The last record that verified (sequence number and hash); sequence 0 when none did. */
            head: components["schemas"]["ChainHead"];
            /** @description Whether every record links to its predecessor and matches its hash. */
            intact: boolean;
            /** @description Store revision the chain was read at. */
            revision: components["schemas"]["Revision"];
            /** @description The audit head the store reports at `revision`. */
            store_head: components["schemas"]["AuditSeq"];
        };
        /**
         * @description How a session was authenticated, weakest first, so `>=` compares strength (IAM-03,
         *     IAM-06).
         * @enum {string}
         */
        AuthStrength: "pin" | "password" | "password_totp" | "passkey" | "hardware_key";
        /** @description An authentication result from the browser (`AuthenticationResponseJSON`). */
        AuthenticationResponse: {
            /** @description `platform` or `cross-platform`, when the client reports it. */
            authenticatorAttachment?: string | null;
            /** @description Client extension results; ignored. */
            clientExtensionResults?: Record<string, never>;
            /** @description The credential id, base64url. */
            id: string;
            /** @description The credential id again, base64url. */
            rawId: string;
            /** @description The assertion response. */
            response: components["schemas"]["AssertionResponse"];
            /** @description Always `public-key`. */
            type: string;
        };
        /** @description Authenticator selection criteria of a registration. */
        AuthenticatorSelection: {
            /** @description `platform` or `cross-platform`; absent for any. */
            authenticatorAttachment?: string | null;
            /** @description Always `true` (Level 1 clients). */
            requireResidentKey: boolean;
            /** @description Always `required`: Tenko creates discoverable credentials. */
            residentKey: string;
            /** @description `required`, `preferred` or `discouraged`. */
            userVerification: string;
        };
        /** @description What the UI needs for its warning banner (API-10: insecure settings are loud). */
        Banner: {
            /** @description Toggles that deviate from the selected profile. */
            deviations: string[];
            /** @description The Lab profile is active. */
            lab: boolean;
            /** @description At least one toggle is weaker than the Home baseline. */
            weaker_than_home: boolean;
        };
        /**
         * @description Where the breached-password check looks (TGL-06).
         * @enum {string}
         */
        BreachMode: "off" | "online" | "offline" | "offline_preferred";
        /**
         * @description The result of the breached-password check (IAM-04).
         * @enum {string}
         */
        BreachStatus: "clean" | "breached" | "unavailable" | "off";
        /** @description `PUT /system/break-glass` (IAM-09). */
        BreakGlassChange: {
            /** @description Make it the break-glass account, or a normal account again. */
            enabled: boolean;
            /** @description The account. */
            user_id: components["schemas"]["UserId"];
        };
        /** @description A bulk change: every operation applies, or none (API-04). */
        BulkRequest: {
            /** @description The operations, in order; all must target the collection of the endpoint. */
            operations: components["schemas"]["IpamCommand"][];
        };
        /** @description The answer of a bulk change. */
        BulkResponse: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /** @description The primary object of each operation, in order. */
            results: components["schemas"]["ObjectRef"][];
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The certificate the listener serves. */
        CertificateStatus: {
            /**
             * Format: int64
             * @description Whole days until `not_after` (negative once expired).
             */
            days_remaining?: number | null;
            /** @description When the listener loaded this certificate. */
            loaded_at: components["schemas"]["Timestamp"];
            /** @description Names the certificate is valid for, when known. */
            names: string[];
            not_after?: components["schemas"]["Timestamp"] | null;
        };
        /** @description The verified end of a chain: the last sequence number and its hash. */
        ChainHead: {
            /** @description Its hash ([`Digest::ZERO`] before the first record). */
            hash: components["schemas"]["Digest"];
            /** @description Last verified sequence number ([`AuditSeq::NONE`] before the first record). */
            seq: components["schemas"]["AuditSeq"];
        };
        /**
         * @description What happened to an object.
         * @enum {string}
         */
        ChangeAction: "create" | "update" | "delete" | "restore" | "lock" | "unlock" | "remove";
        /** @description `POST /auth/login/totp` and `POST /auth/login/recovery`. */
        CodeLogin: {
            /** @description The challenge from the password step. */
            challenge_id: string;
            /** @description The TOTP code or recovery code. */
            code: components["schemas"]["SecretString"];
        };
        /**
         * @description A serializable snapshot of a [`Coded`] error.
         *
         *     This is the wire shape of every error (the API adds `type` and `instance` to make an
         *     RFC 9457 problem document) and the stored shape of failed job steps.
         */
        CodedError: {
            /** @description The stable, namespaced error code. */
            code: string;
            /** @description English explanation of this occurrence. */
            detail: string;
            /** @description Per-field errors. */
            errors?: components["schemas"]["FieldError"][];
            /** @description Named parameters for the translated message. */
            params?: {
                [key: string]: string;
            };
            /**
             * Format: int32
             * @description The HTTP status.
             */
            status: number;
            /** @description Short English summary. */
            title: string;
        };
        /** @description Body of `POST /jobs/{id}/steps/{index}/complete`. The whole body is optional. */
        CompleteStepRequest: {
            /**
             * @description What was done, kept in the job's transition log and in the audit record. At most
             *     4,096 bytes.
             */
            note?: string | null;
        };
        /**
         * @description Which context-specific word a password contained.
         * @enum {string}
         */
        ContextKind: "user_name" | "display_name" | "host_name" | "product";
        /** @description A new token: the secret is shown once. */
        CreatedToken: {
            /** @description Its metadata. */
            info: components["schemas"]["TokenInfo"];
            /** @description The token, for `Authorization: Bearer`. */
            token: components["schemas"]["SecretString"];
        };
        /**
         * @description Options of a registration ceremony, passed to
         *     `PublicKeyCredential.parseCreationOptionsFromJSON()`.
         */
        CreationOptions: {
            /** @description `none` or `direct`. */
            attestation: string;
            /** @description Authenticator selection. */
            authenticatorSelection: components["schemas"]["AuthenticatorSelection"];
            /** @description The challenge, base64url. */
            challenge: string;
            /** @description Credentials the account already has. */
            excludeCredentials?: components["schemas"]["CredentialDescriptor"][];
            /** @description Client hints such as `security-key`. */
            hints?: string[];
            /** @description Acceptable algorithms, preferred first. */
            pubKeyCredParams: components["schemas"]["CredentialParameter"][];
            /** @description The relying party. */
            rp: components["schemas"]["RpEntity"];
            /**
             * Format: int32
             * @description Ceremony timeout in milliseconds.
             */
            timeout: number;
            /** @description The account. */
            user: components["schemas"]["UserEntity"];
        };
        /** @description A credential reference in `excludeCredentials` or `allowCredentials`. */
        CredentialDescriptor: {
            /** @description The credential id, base64url. */
            id: string;
            /** @description Transport hints reported at registration. */
            transports?: string[];
            /** @description Always `public-key`. */
            type: string;
        };
        /** @description A registered WebAuthn credential. */
        CredentialInfo: {
            /** @description The authenticator model (AAGUID), hexadecimal. */
            aaguid: string;
            /**
             * Format: int64
             * @description The COSE algorithm.
             */
            alg: number;
            /** @description What the attestation proved. */
            attestation: components["schemas"]["AttestationKind"];
            /** @description A synced passkey. */
            backup_eligible: boolean;
            /** @description Backed up at the last use. */
            backup_state: boolean;
            /** @description When it was registered. */
            created_at: components["schemas"]["Timestamp"];
            /** @description Counts as a hardware security key. */
            hardware_key: boolean;
            /** @description The credential id, base64url. */
            id: string;
            /** @description The label. */
            label: string;
            last_used_at?: components["schemas"]["Timestamp"] | null;
        };
        /** @description An acceptable credential algorithm. */
        CredentialParameter: {
            /**
             * Format: int64
             * @description The COSE algorithm identifier.
             */
            alg: number;
            /** @description Always `public-key`. */
            type: string;
        };
        /** @description Definition of a custom field (IPAM-08). */
        CustomFieldDef: {
            /** @description Object kinds the field applies to. */
            applies_to: components["schemas"]["ObjectKind"][];
            /** @description Identifier, so the definition can be audited and referenced. */
            id: components["schemas"]["CustomFieldId"];
            /** @description The key used in [`Meta::custom`]. */
            key: components["schemas"]["FieldKey"];
            /** @description Value type. */
            kind: components["schemas"]["CustomKind"];
            /** @description Whether every object of those kinds must have a value. */
            required?: boolean;
        };
        /** Format: uuid */
        CustomFieldId: string;
        /** @description A new custom field definition (IPAM-08). */
        CustomFieldInput: {
            /** @description Object kinds the field applies to. */
            applies_to: components["schemas"]["ObjectKind"][];
            id?: components["schemas"]["CustomFieldId"] | null;
            /** @description The key, `[a-z][a-z0-9_]{0,63}`. */
            key: components["schemas"]["FieldKey"];
            /** @description Value type. */
            kind: components["schemas"]["CustomKind"];
            /** @description Whether every object of those kinds must have a value. */
            required?: boolean;
        };
        /** @description Changes to a custom field definition. The key cannot change. */
        CustomFieldPatch: {
            /** @description New object kinds. */
            applies_to?: components["schemas"]["ObjectKind"][] | null;
            kind?: components["schemas"]["CustomKind"] | null;
            /** @description New required flag. */
            required?: boolean | null;
        };
        /** @description Value type of a custom field. */
        CustomKind: {
            /** @enum {string} */
            type: "text";
        } | {
            /** @enum {string} */
            type: "integer";
        } | {
            /** @enum {string} */
            type: "boolean";
        } | {
            /** @enum {string} */
            type: "date";
        } | {
            /** @enum {string} */
            type: "url";
        } | {
            /** @description The allowed options. */
            options: string[];
            /** @enum {string} */
            type: "select";
        };
        /**
         * @description The limits and the pattern of the Custom preset.
         *
         *     [`PasswordPolicy::validate`] checks the bounds when the setting is saved.
         */
        CustomPolicy: {
            /**
             * @description The maximum length in Unicode characters after normalization: from 64 to 1024.
             *     Defaults to 256.
             */
            max_length?: number;
            /**
             * @description The minimum length in Unicode characters after normalization: 4 or more, and not
             *     more than `max_length`.
             */
            min_length: number;
            /**
             * @description A regular expression (Rust `regex` syntax) that the whole normalized password must
             *     match (it is anchored at both ends for you). Perl classes such as `\d` and `\w` and
             *     Unicode property classes such as `\p{L}` work. Without a pattern, only the length
             *     limits apply.
             */
            pattern?: string | null;
        };
        /** @description A custom field value. */
        CustomValue: {
            /** @enum {string} */
            type: "text";
            /** @description Free text. */
            value: string;
        } | {
            /** @enum {string} */
            type: "integer";
            /**
             * Format: int64
             * @description A signed integer.
             */
            value: number;
        } | {
            /** @enum {string} */
            type: "boolean";
            /** @description True or false. */
            value: boolean;
        } | {
            /** @enum {string} */
            type: "date";
            /** @description A calendar date in ISO 8601 form (`YYYY-MM-DD`), validated by the IPAM domain. */
            value: string;
        } | {
            /** @enum {string} */
            type: "url";
            /** @description A URL. */
            value: string;
        } | {
            /** @enum {string} */
            type: "select";
            /** @description The chosen option. */
            value: string;
        };
        /**
         * @description Which soft-deleted objects a list returns (IPAM-09).
         * @enum {string}
         */
        Deleted: "exclude" | "include" | "only";
        /** @description SHA-256 digest as 64 lowercase hexadecimal characters */
        Digest: string;
        /** @description DHCPv6 DUID as lowercase hexadecimal */
        Duid: string;
        /**
         * @description The `data` of a topic event.
         *
         *     Data events from the store have `revision` (also the SSE id, so `Last-Event-ID`
         *     resumes after it) and list the objects written or deleted by that revision. System
         *     events that do not come from a store change have no revision and no SSE id.
         */
        EventData: {
            /** @description New audit records (topic `audit`). */
            audit?: components["schemas"]["AuditSeq"][];
            /** @description Objects removed from the store. */
            deleted?: components["schemas"]["ObjectRef"][];
            /** @description Kind of a system event that did not come from the store, for example an alarm code. */
            kind?: string | null;
            /** @description Objects created or changed (including soft deletes, which are changes). */
            objects?: components["schemas"]["ObjectRef"][];
            /** @description Parameters of such an event, for the UI's translated message. */
            params?: {
                [key: string]: string;
            };
            revision?: components["schemas"]["Revision"] | null;
            /** @description Changed tables that carry no object reference (topic `admin`, some `system` alarms). */
            tables?: string[];
            /** @description The topic. */
            topic: components["schemas"]["Topic"];
        };
        /**
         * @description The answer of a factor enrolment. Enrolling a factor does not raise the strength of the
         *     session that enrolled it: when the session is below what the profile requires, the UI
         *     logs in again with the new factor.
         */
        FactorEnrolled: {
            credential?: components["schemas"]["CredentialInfo"] | null;
            /** @description Whether the session must log in again to reach the required strength. */
            reauthenticate: boolean;
            /** @description New recovery codes, shown once, when the account had none. */
            recovery_codes?: components["schemas"]["SecretString"][] | null;
        };
        /** @description The factors of an account. */
        FactorSummary: {
            /** @description Of those, hardware security keys. */
            hardware_keys: number;
            /** @description A password or PIN is set. */
            password: boolean;
            /** @description Unused recovery codes. */
            recovery_codes: number;
            /** @description TOTP is enrolled. */
            totp: boolean;
            /** @description Registered passkeys and security keys. */
            webauthn: number;
        };
        /** @description One changed field: a diff line or a toggle change. */
        FieldChange: {
            /** @description The field or toggle, for example `status` or `TGL-02`. */
            field: string;
            /** @description The value after, rendered as text; `None` when the field was removed. */
            new?: string | null;
            object?: components["schemas"]["ObjectRef"] | null;
            /** @description The value before, rendered as text; `None` when the field was absent. */
            old?: string | null;
        };
        /** @description One invalid field of a request body (the `errors` member of problem details). */
        FieldError: {
            /** @description The stable code of the problem with this field. */
            code: string;
            /** @description The field path, for example `cidr` or `interfaces[0].mac`. */
            field: string;
            /** @description Named parameters for the translated message. */
            params?: {
                [key: string]: string;
            };
        };
        /** @description Key of a custom field (IPAM-08): `[a-z][a-z0-9_]{0,63}`. */
        FieldKey: string;
        /** @description DNS name */
        Fqdn: string;
        /**
         * @description Groups jobs that share a parallelism limit, for example every write through one
         *     network controller (CONN-09): 1 to 128 visible ASCII characters.
         */
        GroupKey: string;
        /** @description Body of `GET /health` (liveness): the process answers. */
        Health: {
            /** @description Always `ok`. */
            status: string;
            /** @description Version of the server. */
            version: string;
        };
        /** @description Lowercase hexadecimal bytes */
        HexBytes: string;
        /** @description One change of one object. */
        HistoryEntry: {
            /** @description What happened. */
            action: components["schemas"]["ChangeAction"];
            after?: components["schemas"]["IpamObject"] | null;
            /** @description When (the request time). */
            at: components["schemas"]["Timestamp"];
            before?: components["schemas"]["IpamObject"] | null;
            /** @description Who. */
            by: components["schemas"]["Principal"];
            /** @description Changed fields, rendered as text. */
            changes?: components["schemas"]["FieldChange"][];
            /** @description The kind of job that carried the change. */
            job_kind?: string | null;
            /** @description The object. */
            object: components["schemas"]["ObjectRef"];
            /** @description The request. */
            request: components["schemas"]["RequestId"];
            /** @description The revision of the batch that wrote the entry (filled when read). */
            revision?: components["schemas"]["Revision"];
        };
        /** @description A host: the unit of intent (IPAM-12). */
        Host: {
            /** @description Identifier. */
            id: components["schemas"]["HostId"];
            /** @description Stops all automation for the host (IPAM-16). */
            lock?: boolean;
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description What IPAM may do with the host (IPAM-14). */
            mode: components["schemas"]["AssignmentMode"];
            /** @description Name. */
            name: components["schemas"]["HostName"];
            site?: components["schemas"]["SiteId"] | null;
            /** @description Owning tenant. */
            tenant: components["schemas"]["TenantId"];
        };
        /** Format: uuid */
        HostId: string;
        /** @description A new host, optionally with its interfaces. */
        HostInput: {
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["HostId"] | null;
            /** @description Interfaces created with the host. */
            interfaces?: components["schemas"]["InterfaceInput"][];
            /** @description Lock against automation (IPAM-16). */
            lock?: boolean | null;
            mode?: components["schemas"]["AssignmentMode"] | null;
            /**
             * @description Name, unique within the tenant.
             * @example nas01
             */
            name: string;
            site?: components["schemas"]["SiteId"] | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
            tenant?: components["schemas"]["TenantId"] | null;
        };
        /** @description host name */
        HostName: string;
        /** @description Changes to a host. The tenant cannot change. */
        HostPatch: {
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description Lock or unlock (people only). */
            lock?: boolean | null;
            mode?: components["schemas"]["AssignmentMode"] | null;
            /** @description New name. */
            name?: string | null;
            /** @description New site; `null` clears it. */
            site?: string | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /**
         * @description A client-chosen idempotency key (`Idempotency-Key` header, API-04): 1 to 255 visible
         *     ASCII characters.
         *
         *     The store scopes keys per principal subject (see `Principal::subject`), so two users
         *     cannot collide on the same key.
         */
        IdempotencyKey: string;
        /** @description The multipart form of `POST /imports`. */
        ImportUpload: {
            /**
             * Format: binary
             * @description The spreadsheet or CSV file. Uploads are staged for 24 hours and limited to 20 MB.
             */
            file: string;
        };
        /** @description A network interface of a host. */
        Interface: {
            client_id?: components["schemas"]["HexBytes"] | null;
            duid?: components["schemas"]["Duid"] | null;
            /** @description Owning host. */
            host: components["schemas"]["HostId"];
            /** @description Identifier. */
            id: components["schemas"]["InterfaceId"];
            mac?: components["schemas"]["MacAddr"] | null;
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description Name, such as `eth0`. */
            name: string;
        };
        /** Format: uuid */
        InterfaceId: string;
        /** @description A new interface. */
        InterfaceInput: {
            client_id?: components["schemas"]["HexBytes"] | null;
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            duid?: components["schemas"]["Duid"] | null;
            host?: components["schemas"]["HostId"] | null;
            id?: components["schemas"]["InterfaceId"] | null;
            mac?: components["schemas"]["MacAddr"] | null;
            /** @description Name, unique per host (`eth0`). */
            name: string;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
        };
        /** @description Changes to an interface. The host cannot change. */
        InterfacePatch: {
            /** @description New client identifier; `null` clears it. */
            client_id?: string | null;
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New DUID; `null` clears it. */
            duid?: string | null;
            /** @description New MAC address; `null` clears it. */
            mac?: string | null;
            /** @description New name. */
            name?: string | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /**
         * @description One change, as part of a plan.
         *
         *     Adjacently tagged (`{"op": "create_prefix", "args": {...}}`) because arguments carry
         *     IP addresses (see the encoding rules in `tenko_core::codec`).
         */
        IpamCommand: {
            /** @description Creates a tenant. */
            args: components["schemas"]["TenantInput"];
            /** @enum {string} */
            op: "create_tenant";
        } | {
            /** @description Updates a tenant. */
            args: components["schemas"]["UpdateTenant"];
            /** @enum {string} */
            op: "update_tenant";
        } | {
            /** @description Creates a VRF. */
            args: components["schemas"]["VrfInput"];
            /** @enum {string} */
            op: "create_vrf";
        } | {
            /** @description Updates a VRF. */
            args: components["schemas"]["UpdateVrf"];
            /** @enum {string} */
            op: "update_vrf";
        } | {
            /** @description Creates a site. */
            args: components["schemas"]["SiteInput"];
            /** @enum {string} */
            op: "create_site";
        } | {
            /** @description Updates a site. */
            args: components["schemas"]["UpdateSite"];
            /** @enum {string} */
            op: "update_site";
        } | {
            /** @description Creates a VLAN. */
            args: components["schemas"]["VlanInput"];
            /** @enum {string} */
            op: "create_vlan";
        } | {
            /** @description Updates a VLAN. */
            args: components["schemas"]["UpdateVlan"];
            /** @enum {string} */
            op: "update_vlan";
        } | {
            /** @description Creates a prefix. */
            args: components["schemas"]["PrefixInput"];
            /** @enum {string} */
            op: "create_prefix";
        } | {
            /** @description Updates a prefix. */
            args: components["schemas"]["UpdatePrefix"];
            /** @enum {string} */
            op: "update_prefix";
        } | {
            /** @description Creates a range. */
            args: components["schemas"]["RangeInput"];
            /** @enum {string} */
            op: "create_range";
        } | {
            /** @description Updates a range. */
            args: components["schemas"]["UpdateRange"];
            /** @enum {string} */
            op: "update_range";
        } | {
            /** @description Creates an address. */
            args: components["schemas"]["AddressInput"];
            /** @enum {string} */
            op: "create_address";
        } | {
            /** @description Updates an address. */
            args: components["schemas"]["UpdateAddress"];
            /** @enum {string} */
            op: "update_address";
        } | {
            /** @description Creates a host. */
            args: components["schemas"]["HostInput"];
            /** @enum {string} */
            op: "create_host";
        } | {
            /** @description Updates a host. */
            args: components["schemas"]["UpdateHost"];
            /** @enum {string} */
            op: "update_host";
        } | {
            /** @description Creates an interface. */
            args: components["schemas"]["InterfaceInput"];
            /** @enum {string} */
            op: "create_interface";
        } | {
            /** @description Updates an interface. */
            args: components["schemas"]["UpdateInterface"];
            /** @enum {string} */
            op: "update_interface";
        } | {
            /** @description Soft-deletes an object (IPAM-09). */
            args: {
                /**
                 * @description Also delete what would otherwise block the delete: the addresses and ranges of
                 *     a prefix, the addresses of a host or an interface.
                 */
                cascade?: boolean;
                /**
                 * Format: int64
                 * @description The revision the caller read (`If-Match`).
                 */
                expected?: number | null;
                /** @description The object. */
                object: components["schemas"]["ObjectRef"];
            };
            /** @enum {string} */
            op: "delete";
        } | {
            /** @description Restores a soft-deleted object (IPAM-09). */
            args: {
                /**
                 * Format: int64
                 * @description The revision the caller read.
                 */
                expected?: number | null;
                /** @description The object. */
                object: components["schemas"]["ObjectRef"];
            };
            /** @enum {string} */
            op: "restore";
        } | {
            /** @description Locks or unlocks a host against automation (IPAM-16). */
            args: {
                /**
                 * Format: int64
                 * @description The revision the caller read.
                 */
                expected?: number | null;
                /** @description The host. */
                host: components["schemas"]["HostId"];
                /** @description Whether the host is locked. */
                lock: boolean;
            };
            /** @enum {string} */
            op: "set_lock";
        } | {
            /** @description Changes the assignment mode of a host (IPAM-14). */
            args: {
                /**
                 * Format: int64
                 * @description The revision the caller read.
                 */
                expected?: number | null;
                /** @description The host. */
                host: components["schemas"]["HostId"];
                /** @description The new mode. */
                mode: components["schemas"]["AssignmentMode"];
            };
            /** @enum {string} */
            op: "set_mode";
        } | {
            /** @description Allocates and creates the next free address (IPAM-07). */
            args: components["schemas"]["AllocateAddress"];
            /** @enum {string} */
            op: "allocate_address";
        } | {
            /** @description Allocates and creates the next free child prefix (IPAM-07). */
            args: components["schemas"]["AllocatePrefix"];
            /** @enum {string} */
            op: "allocate_prefix";
        } | {
            /** @description Creates a custom field definition (IPAM-08). */
            args: components["schemas"]["CustomFieldInput"];
            /** @enum {string} */
            op: "create_custom_field";
        } | {
            /** @description Updates a custom field definition. */
            args: components["schemas"]["UpdateCustomField"];
            /** @enum {string} */
            op: "update_custom_field";
        } | {
            /** @description Removes a custom field definition that no object uses. */
            args: {
                /**
                 * Format: int64
                 * @description The revision of the definition the caller read (`If-Match`).
                 */
                expected?: number | null;
                /** @description The key. */
                key: components["schemas"]["FieldKey"];
            };
            /** @enum {string} */
            op: "delete_custom_field";
        };
        /**
         * @description Any IPAM object, tagged by kind.
         *
         *     Adjacently tagged (`{"kind": "prefix", "data": {...}}`) because several variants
         *     carry IP addresses (see the encoding rules in `tenko_core::codec`).
         */
        IpamObject: {
            /** @description A tenant. */
            data: components["schemas"]["Tenant"];
            /** @enum {string} */
            kind: "tenant";
        } | {
            /** @description A VRF. */
            data: components["schemas"]["Vrf"];
            /** @enum {string} */
            kind: "vrf";
        } | {
            /** @description A site. */
            data: components["schemas"]["Site"];
            /** @enum {string} */
            kind: "site";
        } | {
            /** @description A VLAN. */
            data: components["schemas"]["Vlan"];
            /** @enum {string} */
            kind: "vlan";
        } | {
            /** @description A prefix. */
            data: components["schemas"]["Prefix"];
            /** @enum {string} */
            kind: "prefix";
        } | {
            /** @description A range. */
            data: components["schemas"]["Range"];
            /** @enum {string} */
            kind: "range";
        } | {
            /** @description An address. */
            data: components["schemas"]["Address"];
            /** @enum {string} */
            kind: "address";
        } | {
            /** @description A host. */
            data: components["schemas"]["Host"];
            /** @enum {string} */
            kind: "host";
        } | {
            /** @description An interface. */
            data: components["schemas"]["Interface"];
            /** @enum {string} */
            kind: "interface";
        } | {
            /** @description A custom field definition. */
            data: components["schemas"]["CustomFieldDef"];
            /** @enum {string} */
            kind: "custom_field";
        };
        /** @description A job as stored and shown. */
        Job: {
            cancel_requested?: components["schemas"]["Stamp"] | null;
            /** @description Submission. */
            created: components["schemas"]["Stamp"];
            error?: components["schemas"]["CodedError"] | null;
            finished?: components["schemas"]["Timestamp"] | null;
            /** @description Identifier. */
            id: components["schemas"]["JobId"];
            /** @description Store revision of the last write (filled from the read, like `Meta::revision`). */
            revision?: components["schemas"]["Revision"];
            runner?: components["schemas"]["NodeId"] | null;
            /** @description What runs. */
            spec: components["schemas"]["JobSpec"];
            started?: components["schemas"]["Timestamp"] | null;
            /** @description Current state. */
            state: components["schemas"]["JobState"];
            /** @description One record per step of the spec, same order. */
            steps: components["schemas"]["StepRecord"][];
        };
        /** @description A job with its history and preview. */
        JobDetail: {
            /** @description The job with every step. */
            job: components["schemas"]["Job"];
            preview?: components["schemas"]["JobPreview"] | null;
            /** @description The revision the detail was read at. */
            revision: components["schemas"]["Revision"];
            /** @description The transition log, oldest first. */
            transitions: components["schemas"]["Transition"][];
        };
        /** Format: uuid */
        JobId: string;
        /** @description Namespaced job kind */
        JobKind: string;
        /** @description What a whole job would do. */
        JobPreview: {
            /** @description One preview per step. */
            steps: components["schemas"]["StepPreview"][];
            /** @description Job-level warnings. */
            warnings?: components["schemas"]["CodedError"][];
        };
        /** @description What to run. */
        JobSpec: {
            group?: components["schemas"]["GroupKey"] | null;
            /**
             * Format: int32
             * @description Parallelism of the job's group when the engine has no configured limit for it; the
             *     jobs of one group carry the same value (a move job group, IPAM-19, CONN-09).
             */
            group_limit?: number | null;
            idempotency?: components["schemas"]["IdempotencyKey"] | null;
            /** @description The kind of job. */
            kind: components["schemas"]["JobKind"];
            /** @description The steps, run in order. */
            steps: components["schemas"]["StepSpec"][];
            /** @description The objects the job changes. */
            targets: components["schemas"]["ObjectRef"][];
            /**
             * Format: int64
             * @description Overall timeout; passing it starts the rollback.
             */
            timeout: number;
            /** @description Translatable title. */
            title: components["schemas"]["MessageKey"];
        };
        /**
         * @description States of a job.
         * @enum {string}
         */
        JobState: "queued" | "running" | "waiting" | "rolling_back" | "succeeded" | "failed" | "rolled_back" | "cancelled";
        /** @description A job in a list: everything a job panel shows per row. */
        JobSummary: {
            /** @description Whether someone asked to cancel. */
            cancel_requested: boolean;
            /** @description Submission. */
            created: components["schemas"]["Stamp"];
            /**
             * Format: int32
             * @description The first step that is neither done nor skipped.
             */
            current_step?: number | null;
            current_step_state?: components["schemas"]["StepStateKind"] | null;
            error?: components["schemas"]["CodedError"] | null;
            finished?: components["schemas"]["Timestamp"] | null;
            group?: components["schemas"]["GroupKey"] | null;
            /** @description Identifier. */
            id: components["schemas"]["JobId"];
            /** @description The kind of job. */
            kind: components["schemas"]["JobKind"];
            /** @description Steps waiting for a person: manual tasks and manual undo tasks. */
            manual_steps?: number[];
            /** @description Store revision of the job's last write. */
            revision: components["schemas"]["Revision"];
            runner?: components["schemas"]["NodeId"] | null;
            /** @description Current state. */
            state: components["schemas"]["JobState"];
            /**
             * Format: int32
             * @description Number of steps.
             */
            step_count: number;
            /**
             * Format: int32
             * @description Steps done or skipped.
             */
            steps_done: number;
            /** @description The objects the job changes. */
            targets: components["schemas"]["ObjectRef"][];
            /** @description Translatable title. */
            title: components["schemas"]["MessageKey"];
        };
        /** @description A list without paging. */
        ListBody_CustomFieldDef: {
            /** @description Every item. */
            items: {
                /** @description Object kinds the field applies to. */
                applies_to: components["schemas"]["ObjectKind"][];
                /** @description Identifier, so the definition can be audited and referenced. */
                id: components["schemas"]["CustomFieldId"];
                /** @description The key used in [`Meta::custom`]. */
                key: components["schemas"]["FieldKey"];
                /** @description Value type. */
                kind: components["schemas"]["CustomKind"];
                /** @description Whether every object of those kinds must have a value. */
                required?: boolean;
            }[];
            /**
             * Format: int64
             * @description The store revision the list was read at.
             */
            revision: number;
        };
        /** @description A list without paging. */
        ListBody_SearchHit: {
            /** @description Every item. */
            items: {
                /** @description The object itself. */
                item: components["schemas"]["IpamObject"];
                /** @description A short label: the network, address or name. */
                label: string;
                /** @description The object. */
                object: components["schemas"]["ObjectRef"];
            }[];
            /**
             * Format: int64
             * @description The store revision the list was read at.
             */
            revision: number;
        };
        /** @description A list without paging. */
        ListBody_TagCount: {
            /** @description Every item. */
            items: {
                /** @description Objects per kind. */
                by_kind: {
                    [key: string]: number;
                };
                /**
                 * Format: int64
                 * @description Objects carrying it.
                 */
                count: number;
                /** @description The tag. */
                tag: string;
            }[];
            /**
             * Format: int64
             * @description The store revision the list was read at.
             */
            revision: number;
        };
        /**
         * @description How failed logins are punished (TGL-07).
         *
         *     The security presets map onto the modes as Home to `ProgressiveDelay`, Standard to
         *     `DelayThenTemporaryLock`, Hardened to `LockUntilUnlock` and Lab to `Off`.
         * @enum {string}
         */
        LockoutMode: "off" | "progressive_delay" | "delay_then_temporary_lock" | "lock_until_unlock";
        /** @description The answer of a login step. */
        LoginResponse: {
            /** @description The new session. */
            session: components["schemas"]["SessionInfo"];
            /** @enum {string} */
            status: "authenticated";
        } | {
            /** @description Pass this to the next step. */
            challenge_id: string;
            /**
             * Format: int64
             * @description Seconds until the challenge expires.
             */
            expires_in: number;
            /** @description The methods the account can use. */
            methods: components["schemas"]["SecondFactorMethod"][];
            /** @enum {string} */
            status: "second_factor";
        };
        /** @description MAC address, lowercase and colon-separated (00:00:5e:00:53:01) */
        MacAddr: string;
        /** @description A task for a person, with translatable text. */
        ManualTask: {
            /** @description Message arguments (host name, address, VLAN). */
            args?: {
                [key: string]: string;
            };
            /** @description What to do. */
            instruction: components["schemas"]["MessageKey"];
            undo?: components["schemas"]["MessageKey"] | null;
        };
        /** @description Namespaced message key */
        MessageKey: string;
        /** @description Metadata shared by every IPAM object (IPAM-08, IPAM-09). */
        Meta: {
            /** @description Creation. */
            created: components["schemas"]["Stamp"];
            /** @description Custom field values (IPAM-08), validated against their [`CustomFieldDef`]. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            deleted?: components["schemas"]["Stamp"] | null;
            /** @description Free text. */
            description?: string | null;
            /**
             * @description Store revision of the last write. Readers overwrite it with the revision the store
             *     reports for the value (`Versioned::revision`); the stored copy is not authoritative,
             *     because the revision is only known after the write commits.
             */
            revision?: components["schemas"]["Revision"];
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
            /** @description Last change. */
            updated: components["schemas"]["Stamp"];
        };
        /**
         * @description Who must use a second factor (TGL-02). The PIN coupling rule (IAM-07) can force it
         *     regardless.
         * @enum {string}
         */
        MfaRequirement: "optional" | "administrators" | "everyone";
        /** @description The body of `POST /prefixes/{id}/ranges`; the prefix comes from the path. */
        NewRange: {
            /** @description Custom field values. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            /**
             * @description First address, inclusive.
             * @example 192.0.2.100
             */
            first: string;
            id?: components["schemas"]["RangeId"] | null;
            /**
             * @description Last address, inclusive.
             * @example 192.0.2.199
             */
            last: string;
            /** @description What the range is for. */
            role: components["schemas"]["RangeRole"];
            status?: components["schemas"]["Status"] | null;
            /** @description Tags. */
            tags?: components["schemas"]["Tag"][];
        };
        /**
         * @description The optional body of `POST /prefixes/{id}/next-free-address`: how the new address is
         *     chosen and what it carries. Every member is optional; an empty body means all defaults.
         */
        NextFreeAddress: {
            /**
             * @description Custom field values of the new address.
             * @default {}
             */
            custom: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /**
             * @description Free text.
             * @default null
             */
            description: string | null;
            /** @default null */
            dns_name: components["schemas"]["Fqdn"] | null;
            /** @default null */
            id: components["schemas"]["AddressId"] | null;
            /** @default null */
            interface: components["schemas"]["InterfaceId"] | null;
            /** @default null */
            policy: components["schemas"]["AllocPolicy"] | null;
            /** @default null */
            range: components["schemas"]["RangeId"] | null;
            /** @default null */
            status: components["schemas"]["Status"] | null;
            /**
             * @description Tags of the new address.
             * @default []
             */
            tags: components["schemas"]["Tag"][];
        };
        /**
         * @description The body of `POST /prefixes/{id}/next-free-prefix`: the length of the new child prefix
         *     and what it carries.
         */
        NextFreePrefix: {
            alarm?: components["schemas"]["UtilizationAlarm"] | null;
            /** @description Custom field values of the new prefix. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["PrefixId"] | null;
            /**
             * Format: int32
             * @description Prefix length of the new prefix, for example 26.
             */
            length: number;
            policy?: components["schemas"]["AllocPolicy"] | null;
            role?: components["schemas"]["PrefixRole"] | null;
            site?: components["schemas"]["SiteId"] | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Tags of the new prefix. */
            tags?: components["schemas"]["Tag"][];
            vlan?: components["schemas"]["VlanId"] | null;
        };
        /**
         * Format: int64
         * @description Raft node identifier, assigned at enrolment.
         */
        NodeId: number;
        /** @description Identity and roles of the node. */
        NodeStatus: {
            id?: components["schemas"]["NodeId"] | null;
            /** @description Roles this node runs: `controller`, `dns`, `dhcp`, `probe`. */
            roles: string[];
        };
        /**
         * @description The kind of an object: one variant per entity.
         *
         *     Serialized and key-encoded as its `snake_case` name, which is stable. Ordering
         *     follows the name, so it matches the key encoding.
         * @enum {string}
         */
        ObjectKind: "tenant" | "vrf" | "site" | "vlan" | "prefix" | "range" | "address" | "host" | "interface" | "custom_field" | "user" | "session" | "api_token" | "job" | "observation" | "proposal" | "import" | "connector" | "secret" | "node" | "settings" | "system";
        /** @description A typed reference to one object. */
        ObjectRef: {
            /**
             * Format: uuid
             * @description The object's identifier (nil for singletons).
             */
            id: string;
            /** @description The kind of object. */
            kind: components["schemas"]["ObjectKind"];
        };
        /** @description An observation a waiting step needs. */
        ObservationCondition: {
            /** @description Any one of these satisfies the condition. */
            any_of: components["schemas"]["ObservedPredicate"][];
            /** @description The object the job waits for (usually the host). */
            subject: components["schemas"]["ObjectRef"];
        };
        /**
         * @description One acceptable observation.
         *
         *     Adjacently tagged because variants carry IP addresses.
         */
        ObservedPredicate: {
            /** @description The address answers (ARP, ND or ping), from the given MAC when set. */
            data: {
                /** @description The address. */
                ip: string;
                mac?: components["schemas"]["MacAddr"] | null;
                /** @description The VRF. */
                vrf: components["schemas"]["VrfId"];
            };
            /** @enum {string} */
            type: "address_seen";
        } | {
            /** @description The MAC holds a DHCP lease inside the prefix (Phase 3). */
            data: {
                /** @description The client. */
                mac: components["schemas"]["MacAddr"];
                /** @description The prefix. */
                prefix: components["schemas"]["PrefixId"];
            };
            /** @enum {string} */
            type: "lease_in_prefix";
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Address: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                dns_name?: components["schemas"]["Fqdn"] | null;
                /** @description Identifier. */
                id: components["schemas"]["AddressId"];
                interface?: components["schemas"]["InterfaceId"] | null;
                /**
                 * @description The address.
                 * @example 192.0.2.10
                 */
                ip: string;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description The most specific prefix containing the address. */
                prefix: components["schemas"]["PrefixId"];
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
                /** @description The VRF. */
                vrf: components["schemas"]["VrfId"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_AuditRecord: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description The proposer's time of the batch. */
                at: components["schemas"]["Timestamp"];
                /** @description The audited action. */
                draft: components["schemas"]["AuditDraft"];
                /** @description SHA-256 over the canonical CBOR of every field above. */
                hash: components["schemas"]["Digest"];
                /** @description Hash of the previous record ([`Digest::ZERO`] for the first). */
                prev: components["schemas"]["Digest"];
                /** @description Who acted. */
                principal: components["schemas"]["Principal"];
                request?: components["schemas"]["RequestId"] | null;
                /** @description The store revision that committed the record with its change. */
                revision: components["schemas"]["Revision"];
                /** @description Position in the chain, gap-free from 1. */
                seq: components["schemas"]["AuditSeq"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_CredentialInfo: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description The authenticator model (AAGUID), hexadecimal. */
                aaguid: string;
                /**
                 * Format: int64
                 * @description The COSE algorithm.
                 */
                alg: number;
                /** @description What the attestation proved. */
                attestation: components["schemas"]["AttestationKind"];
                /** @description A synced passkey. */
                backup_eligible: boolean;
                /** @description Backed up at the last use. */
                backup_state: boolean;
                /** @description When it was registered. */
                created_at: components["schemas"]["Timestamp"];
                /** @description Counts as a hardware security key. */
                hardware_key: boolean;
                /** @description The credential id, base64url. */
                id: string;
                /** @description The label. */
                label: string;
                last_used_at?: components["schemas"]["Timestamp"] | null;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_HistoryEntry: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description What happened. */
                action: components["schemas"]["ChangeAction"];
                after?: components["schemas"]["IpamObject"] | null;
                /** @description When (the request time). */
                at: components["schemas"]["Timestamp"];
                before?: components["schemas"]["IpamObject"] | null;
                /** @description Who. */
                by: components["schemas"]["Principal"];
                /** @description Changed fields, rendered as text. */
                changes?: components["schemas"]["FieldChange"][];
                /** @description The kind of job that carried the change. */
                job_kind?: string | null;
                /** @description The object. */
                object: components["schemas"]["ObjectRef"];
                /** @description The request. */
                request: components["schemas"]["RequestId"];
                /** @description The revision of the batch that wrote the entry (filled when read). */
                revision?: components["schemas"]["Revision"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Host: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description Identifier. */
                id: components["schemas"]["HostId"];
                /** @description Stops all automation for the host (IPAM-16). */
                lock?: boolean;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description What IPAM may do with the host (IPAM-14). */
                mode: components["schemas"]["AssignmentMode"];
                /** @description Name. */
                name: components["schemas"]["HostName"];
                site?: components["schemas"]["SiteId"] | null;
                /** @description Owning tenant. */
                tenant: components["schemas"]["TenantId"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Interface: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                client_id?: components["schemas"]["HexBytes"] | null;
                duid?: components["schemas"]["Duid"] | null;
                /** @description Owning host. */
                host: components["schemas"]["HostId"];
                /** @description Identifier. */
                id: components["schemas"]["InterfaceId"];
                mac?: components["schemas"]["MacAddr"] | null;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name, such as `eth0`. */
                name: string;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_JobSummary: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description Whether someone asked to cancel. */
                cancel_requested: boolean;
                /** @description Submission. */
                created: components["schemas"]["Stamp"];
                /**
                 * Format: int32
                 * @description The first step that is neither done nor skipped.
                 */
                current_step?: number | null;
                current_step_state?: components["schemas"]["StepStateKind"] | null;
                error?: components["schemas"]["CodedError"] | null;
                finished?: components["schemas"]["Timestamp"] | null;
                group?: components["schemas"]["GroupKey"] | null;
                /** @description Identifier. */
                id: components["schemas"]["JobId"];
                /** @description The kind of job. */
                kind: components["schemas"]["JobKind"];
                /** @description Steps waiting for a person: manual tasks and manual undo tasks. */
                manual_steps?: number[];
                /** @description Store revision of the job's last write. */
                revision: components["schemas"]["Revision"];
                runner?: components["schemas"]["NodeId"] | null;
                /** @description Current state. */
                state: components["schemas"]["JobState"];
                /**
                 * Format: int32
                 * @description Number of steps.
                 */
                step_count: number;
                /**
                 * Format: int32
                 * @description Steps done or skipped.
                 */
                steps_done: number;
                /** @description The objects the job changes. */
                targets: components["schemas"]["ObjectRef"][];
                /** @description Translatable title. */
                title: components["schemas"]["MessageKey"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Prefix: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                alarm?: components["schemas"]["UtilizationAlarm"] | null;
                /** @description Allocation policy for next-free (IPAM-07). */
                alloc?: components["schemas"]["AllocPolicy"];
                /**
                 * @description The network in CIDR notation, without host bits.
                 * @example 192.0.2.0/24
                 */
                cidr: string;
                /** @description Identifier. */
                id: components["schemas"]["PrefixId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Supernet or network. */
                role: components["schemas"]["PrefixRole"];
                site?: components["schemas"]["SiteId"] | null;
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
                vlan?: components["schemas"]["VlanId"] | null;
                /** @description The VRF the prefix lives in. */
                vrf: components["schemas"]["VrfId"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_PrefixAddressItem: {
            /** @description The items of this page, at most `limit` of them. */
            items: ({
                /** @description An address object. */
                data: components["schemas"]["Address"];
                /** @enum {string} */
                type: "address";
            } | {
                /** @description Free addresses between two address objects. */
                data: {
                    /** @description First free address. */
                    first: string;
                    /** @description Last free address. */
                    last: string;
                    /** @description Number of free addresses, as a decimal string. */
                    size: string;
                };
                /** @enum {string} */
                type: "free";
            })[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Range: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /**
                 * @description First address, inclusive.
                 * @example 192.0.2.100
                 */
                first: string;
                /** @description Identifier. */
                id: components["schemas"]["RangeId"];
                /**
                 * @description Last address, inclusive.
                 * @example 192.0.2.199
                 */
                last: string;
                /**
                 * Format: int32
                 * @description DHCP lease time in seconds of a `dhcp_pool` range. Informational until Tenko DHCP
                 *     exists, and the source of the default move timeout (IPAM-19).
                 */
                lease_secs?: number | null;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description The containing prefix. */
                prefix: components["schemas"]["PrefixId"];
                /** @description What the range is for. */
                role: components["schemas"]["RangeRole"];
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_RoleInfo: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description What it grants. */
                description: string;
                /** @description The role. */
                name: components["schemas"]["RoleName"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_SessionSummary: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description When it started. */
                created_at: components["schemas"]["Timestamp"];
                /** @description Whether this is the session of the request. */
                current: boolean;
                /** @description When it ends unless used. */
                expires_at: components["schemas"]["Timestamp"];
                /** @description The session id. */
                id: components["schemas"]["SessionId"];
                /** @description The last recorded activity. */
                last_seen_at: components["schemas"]["Timestamp"];
                /** @description The client address at login. */
                source_ip?: string | null;
                /** @description Its strength. */
                strength: components["schemas"]["AuthStrength"];
                /** @description The client's user agent at login. */
                user_agent?: string | null;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Site: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description Matching Active Directory site name, for migration and DNS later. */
                ad_site?: string | null;
                /** @description Identifier. */
                id: components["schemas"]["SiteId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name. */
                name: string;
                parent?: components["schemas"]["SiteId"] | null;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Tenant: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description Identifier. */
                id: components["schemas"]["TenantId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Unique name. */
                name: string;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_TokenInfo: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description When it was created. */
                created_at: components["schemas"]["Timestamp"];
                expires_at?: components["schemas"]["Timestamp"] | null;
                /** @description The token id. */
                id: components["schemas"]["ApiTokenId"];
                last_used_at?: components["schemas"]["Timestamp"] | null;
                /** @description The name. */
                name: string;
                /** @description The first characters of the token. */
                prefix: string;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_UserInfo: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description The break-glass account. */
                break_glass: boolean;
                /** @description When the account was created. */
                created_at: components["schemas"]["Timestamp"];
                /** @description Disabled accounts cannot log in. */
                disabled: boolean;
                /** @description The display name. */
                display_name: string;
                /** @description The factors. */
                factors: components["schemas"]["FactorSummary"];
                /** @description The id. */
                id: components["schemas"]["UserId"];
                /** @description The fixed UI language. */
                language?: string | null;
                last_login_at?: components["schemas"]["Timestamp"] | null;
                lock?: components["schemas"]["AccountLock"] | null;
                /** @description The login name. */
                name: string;
                /** @description The password must be changed. */
                password_change_required: boolean;
                /** @description The revision for `If-Match`. */
                revision: components["schemas"]["Revision"];
                /** @description Global roles. */
                roles: components["schemas"]["RoleName"][];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Vlan: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description Identifier. */
                id: components["schemas"]["VlanId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name. */
                name: string;
                site?: components["schemas"]["SiteId"] | null;
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
                /**
                 * Format: int32
                 * @description VLAN id, 1 to 4094.
                 */
                vid: number;
                /**
                 * Format: int32
                 * @description VXLAN network identifier, if any.
                 */
                vni?: number | null;
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_Vrf: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description Identifier. */
                id: components["schemas"]["VrfId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name, unique within the tenant. */
                name: string;
                /** @description Route distinguisher, informational. */
                rd?: string | null;
                /** @description Owning tenant. */
                tenant: components["schemas"]["TenantId"];
            }[];
            /** @description Cursor of the next page; `null` on the last page. */
            next_cursor?: string | null;
            /** @description Store revision the page was read at. */
            revision: components["schemas"]["Revision"];
        };
        /** @description `POST /auth/password`. */
        PasswordChange: {
            current_password?: components["schemas"]["SecretString"] | null;
            /** @description The new password. */
            new_password: components["schemas"]["SecretString"];
        };
        /** @description The answer of a password change. */
        PasswordChanged: {
            /** @description The breached-password check. */
            breach_check: components["schemas"]["BreachStatus"];
            /** @description Other sessions of the account that were ended. */
            sessions_revoked: number;
        };
        /** @description `POST /auth/password/check`: live policy feedback. */
        PasswordCheck: {
            /** @description The candidate password. */
            password: components["schemas"]["SecretString"];
            profile?: components["schemas"]["Profile"] | null;
            /** @description The user name it is meant for (context-specific words), when not the caller's own. */
            user_name?: string | null;
        };
        /** @description The answer of `POST /auth/password/check`. */
        PasswordCheckResult: {
            /** @description Whether the password would be accepted. */
            acceptable: boolean;
            /** @description The breached-password check. */
            breach_check: components["schemas"]["BreachStatus"];
            /** @description The preset that applies. */
            policy: components["schemas"]["PasswordPolicy"];
            /** @description What is wrong with it. */
            violations: components["schemas"]["PolicyViolation"][];
        };
        /** @description `POST /auth/login/password`. */
        PasswordLogin: {
            /** @description The password or PIN. */
            password: components["schemas"]["SecretString"];
            /** @description The user name. */
            user_name: string;
        };
        /**
         * @description The password policy of a security profile (TGL-01).
         *
         *     The presets differ in length only. There are no composition rules (NIST SP 800-63B,
         *     section 3.1.1.2); the Custom preset adds an operator-chosen pattern. Serialized as an
         *     object tagged by `preset`: `{"preset": "standard"}`, or for Custom
         *     `{"preset": "custom", "min_length": 10, "max_length": 128, "pattern": "..."}`.
         */
        PasswordPolicy: {
            /** @enum {string} */
            preset: "pin";
        } | {
            /** @enum {string} */
            preset: "standard";
        } | {
            /** @enum {string} */
            preset: "hardened";
        } | (components["schemas"]["CustomPolicy"] & {
            /** @enum {string} */
            preset: "custom";
        });
        /** @description A human summary of a plan: counts per kind and action, warnings, and English lines. */
        PlanSummary: {
            /** @description Counts per kind and action, ordered by kind and action. */
            counts: components["schemas"]["SummaryCount"][];
            /** @description English lines such as `3 prefixes created`. */
            lines: string[];
            /** @description Physical writes in the batch. */
            mutations: number;
            /** @description Preconditions in the batch. */
            preconditions: number;
            /** @description Warning codes that still need an acknowledgement. */
            unacknowledged: string[];
            /** @description Warning counts by code. */
            warnings: {
                [key: string]: number;
            };
        };
        /**
         * @description The reviewable part of a plan: the dry-run answer of the API (API-09) and the import
         *     preview.
         */
        PlanView: {
            /**
             * Format: int64
             * @description The revision the plan was computed from.
             */
            base_revision: number;
            /** @description Every change with before and after. */
            changes: components["schemas"]["PlannedChange"][];
            /** @description The primary object of each command. */
            results: components["schemas"]["ObjectRef"][];
            /** @description Counts, warnings and summary lines. */
            summary: components["schemas"]["PlanSummary"];
            /** @description Warnings. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description A warning found while planning. */
        PlanWarning: {
            /** @description Whether the code was acknowledged in the options. */
            acknowledged?: boolean;
            /** @description Stable code, for example `ipam.prefix.nibble_boundary`. */
            code: string;
            /** @description English explanation. */
            message: string;
            object?: components["schemas"]["ObjectRef"] | null;
            /** @description Named parameters for the translated message. */
            params?: {
                [key: string]: string;
            };
            /** @description Whether the plan applies only after the code is acknowledged. */
            requires_ack?: boolean;
        };
        /** @description One change of one object. */
        PlannedChange: {
            /** @description What happens. */
            action: components["schemas"]["ChangeAction"];
            after?: components["schemas"]["IpamObject"] | null;
            before?: components["schemas"]["IpamObject"] | null;
            /**
             * @description Whether the change follows from another one (an address moving to a new, more
             *     specific prefix, interfaces deleted with their host).
             */
            derived?: boolean;
            /** @description Changed fields as text. */
            fields?: components["schemas"]["FieldChange"][];
            /** @description The object. */
            object: components["schemas"]["ObjectRef"];
        };
        /** @description One way a password breaks the policy. Each has a stable code under `auth.password.`. */
        PolicyViolation: {
            /** @enum {string} */
            kind: "too_short";
            /** @description The minimum length. */
            min: number;
        } | {
            /** @enum {string} */
            kind: "too_long";
            /** @description The maximum length. */
            max: number;
        } | {
            /** @enum {string} */
            kind: "pin_digits_only";
        } | {
            /** @enum {string} */
            kind: "trivial";
        } | {
            /** @description Which word. */
            context: components["schemas"]["ContextKind"];
            /** @enum {string} */
            kind: "context_specific";
        } | {
            /** @enum {string} */
            kind: "pattern_mismatch";
        } | {
            /**
             * Format: int64
             * @description How often it appears, when the source reports it.
             */
            count?: number | null;
            /** @enum {string} */
            kind: "breached";
        } | {
            /** @enum {string} */
            kind: "invalid_characters";
        };
        /** @description A prefix: a supernet (container) or a network (IPAM-02). */
        Prefix: {
            alarm?: components["schemas"]["UtilizationAlarm"] | null;
            /** @description Allocation policy for next-free (IPAM-07). */
            alloc?: components["schemas"]["AllocPolicy"];
            /**
             * @description The network in CIDR notation, without host bits.
             * @example 192.0.2.0/24
             */
            cidr: string;
            /** @description Identifier. */
            id: components["schemas"]["PrefixId"];
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description Supernet or network. */
            role: components["schemas"]["PrefixRole"];
            site?: components["schemas"]["SiteId"] | null;
            /** @description Lifecycle status. */
            status: components["schemas"]["Status"];
            vlan?: components["schemas"]["VlanId"] | null;
            /** @description The VRF the prefix lives in. */
            vrf: components["schemas"]["VrfId"];
        };
        /** @description One row of a prefix's address list: an address object or a free gap. */
        PrefixAddressItem: {
            /** @description An address object. */
            data: components["schemas"]["Address"];
            /** @enum {string} */
            type: "address";
        } | {
            /** @description Free addresses between two address objects. */
            data: {
                /** @description First free address. */
                first: string;
                /** @description Last free address. */
                last: string;
                /** @description Number of free addresses, as a decimal string. */
                size: string;
            };
            /** @enum {string} */
            type: "free";
        };
        /** Format: uuid */
        PrefixId: string;
        /** @description A new prefix. */
        PrefixInput: {
            alarm?: components["schemas"]["UtilizationAlarm"] | null;
            alloc?: components["schemas"]["AllocPolicy"] | null;
            /**
             * @description The network, without host bits.
             * @example 192.0.2.0/24
             */
            cidr: string;
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["PrefixId"] | null;
            role?: components["schemas"]["PrefixRole"] | null;
            site?: components["schemas"]["SiteId"] | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
            vlan?: components["schemas"]["VlanId"] | null;
            vrf?: components["schemas"]["VrfId"] | null;
        };
        /** @description Changes to a prefix. The VRF cannot change. */
        PrefixPatch: {
            alarm?: components["schemas"]["UtilizationAlarm"] | null;
            alloc?: components["schemas"]["AllocPolicy"] | null;
            /**
             * @description New network (resize or renumber); children, addresses and ranges must still fit.
             * @example 192.0.2.0/23
             */
            cidr?: string | null;
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            role?: components["schemas"]["PrefixRole"] | null;
            /** @description New site; `null` clears it. */
            site?: string | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
            /** @description New VLAN; `null` clears it. */
            vlan?: string | null;
        };
        /**
         * @description Role of a prefix (IPAM-02).
         * @enum {string}
         */
        PrefixRole: "supernet" | "network";
        /** @description Who performs an action. */
        Principal: {
            /** @description The user. */
            id: components["schemas"]["UserId"];
            /** @enum {string} */
            kind: "user";
            /** @description The session the request arrived on. */
            session: components["schemas"]["SessionId"];
            /** @description How strongly the session was authenticated. */
            strength: components["schemas"]["AuthStrength"];
        } | {
            /** @description The token. */
            id: components["schemas"]["ApiTokenId"];
            /** @enum {string} */
            kind: "token";
            /** @description The user who owns the token. */
            owner: components["schemas"]["UserId"];
        } | {
            /** @description The acting component. */
            component: components["schemas"]["SystemComponent"];
            /** @enum {string} */
            kind: "system";
            on_behalf_of?: components["schemas"]["UserId"] | null;
        } | {
            /** @description The node. */
            id: components["schemas"]["NodeId"];
            /** @enum {string} */
            kind: "node";
        };
        /**
         * @description The JSON body of every error response: RFC 9457 problem details plus the Tenko members
         *     `code`, `params` and `errors`.
         */
        ProblemDetails: {
            /** @description The stable, namespaced error code, for example `ipam.prefix.overlap`. */
            code: string;
            /** @description English explanation of this occurrence. */
            detail: string;
            /** @description Per-field errors of the request body. */
            errors?: components["schemas"]["FieldError"][];
            /** @description A URI reference that identifies this occurrence, when there is one. */
            instance?: string | null;
            /** @description Named parameters the UI uses to render a translated message. */
            params?: {
                [key: string]: string;
            };
            /**
             * Format: int32
             * @description The HTTP status code of the response.
             */
            status: number;
            /** @description Short English summary of the problem. */
            title: string;
            /**
             * @description The problem type. Always `about:blank` for now: the stable `code` identifies the
             *     problem, and `title` is the English summary of its status.
             * @example about:blank
             */
            type: string;
        };
        /**
         * @description A security profile (API-10).
         * @enum {string}
         */
        Profile: "home" | "standard" | "hardened" | "lab";
        /** @description A profile offered by the first-run wizard. */
        ProfileInfo: {
            /** @description Its banner state. */
            banner: components["schemas"]["Banner"];
            /** @description The profile. */
            profile: components["schemas"]["Profile"];
            /** @description Its toggle values. */
            settings: components["schemas"]["SecuritySettings"];
        };
        /** @description A range of addresses inside a prefix. */
        Range: {
            /**
             * @description First address, inclusive.
             * @example 192.0.2.100
             */
            first: string;
            /** @description Identifier. */
            id: components["schemas"]["RangeId"];
            /**
             * @description Last address, inclusive.
             * @example 192.0.2.199
             */
            last: string;
            /**
             * Format: int32
             * @description DHCP lease time in seconds of a `dhcp_pool` range. Informational until Tenko DHCP
             *     exists, and the source of the default move timeout (IPAM-19).
             */
            lease_secs?: number | null;
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description The containing prefix. */
            prefix: components["schemas"]["PrefixId"];
            /** @description What the range is for. */
            role: components["schemas"]["RangeRole"];
            /** @description Lifecycle status. */
            status: components["schemas"]["Status"];
        };
        /** Format: uuid */
        RangeId: string;
        /** @description A new range inside a network prefix. */
        RangeInput: {
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            /**
             * @description First address, inclusive.
             * @example 192.0.2.100
             */
            first: string;
            id?: components["schemas"]["RangeId"] | null;
            /**
             * @description Last address, inclusive.
             * @example 192.0.2.199
             */
            last: string;
            /** @description The network prefix. */
            prefix: components["schemas"]["PrefixId"];
            /** @description What the range is for. */
            role: components["schemas"]["RangeRole"];
            status?: components["schemas"]["Status"] | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
        };
        /** @description Changes to a range. The prefix cannot change. */
        RangePatch: {
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New first address. */
            first?: string | null;
            /** @description New last address. */
            last?: string | null;
            role?: components["schemas"]["RangeRole"] | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /**
         * @description Role of a range.
         * @enum {string}
         */
        RangeRole: "dhcp_pool" | "reserved" | "infrastructure";
        /** @description Body of `GET /health/ready` when the node serves requests. */
        Readiness: {
            /** @description Store revision the node has applied. */
            revision: components["schemas"]["Revision"];
            /** @description Always `ready`. */
            status: string;
        };
        /** @description New recovery codes, shown once. */
        RecoveryCodes: {
            /** @description The codes. */
            codes: components["schemas"]["SecretString"][];
        };
        /** @description A registration result from the browser (`RegistrationResponseJSON`). */
        RegistrationResponse: {
            /** @description `platform` or `cross-platform`, when the client reports it. */
            authenticatorAttachment?: string | null;
            /** @description Client extension results; ignored. */
            clientExtensionResults?: Record<string, never>;
            /** @description The credential id, base64url. */
            id: string;
            /** @description The credential id again, base64url. */
            rawId: string;
            /** @description The attestation response. */
            response: components["schemas"]["AttestationResponse"];
            /** @description Always `public-key`. */
            type: string;
        };
        /** Format: uuid */
        RequestId: string;
        /**
         * @description Options of an authentication ceremony, passed to
         *     `PublicKeyCredential.parseRequestOptionsFromJSON()`.
         */
        RequestOptions: {
            /** @description Allowed credentials; empty for a discoverable login. */
            allowCredentials?: components["schemas"]["CredentialDescriptor"][];
            /** @description The challenge, base64url. */
            challenge: string;
            /** @description Client hints such as `security-key`. */
            hints?: string[];
            /** @description The RP ID. */
            rpId: string;
            /**
             * Format: int32
             * @description Ceremony timeout in milliseconds.
             */
            timeout: number;
            /** @description `required`, `preferred` or `discouraged`. */
            userVerification: string;
        };
        /** @description The `data` of a `reset` event. Its SSE id is `revision`. */
        ResetData: {
            /** @description Why the client must reload. */
            reason: components["schemas"]["ResetReason"];
            /** @description Reload at this revision or later (`at_least` on list endpoints). */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description Why a `reset` event was sent: the client must reload its state at `revision` or later.
         * @enum {string}
         */
        ResetReason: "lagged" | "gap" | "journal";
        /**
         * Format: int64
         * @description Store revision: incremented by exactly one per applied write batch, store-wide. It is
         *     also the SSE event id (ADR 0008, ADR 0011).
         *
         *     `Revision(0)` is the empty store; the first batch commits as `Revision(1)`.
         */
        Revision: number;
        /** @description A role in `GET /roles`. */
        RoleInfo: {
            /** @description What it grants. */
            description: string;
            /** @description The role. */
            name: components["schemas"]["RoleName"];
        };
        /**
         * @description A global role.
         * @enum {string}
         */
        RoleName: "admin" | "operator" | "viewer";
        /** @description The ranges of one role inside a network. */
        RoleUsage: {
            /** @description The role. */
            role: components["schemas"]["RangeRole"];
            /** @description Addresses in ranges of this role. */
            size: string;
            /** @description Address objects inside them. */
            used: string;
        };
        /** @description `PUT /users/{id}/roles`. */
        RolesUpdate: {
            /** @description The new roles. */
            roles: components["schemas"]["RoleName"][];
        };
        /** @description The relying party as shown by the browser. */
        RpEntity: {
            /** @description The RP ID: the host name of the installation. */
            id: string;
            /** @description A human-readable name. */
            name: string;
        };
        /** @description One search hit. */
        SearchHit: {
            /** @description The object itself. */
            item: components["schemas"]["IpamObject"];
            /** @description A short label: the network, address or name. */
            label: string;
            /** @description The object. */
            object: components["schemas"]["ObjectRef"];
        };
        /**
         * @description A second factor that completes a password login.
         * @enum {string}
         */
        SecondFactorMethod: "totp" | "recovery" | "webauthn";
        /** Format: password */
        SecretString: string;
        /** @description The authentication part of the security settings: the profile and TGL-01 to TGL-07. */
        SecuritySettings: {
            /** @description TGL-06: breached-password check. */
            breach_check: components["schemas"]["BreachMode"];
            /** @description TGL-07: lockout. */
            lockout: components["schemas"]["LockoutMode"];
            /** @description TGL-02: MFA requirement. */
            mfa: components["schemas"]["MfaRequirement"];
            /** @description TGL-03: passkey required for administrators. */
            passkey_for_admins: boolean;
            /** @description TGL-01: password policy preset. */
            password_policy: components["schemas"]["PasswordPolicy"];
            /** @description The selected profile. */
            profile: components["schemas"]["Profile"];
            /** @description TGL-04: session lifetime. */
            session: components["schemas"]["SessionLifetime"];
            /**
             * Format: int32
             * @description TGL-05: API token maximum lifetime in days; `None` allows non-expiring tokens.
             */
            token_max_days?: number | null;
        };
        /** @description `GET /settings/security`. */
        SecuritySettingsView: {
            /** @description The warning banner. */
            banner: components["schemas"]["Banner"];
            revision?: components["schemas"]["Revision"] | null;
            /** @description The settings. */
            settings: components["schemas"]["SecuritySettings"];
            /** @description Each toggle with its profile default and markers. */
            toggles: components["schemas"]["ToggleState"][];
            /** @description Whether the vault holds operator secrets (the PIN coupling rule applies). */
            vault_has_operator_secrets: boolean;
        };
        /** @description Flags of a session that the UI acts on. */
        SessionFlags: {
            /** @description The break-glass account is in use. */
            break_glass: boolean;
            /** @description The profile requires a stronger factor than this session used; enrol one. */
            mfa_enrolment_required: boolean;
            /** @description The password no longer meets the policy and must be changed. */
            password_change_required: boolean;
        };
        /** Format: uuid */
        SessionId: string;
        /** @description `GET /auth/session` (IAM-08). */
        SessionInfo: {
            /** @description The absolute end. */
            absolute_expires_at: components["schemas"]["Timestamp"];
            /** @description The warning banner (API-10). */
            banner: components["schemas"]["Banner"];
            /** @description When the session started. */
            created_at: components["schemas"]["Timestamp"];
            /** @description The default UI language of the installation. */
            default_language?: string | null;
            /** @description When the session ends unless used (the earlier of the idle and absolute ends). */
            expires_at: components["schemas"]["Timestamp"];
            /** @description Flags. */
            flags: components["schemas"]["SessionFlags"];
            /** @description The selected profile. */
            profile: components["schemas"]["Profile"];
            /** @description The strength the profile requires of this account. */
            required_strength: components["schemas"]["AuthStrength"];
            /** @description Global roles. */
            roles: components["schemas"]["RoleName"][];
            /** @description The session id. */
            session_id: components["schemas"]["SessionId"];
            /** @description How strongly the session was authenticated. */
            strength: components["schemas"]["AuthStrength"];
            /** @description The account. */
            user: components["schemas"]["UserSummary"];
        };
        /** @description Session lifetimes (TGL-04). */
        SessionLifetime: {
            /**
             * Format: int64
             * @description Seconds from login until the session ends regardless of activity.
             */
            absolute_secs: number;
            /**
             * Format: int64
             * @description Seconds of inactivity that end the session.
             */
            idle_secs: number;
        };
        /** @description One session in `GET /auth/sessions`. */
        SessionSummary: {
            /** @description When it started. */
            created_at: components["schemas"]["Timestamp"];
            /** @description Whether this is the session of the request. */
            current: boolean;
            /** @description When it ends unless used. */
            expires_at: components["schemas"]["Timestamp"];
            /** @description The session id. */
            id: components["schemas"]["SessionId"];
            /** @description The last recorded activity. */
            last_seen_at: components["schemas"]["Timestamp"];
            /** @description The client address at login. */
            source_ip?: string | null;
            /** @description Its strength. */
            strength: components["schemas"]["AuthStrength"];
            /** @description The client's user agent at login. */
            user_agent?: string | null;
        };
        /**
         * @description A change of the security settings (`PATCH /settings/security`). A new profile resets
         *     every toggle to its values first; explicit toggles then apply on top.
         */
        SettingsPatch: {
            breach_check?: components["schemas"]["BreachMode"] | null;
            lockout?: components["schemas"]["LockoutMode"] | null;
            mfa?: components["schemas"]["MfaRequirement"] | null;
            /** @description TGL-03. */
            passkey_for_admins?: boolean | null;
            password_policy?: components["schemas"]["PasswordPolicy"] | null;
            profile?: components["schemas"]["Profile"] | null;
            session?: components["schemas"]["SessionLifetime"] | null;
            token_max_lifetime?: components["schemas"]["TokenMaxLifetime"] | null;
        };
        /** @description The first administrator in `POST /setup`. */
        SetupAdmin: {
            /** @description The display name. */
            display_name?: string | null;
            /** @description The login name. */
            name: string;
            /** @description The password or PIN, checked against the chosen profile's preset. */
            password: components["schemas"]["SecretString"];
        };
        /** @description `POST /setup` (API-10). */
        SetupRequest: {
            /** @description The first administrator. */
            admin: components["schemas"]["SetupAdmin"];
            /** @description The host name: TLS subject and WebAuthn RP ID; not an IP address (Q5). */
            host_name: string;
            /** @description The default UI language: `en` or `sv`. */
            language?: string;
            /** @description The security profile. */
            profile: components["schemas"]["Profile"];
            /** @description The one-time token from the console or log. */
            setup_token: components["schemas"]["SecretString"];
        };
        /** @description `GET /setup`. */
        SetupState: {
            /** @description Whether setup is still open. */
            open: boolean;
            /** @description The profiles to choose from (while open). */
            profiles?: components["schemas"]["ProfileInfo"][];
        };
        /** @description A site, optionally nested (IPAM-04). */
        Site: {
            /** @description Matching Active Directory site name, for migration and DNS later. */
            ad_site?: string | null;
            /** @description Identifier. */
            id: components["schemas"]["SiteId"];
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description Name. */
            name: string;
            parent?: components["schemas"]["SiteId"] | null;
        };
        /** Format: uuid */
        SiteId: string;
        /** @description A new site. */
        SiteInput: {
            /** @description Matching Active Directory site. */
            ad_site?: string | null;
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["SiteId"] | null;
            /** @description Unique name. */
            name: string;
            parent?: components["schemas"]["SiteId"] | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
        };
        /** @description Changes to a site. */
        SitePatch: {
            /** @description New Active Directory site; `null` clears it. */
            ad_site?: string | null;
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New name. */
            name?: string | null;
            /** @description New parent; `null` makes it a top-level site. */
            parent?: string | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /**
         * @description Sort direction of lists that only sort by their natural key.
         * @enum {string}
         */
        SortOrder: "asc" | "desc";
        /** @description When and by whom something happened. */
        Stamp: {
            /** @description The time (the proposer's request time). */
            at: components["schemas"]["Timestamp"];
            /** @description The principal. */
            by: components["schemas"]["Principal"];
        };
        /**
         * @description Lifecycle status (IPAM-05).
         * @enum {string}
         */
        Status: "planned" | "active" | "reserved" | "deprecated";
        /** @description A condition an administrator should look at. */
        StatusWarning: {
            /** @description Stable code, for example `sys.tls.certificate_expiring`. */
            code: string;
            /** @description English explanation. */
            detail: string;
            /** @description Parameters for the UI's translated message. */
            params?: {
                [key: string]: string;
            };
        };
        /** @description Namespaced step kind */
        StepKind: string;
        /** @description What a step would do, for the preview before apply (API-09). */
        StepPreview: {
            /** @description Message arguments. */
            args?: {
                [key: string]: string;
            };
            /** @description Objects the step changes. */
            changes?: components["schemas"]["ObjectRef"][];
            manual?: components["schemas"]["ManualTask"] | null;
            /** @description Translatable summary. */
            summary: components["schemas"]["MessageKey"];
            /** @description Warnings such as a `reserved` host without MAC (IPAM-18). */
            warnings?: components["schemas"]["CodedError"][];
        };
        /** @description Persisted state of one step. */
        StepRecord: {
            /**
             * Format: int32
             * @description Executions started so far.
             */
            attempts?: number;
            finished?: components["schemas"]["Timestamp"] | null;
            /**
             * Format: int32
             * @description Position in the spec.
             */
            index: number;
            /** @description The handler kind. */
            kind: components["schemas"]["StepKind"];
            output?: components["schemas"]["HexBytes"] | null;
            started?: components["schemas"]["Timestamp"] | null;
            /** @description Current state. */
            state: components["schemas"]["StepState"];
        };
        /** @description One step of a job. */
        StepSpec: {
            /** @description The handler kind. */
            kind: components["schemas"]["StepKind"];
            /** @description Handler parameters as CBOR, opaque to the engine. */
            params: components["schemas"]["HexBytes"];
            /**
             * Format: int64
             * @description Step timeout; `None` uses the job timeout.
             */
            timeout?: number | null;
        };
        /**
         * @description States of a step.
         *
         *     Adjacently tagged (`{"state": "...", "data": {...}}`) because waiting states carry
         *     IP addresses (see the encoding rules in `tenko_core::codec`).
         */
        StepState: {
            /** @enum {string} */
            state: "pending";
        } | {
            /** @enum {string} */
            state: "running";
        } | {
            /** @enum {string} */
            state: "done";
        } | {
            /** @enum {string} */
            state: "skipped";
        } | {
            /** @description Waiting for an observation. */
            data: {
                /** @description What must be observed. */
                condition: components["schemas"]["ObservationCondition"];
                /** @description When waiting stops and the job rolls back. */
                deadline: components["schemas"]["Timestamp"];
            };
            /** @enum {string} */
            state: "waiting_for_observation";
        } | {
            /** @description Waiting for a person. */
            data: {
                deadline?: components["schemas"]["Timestamp"] | null;
                /** @description The task. */
                task: components["schemas"]["ManualTask"];
            };
            /** @enum {string} */
            state: "waiting_for_manual";
        } | {
            /** @description Failed. */
            data: {
                /** @description The error. */
                error: components["schemas"]["CodedError"];
            };
            /** @enum {string} */
            state: "failed";
        } | {
            /** @enum {string} */
            state: "compensating";
        } | {
            /** @enum {string} */
            state: "compensated";
        } | {
            /** @description Compensation failed. */
            data: {
                /** @description The error. */
                error: components["schemas"]["CodedError"];
            };
            /** @enum {string} */
            state: "compensation_failed";
        };
        /**
         * @description The state of a step without its data, for events and summaries.
         * @enum {string}
         */
        StepStateKind: "pending" | "running" | "done" | "skipped" | "waiting_for_observation" | "waiting_for_manual" | "failed" | "compensating" | "compensated" | "compensation_failed";
        /** @description Summary of the store status. */
        StoreSummary: {
            /** @description Sequence number of the newest audit record. */
            audit_head: components["schemas"]["AuditSeq"];
            /**
             * Format: int64
             * @description Bytes of live data.
             */
            data_bytes: number;
            /**
             * Format: int64
             * @description Bytes on disk, when the store is persistent.
             */
            disk_bytes?: number | null;
            /**
             * Format: int64
             * @description Change sets in the journal.
             */
            journal_len: number;
            journal_oldest?: components["schemas"]["Revision"] | null;
            /**
             * Format: int64
             * @description Revisions behind the leader, when known.
             */
            lag?: number | null;
            leader?: components["schemas"]["NodeId"] | null;
            /** @description Last applied revision. */
            revision: components["schemas"]["Revision"];
            /** @description `memory`, `leader`, `follower`, `learner`, `candidate` or `shutdown`. */
            role: string;
        };
        /** @description How many objects of a kind a plan changes in one way. */
        SummaryCount: {
            /** @description The action. */
            action: components["schemas"]["ChangeAction"];
            /** @description How many. */
            count: number;
            /** @description The object kind. */
            kind: components["schemas"]["ObjectKind"];
        };
        /**
         * @description Components that act as [`Principal::System`].
         * @enum {string}
         */
        SystemComponent: "setup" | "api" | "auth" | "vault" | "store" | "ipam" | "import" | "jobs" | "reconciler" | "connector" | "scan" | "cluster";
        /** @description Body of `GET /system/status`. */
        SystemStatus: {
            /** @description This node. */
            node: components["schemas"]["NodeStatus"];
            /** @description When the API started. */
            started_at: components["schemas"]["Timestamp"];
            /** @description The replicated store as this node sees it. */
            store: components["schemas"]["StoreSummary"];
            tls?: components["schemas"]["TlsStatus"] | null;
            /** @description Whether the build embeds the real web UI or the development placeholder. */
            ui: components["schemas"]["UiStatus"];
            /**
             * Format: int64
             * @description Seconds since the API started.
             */
            uptime_seconds: number;
            /** @description Version of the server. */
            version: string;
            /**
             * @description Conditions an administrator should look at, for example a certificate close to
             *     expiry or plain HTTP in the Lab profile.
             */
            warnings: components["schemas"]["StatusWarning"][];
        };
        /**
         * @description A tag (IPAM-08): 1 to 64 characters, no control characters, surrounding whitespace
         *     removed.
         */
        Tag: string;
        /** @description A tag and how many live objects carry it. */
        TagCount: {
            /** @description Objects per kind. */
            by_kind: {
                [key: string]: number;
            };
            /**
             * Format: int64
             * @description Objects carrying it.
             */
            count: number;
            /** @description The tag. */
            tag: string;
        };
        /** @description A tenant (IPAM-01). */
        Tenant: {
            /** @description Identifier. */
            id: components["schemas"]["TenantId"];
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description Unique name. */
            name: string;
        };
        /** Format: uuid */
        TenantId: string;
        /** @description A new tenant. */
        TenantInput: {
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["TenantId"] | null;
            /** @description Unique name. */
            name: string;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
        };
        /** @description Changes to a tenant. */
        TenantPatch: {
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New name. */
            name?: string | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /**
         * Format: date-time
         * @description RFC 3339 date and time in UTC
         */
        Timestamp: string;
        /**
         * @description How the listener secures connections (OPS-22, TGL-08).
         * @enum {string}
         */
        TlsMode: "internal_ca" | "imported" | "reverse_proxy" | "plain";
        /** @description TLS status of the listener. */
        TlsStatus: {
            certificate?: components["schemas"]["CertificateStatus"] | null;
            /** @description Whether HTTPS responses carry `Strict-Transport-Security`. */
            hsts: boolean;
            /** @description Lowest TLS version accepted (`1.2` or `1.3`), when the listener terminates TLS. */
            min_version?: string | null;
            /** @description The TLS mode. */
            mode: components["schemas"]["TlsMode"];
            /** @description Whether the PROXY protocol is read from trusted proxies. */
            proxy_protocol: boolean;
            /** @description Trusted reverse proxy networks (CIDR). */
            trusted_proxies: string[];
        };
        /** @description One toggle as reported to the UI. */
        ToggleState: {
            /** @description Whether the value differs from the profile. */
            deviates: boolean;
            /** @description The toggle id, for example `TGL-04`. */
            id: string;
            /** @description The value of the selected profile. */
            profile_default: Record<string, never>;
            /** @description The setting name in [`SecuritySettings`], for example `session`. */
            setting: string;
            /** @description The current value. */
            value: Record<string, never>;
            /** @description Whether the value is weaker than the Home baseline (shown as a warning banner). */
            weaker_than_home: boolean;
        };
        /** @description `POST /auth/tokens`. */
        TokenCreate: {
            /**
             * Format: int32
             * @description Lifetime in days; defaults to the TGL-05 maximum (or no expiry where it allows).
             */
            expires_in_days?: number | null;
            /** @description A name for the token. */
            name: string;
        };
        /** @description A personal token without its secret. */
        TokenInfo: {
            /** @description When it was created. */
            created_at: components["schemas"]["Timestamp"];
            expires_at?: components["schemas"]["Timestamp"] | null;
            /** @description The token id. */
            id: components["schemas"]["ApiTokenId"];
            last_used_at?: components["schemas"]["Timestamp"] | null;
            /** @description The name. */
            name: string;
            /** @description The first characters of the token. */
            prefix: string;
        };
        /** @description The TGL-05 value in a patch. */
        TokenMaxLifetime: {
            /**
             * Format: int32
             * @description At most this many days.
             */
            days: number;
        } | "unlimited";
        /**
         * @description An event topic. `GET /events?topics=ipam,jobs` subscribes to a subset; no `topics`
         *     parameter subscribes to all of them.
         * @enum {string}
         */
        Topic: "ipam" | "jobs" | "audit" | "import" | "system" | "admin";
        /**
         * @description The HMAC hash of a TOTP configuration (RFC 6238 section 1.2).
         * @enum {string}
         */
        TotpAlgorithm: "sha1" | "sha256" | "sha512";
        /** @description `POST /auth/totp/enroll/finish`. */
        TotpEnrolFinish: {
            /** @description A current code from the authenticator app. */
            code: components["schemas"]["SecretString"];
            /** @description From the start step. */
            enrolment_id: string;
        };
        /** @description The answer of `POST /auth/totp/enroll/start`. The secret is shown once. */
        TotpEnrolment: {
            /** @description Pass this to the finish step. */
            enrolment_id: string;
            /** @description The `otpauth://` URI for a QR code. */
            otpauth_uri: components["schemas"]["SecretString"];
            /** @description The code parameters. */
            params: components["schemas"]["TotpParams"];
            /** @description The seed in base32, for manual entry. */
            secret: components["schemas"]["SecretString"];
        };
        /**
         * @description The parameters of a TOTP enrolment.
         *
         *     The secret is not part of the parameters. Stored parameters can be checked with
         *     [`TotpParams::validate`]; [`verify`] refuses parameters that fail the check.
         */
        TotpParams: {
            /** @description The HMAC hash. */
            algorithm: components["schemas"]["TotpAlgorithm"];
            /**
             * Format: int32
             * @description The number of digits of a code, 6 to 8.
             */
            digits: number;
            /**
             * Format: int64
             * @description The length of a time step in seconds.
             */
            period: number;
            /**
             * Format: int64
             * @description How many steps either side of the current one [`verify`] accepts.
             */
            skew: number;
        };
        /**
         * @description One row of a job's transition log. Every transition is also part of an audited write
         *     batch (IPAM-17).
         */
        Transition: {
            /**
             * @description The job action, for [`TransitionEvent::Job`]: `start`, `wait`, `resume`, `complete`,
             *     `roll_back`, `cancel`, `finish_rollback`, `finish_cancel` or `fail`.
             */
            action?: string | null;
            /** @description When it happened. */
            at: components["schemas"]["Timestamp"];
            /** @description Who caused it: the submitting or acting principal, or the job engine. */
            by: components["schemas"]["Principal"];
            /** @description What happened. */
            event: components["schemas"]["TransitionEvent"];
            from?: components["schemas"]["JobState"] | null;
            /** @description The note of a completed manual task. */
            note?: string | null;
            request?: components["schemas"]["RequestId"] | null;
            runner?: components["schemas"]["NodeId"] | null;
            /**
             * Format: int32
             * @description Position in the job's log, from 0.
             */
            seq: number;
            /** @description The job state after the transition. */
            state: components["schemas"]["JobState"];
            /**
             * Format: int32
             * @description The step, for [`TransitionEvent::Step`].
             */
            step?: number | null;
            step_state?: components["schemas"]["StepState"] | null;
        };
        /**
         * @description What a transition row records.
         * @enum {string}
         */
        TransitionEvent: "submitted" | "job" | "step" | "claimed" | "cancel_requested";
        /** @description One prefix of the flattened tree (pre-order). */
        TreeNode: {
            alarm?: components["schemas"]["UtilizationAlarm"] | null;
            /**
             * Format: int32
             * @description Direct child prefixes.
             */
            children: number;
            /**
             * @description The network.
             * @example 192.0.2.0/24
             */
            cidr: string;
            /**
             * Format: int32
             * @description Depth below the first level of the answer (0 for its top level).
             */
            depth: number;
            /** @description Description. */
            description?: string | null;
            /** @description The prefix. */
            id: components["schemas"]["PrefixId"];
            /** @description Alarm level now. */
            level: components["schemas"]["AlarmLevel"];
            parent?: components["schemas"]["PrefixId"] | null;
            /** @description Supernet or network. */
            role: components["schemas"]["PrefixRole"];
            site?: components["schemas"]["SiteId"] | null;
            /** @description Status. */
            status: components["schemas"]["Status"];
            /** @description Utilization. */
            utilization: components["schemas"]["UtilizationView"];
            vlan?: components["schemas"]["VlanId"] | null;
        };
        /** @description The prefix tree of one VRF (`GET /prefixes/tree`). */
        TreeResponse: {
            /**
             * @description The prefixes in pre-order, each with depth, parent, child count, utilization and
             *     alarm level.
             */
            nodes: components["schemas"]["TreeNode"][];
            /**
             * Format: int64
             * @description The store revision the tree is at least as new as; subscribe to events from here.
             */
            revision: number;
            vrf?: components["schemas"]["VrfId"] | null;
        };
        /** @description Which web UI the binary serves. */
        UiStatus: {
            /** @description The UI is served from a directory (`--ui-dir`, development). */
            from_directory: boolean;
            /** @description The development placeholder page instead of the web UI (`TENKO_UI_STUB=1`). */
            stub: boolean;
        };
        /** @description Updates an address. */
        UpdateAddress: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["AddressId"];
            /** @description The changes. */
            patch: components["schemas"]["AddressPatch"];
        };
        /** @description Updates a custom field definition. */
        UpdateCustomField: {
            /**
             * Format: int64
             * @description The revision of the definition the caller read (`If-Match`).
             */
            expected?: number | null;
            /** @description The key. */
            key: components["schemas"]["FieldKey"];
            /** @description The changes. */
            patch: components["schemas"]["CustomFieldPatch"];
        };
        /** @description Updates a host. */
        UpdateHost: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["HostId"];
            /** @description The changes. */
            patch: components["schemas"]["HostPatch"];
        };
        /** @description Updates an interface. */
        UpdateInterface: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["InterfaceId"];
            /** @description The changes. */
            patch: components["schemas"]["InterfacePatch"];
        };
        /** @description Updates a prefix. */
        UpdatePrefix: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["PrefixId"];
            /** @description The changes. */
            patch: components["schemas"]["PrefixPatch"];
        };
        /** @description Updates a range. */
        UpdateRange: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["RangeId"];
            /** @description The changes. */
            patch: components["schemas"]["RangePatch"];
        };
        /** @description Updates a site. */
        UpdateSite: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["SiteId"];
            /** @description The changes. */
            patch: components["schemas"]["SitePatch"];
        };
        /** @description Updates a tenant. */
        UpdateTenant: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["TenantId"];
            /** @description The changes. */
            patch: components["schemas"]["TenantPatch"];
        };
        /** @description Updates a VLAN. */
        UpdateVlan: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["VlanId"];
            /** @description The changes. */
            patch: components["schemas"]["VlanPatch"];
        };
        /** @description Updates a VRF. */
        UpdateVrf: {
            /**
             * Format: int64
             * @description The revision the caller read (`If-Match`); the plan fails when it differs.
             */
            expected?: number | null;
            /** @description The object. */
            id: components["schemas"]["VrfId"];
            /** @description The changes. */
            patch: components["schemas"]["VrfPatch"];
        };
        /** @description `POST /users`. */
        UserCreate: {
            /** @description The display name; defaults to the login name. */
            display_name?: string | null;
            /** @description A fixed UI language. */
            language?: string | null;
            /** @description The login name: 1 to 64 characters, no spaces or control characters. */
            name: string;
            password?: components["schemas"]["SecretString"] | null;
            /** @description Global roles. */
            roles: components["schemas"]["RoleName"][];
        };
        /** @description The account a credential is created for. */
        UserEntity: {
            /** @description The display name. */
            displayName: string;
            /** @description The user handle: the 16 bytes of the user's UUID, base64url. */
            id: string;
            /** @description The user name. */
            name: string;
        };
        /** Format: uuid */
        UserId: string;
        /** @description A user as administrators see it. */
        UserInfo: {
            /** @description The break-glass account. */
            break_glass: boolean;
            /** @description When the account was created. */
            created_at: components["schemas"]["Timestamp"];
            /** @description Disabled accounts cannot log in. */
            disabled: boolean;
            /** @description The display name. */
            display_name: string;
            /** @description The factors. */
            factors: components["schemas"]["FactorSummary"];
            /** @description The id. */
            id: components["schemas"]["UserId"];
            /** @description The fixed UI language. */
            language?: string | null;
            last_login_at?: components["schemas"]["Timestamp"] | null;
            lock?: components["schemas"]["AccountLock"] | null;
            /** @description The login name. */
            name: string;
            /** @description The password must be changed. */
            password_change_required: boolean;
            /** @description The revision for `If-Match`. */
            revision: components["schemas"]["Revision"];
            /** @description Global roles. */
            roles: components["schemas"]["RoleName"][];
        };
        /** @description The account of a session. */
        UserSummary: {
            /** @description The display name. */
            display_name: string;
            /** @description The user id. */
            id: components["schemas"]["UserId"];
            /** @description The fixed UI language, if any. */
            language?: string | null;
            /** @description The login name. */
            name: string;
        };
        /** @description `PATCH /users/{id}`. */
        UserUpdate: {
            /** @description Disable or enable the account. */
            disabled?: boolean | null;
            /** @description A new display name. */
            display_name?: string | null;
            /** @description A fixed UI language; an empty string removes it. */
            language?: string | null;
            password?: components["schemas"]["SecretString"] | null;
        };
        /** @description Utilization alarm thresholds of a prefix in percent (IPAM-10). */
        UtilizationAlarm: {
            /**
             * Format: int32
             * @description Critical threshold.
             */
            crit_pct: number;
            /**
             * Format: int32
             * @description Warning threshold.
             */
            warn_pct: number;
        };
        /**
         * @description Utilization as the API shows it. Counts are decimal strings because IPv6 sizes exceed
         *     JSON's exact integers.
         */
        UtilizationView: {
            /** @description Ranges per role. */
            by_role: components["schemas"]["RoleUsage"][];
            /**
             * @description Addresses that can be used.
             * @example 254
             */
            capacity: string;
            /**
             * @description Addresses covered by child prefixes.
             * @example 0
             */
            covered: string;
            /**
             * @description Addresses left.
             * @example 142
             */
            free: string;
            /**
             * Format: double
             * @description `used + reserved` as a percentage of the capacity, one decimal.
             * @example 44.1
             */
            percent: number;
            /**
             * @description Addresses held by ranges.
             * @example 100
             */
            reserved: string;
            /**
             * @description Addresses in use (for a supernet: covered by children or used directly).
             * @example 12
             */
            used: string;
        };
        /** @description A VLAN (IPAM-03). */
        Vlan: {
            /** @description Identifier. */
            id: components["schemas"]["VlanId"];
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description Name. */
            name: string;
            site?: components["schemas"]["SiteId"] | null;
            /** @description Lifecycle status. */
            status: components["schemas"]["Status"];
            /**
             * Format: int32
             * @description VLAN id, 1 to 4094.
             */
            vid: number;
            /**
             * Format: int32
             * @description VXLAN network identifier, if any.
             */
            vni?: number | null;
        };
        /** Format: uuid */
        VlanId: string;
        /** @description A new VLAN. */
        VlanInput: {
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["VlanId"] | null;
            /** @description Name. */
            name: string;
            site?: components["schemas"]["SiteId"] | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
            /**
             * Format: int32
             * @description VLAN id, 1 to 4094, unique per site.
             */
            vid: number;
            /**
             * Format: int32
             * @description VXLAN network identifier, up to 16,777,215.
             */
            vni?: number | null;
        };
        /** @description Changes to a VLAN. */
        VlanPatch: {
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New name. */
            name?: string | null;
            /** @description New site; `null` makes it global. */
            site?: string | null;
            status?: components["schemas"]["Status"] | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
            /**
             * Format: int32
             * @description New VLAN id.
             */
            vid?: number | null;
            /**
             * Format: int32
             * @description New VNI; `null` clears it.
             */
            vni?: number | null;
        };
        /**
         * @description A VRF: an independent address space inside a tenant (IPAM-01). Prefixes overlap only
         *     across VRFs (IPAM-23).
         */
        Vrf: {
            /** @description Identifier. */
            id: components["schemas"]["VrfId"];
            /** @description Metadata. */
            meta: components["schemas"]["Meta"];
            /** @description Name, unique within the tenant. */
            name: string;
            /** @description Route distinguisher, informational. */
            rd?: string | null;
            /** @description Owning tenant. */
            tenant: components["schemas"]["TenantId"];
        };
        /** Format: uuid */
        VrfId: string;
        /** @description A new VRF. */
        VrfInput: {
            /** @description Custom field values (IPAM-08). */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            };
            /** @description Free text. */
            description?: string | null;
            id?: components["schemas"]["VrfId"] | null;
            /** @description Name, unique within the tenant. */
            name: string;
            /** @description Route distinguisher. */
            rd?: string | null;
            /** @description Tags (IPAM-08). */
            tags?: components["schemas"]["Tag"][];
            tenant?: components["schemas"]["TenantId"] | null;
        };
        /** @description Changes to a VRF. The tenant cannot change. */
        VrfPatch: {
            /** @description Sets custom field values; `null` removes a value. */
            custom?: {
                [key: string]: components["schemas"]["CustomValue"];
            } | null;
            /** @description Replaces the description; `null` clears it. */
            description?: string | null;
            /** @description New name. */
            name?: string | null;
            /** @description New route distinguisher; `null` clears it. */
            rd?: string | null;
            /** @description Replaces the tags. */
            tags?: components["schemas"]["Tag"][] | null;
        };
        /** @description `POST /auth/webauthn/login/finish`. */
        WebAuthnLoginFinish: {
            /** @description From the start step. */
            ceremony_id: string;
            /** @description The browser's result. */
            credential: components["schemas"]["AuthenticationResponse"];
        };
        /** @description Options of a WebAuthn login. */
        WebAuthnLoginOptions: {
            /** @description Pass this to the finish step. */
            ceremony_id: string;
            /** @description The options for `navigator.credentials.get()`. */
            public_key: components["schemas"]["RequestOptions"];
        };
        /** @description `POST /auth/webauthn/login/start`. */
        WebAuthnLoginStart: {
            /** @description The challenge of a password login that this passkey completes. */
            challenge_id?: string | null;
            /**
             * @description A user name for a login with that account's credentials; absent for a
             *     discoverable login.
             */
            user_name?: string | null;
        };
        /** @description `POST /auth/webauthn/register/finish`. */
        WebAuthnRegisterFinish: {
            /** @description From the start step. */
            ceremony_id: string;
            /** @description The browser's result. */
            credential: components["schemas"]["RegistrationResponse"];
        };
        /** @description Options of a WebAuthn registration. */
        WebAuthnRegisterOptions: {
            /** @description Pass this to the finish step. */
            ceremony_id: string;
            /** @description The options for `navigator.credentials.create()`. */
            public_key: components["schemas"]["CreationOptions"];
        };
        /** @description `POST /auth/webauthn/register/start`. */
        WebAuthnRegisterStart: {
            /** @description A label for the credential, for example `YubiKey 5` or `Laptop`. */
            label?: string | null;
            /** @description Ask for a security key with `direct` attestation (needed for break-glass). */
            security_key?: boolean;
        };
        /** @description The answer of a write. */
        WriteResponse_Address: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description An IP address object. */
            item?: {
                dns_name?: components["schemas"]["Fqdn"] | null;
                /** @description Identifier. */
                id: components["schemas"]["AddressId"];
                interface?: components["schemas"]["InterfaceId"] | null;
                /**
                 * @description The address.
                 * @example 192.0.2.10
                 */
                ip: string;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description The most specific prefix containing the address. */
                prefix: components["schemas"]["PrefixId"];
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
                /** @description The VRF. */
                vrf: components["schemas"]["VrfId"];
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_CustomFieldDef: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description Definition of a custom field (IPAM-08). */
            item?: {
                /** @description Object kinds the field applies to. */
                applies_to: components["schemas"]["ObjectKind"][];
                /** @description Identifier, so the definition can be audited and referenced. */
                id: components["schemas"]["CustomFieldId"];
                /** @description The key used in [`Meta::custom`]. */
                key: components["schemas"]["FieldKey"];
                /** @description Value type. */
                kind: components["schemas"]["CustomKind"];
                /** @description Whether every object of those kinds must have a value. */
                required?: boolean;
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Host: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A host: the unit of intent (IPAM-12). */
            item?: {
                /** @description Identifier. */
                id: components["schemas"]["HostId"];
                /** @description Stops all automation for the host (IPAM-16). */
                lock?: boolean;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description What IPAM may do with the host (IPAM-14). */
                mode: components["schemas"]["AssignmentMode"];
                /** @description Name. */
                name: components["schemas"]["HostName"];
                site?: components["schemas"]["SiteId"] | null;
                /** @description Owning tenant. */
                tenant: components["schemas"]["TenantId"];
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Interface: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A network interface of a host. */
            item?: {
                client_id?: components["schemas"]["HexBytes"] | null;
                duid?: components["schemas"]["Duid"] | null;
                /** @description Owning host. */
                host: components["schemas"]["HostId"];
                /** @description Identifier. */
                id: components["schemas"]["InterfaceId"];
                mac?: components["schemas"]["MacAddr"] | null;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name, such as `eth0`. */
                name: string;
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Prefix: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A prefix: a supernet (container) or a network (IPAM-02). */
            item?: {
                alarm?: components["schemas"]["UtilizationAlarm"] | null;
                /** @description Allocation policy for next-free (IPAM-07). */
                alloc?: components["schemas"]["AllocPolicy"];
                /**
                 * @description The network in CIDR notation, without host bits.
                 * @example 192.0.2.0/24
                 */
                cidr: string;
                /** @description Identifier. */
                id: components["schemas"]["PrefixId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Supernet or network. */
                role: components["schemas"]["PrefixRole"];
                site?: components["schemas"]["SiteId"] | null;
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
                vlan?: components["schemas"]["VlanId"] | null;
                /** @description The VRF the prefix lives in. */
                vrf: components["schemas"]["VrfId"];
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Range: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A range of addresses inside a prefix. */
            item?: {
                /**
                 * @description First address, inclusive.
                 * @example 192.0.2.100
                 */
                first: string;
                /** @description Identifier. */
                id: components["schemas"]["RangeId"];
                /**
                 * @description Last address, inclusive.
                 * @example 192.0.2.199
                 */
                last: string;
                /**
                 * Format: int32
                 * @description DHCP lease time in seconds of a `dhcp_pool` range. Informational until Tenko DHCP
                 *     exists, and the source of the default move timeout (IPAM-19).
                 */
                lease_secs?: number | null;
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description The containing prefix. */
                prefix: components["schemas"]["PrefixId"];
                /** @description What the range is for. */
                role: components["schemas"]["RangeRole"];
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Site: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A site, optionally nested (IPAM-04). */
            item?: {
                /** @description Matching Active Directory site name, for migration and DNS later. */
                ad_site?: string | null;
                /** @description Identifier. */
                id: components["schemas"]["SiteId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name. */
                name: string;
                parent?: components["schemas"]["SiteId"] | null;
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Tenant: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A tenant (IPAM-01). */
            item?: {
                /** @description Identifier. */
                id: components["schemas"]["TenantId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Unique name. */
                name: string;
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Vlan: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /** @description A VLAN (IPAM-03). */
            item?: {
                /** @description Identifier. */
                id: components["schemas"]["VlanId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name. */
                name: string;
                site?: components["schemas"]["SiteId"] | null;
                /** @description Lifecycle status. */
                status: components["schemas"]["Status"];
                /**
                 * Format: int32
                 * @description VLAN id, 1 to 4094.
                 */
                vid: number;
                /**
                 * Format: int32
                 * @description VXLAN network identifier, if any.
                 */
                vni?: number | null;
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description The answer of a write. */
        WriteResponse_Vrf: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            /**
             * @description A VRF: an independent address space inside a tenant (IPAM-01). Prefixes overlap only
             *     across VRFs (IPAM-23).
             */
            item?: {
                /** @description Identifier. */
                id: components["schemas"]["VrfId"];
                /** @description Metadata. */
                meta: components["schemas"]["Meta"];
                /** @description Name, unique within the tenant. */
                name: string;
                /** @description Route distinguisher, informational. */
                rd?: string | null;
                /** @description Owning tenant. */
                tenant: components["schemas"]["TenantId"];
            };
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description Whether an earlier result was returned for a repeated `Idempotency-Key`. */
            replayed: boolean;
            /**
             * Format: int64
             * @description The revision that committed the change; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
    };
    responses: never;
    parameters: never;
    requestBodies: never;
    headers: never;
    pathItems: never;
}
export type $defs = Record<string, never>;
export interface operations {
    list_addresses: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only addresses with one of these statuses: `planned`, `active`, `reserved` or `deprecated`. Repeat the parameter or separate the values with commas. */
                status?: string;
                /** @description Only addresses of this VRF (identifier). */
                vrf?: string;
                /** @description Only addresses inside this network, for example `192.0.2.0/24`. A bare address is a host network. Host bits must be zero. */
                within?: string;
                /** @description Only addresses whose most specific prefix is this prefix (identifier). */
                prefix?: string;
                /** @description Only addresses assigned to this interface (identifier). */
                interface?: string;
                /** @description Only addresses assigned to an interface of this host (identifier). */
                host?: string;
                /** @description Only addresses that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the address, the DNS name, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-updated,ip`. Fields: `ip` (the default), `dns_name`, `status`, `created`, `updated`. */
                sort?: string;
                /** @description Deleted addresses: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of addresses */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Address"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_address: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AddressInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description The new address, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The address exists in the VRF, no prefix contains it, it is a network or broadcast address, a DHCP pool covers it for a reserved host, the VRF or interface is missing, or the identifier is in use (`ipam.address.duplicate`, `ipam.address.no_prefix`, `ipam.address.network_or_broadcast`, `ipam.address.in_dhcp_pool`, `ipam.reference_missing`, `ipam.id_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host of the interface is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_addresses: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_address: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Address identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The address, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Address"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such address (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_address: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Address identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted address (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such address (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The address is deleted already (`ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host of the interface is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_address: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Address identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["AddressPatch"];
            };
        };
        responses: {
            /** @description The changed address, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description Invalid body or parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such address (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The new address exists in the VRF or no prefix contains it, the status change is not allowed, the interface is missing, or the address is deleted (`ipam.address.duplicate`, `ipam.address.no_prefix`, `ipam.status.transition`, `ipam.reference_missing`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host of the interface is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_address_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the address */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_address: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the address */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_audit: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes). */
                at_least?: number;
                /** @description Principal subject, for example `user:<uuid>`, `token:<uuid>` or `system:api`. */
                principal?: string;
                /**
                 * @description Audit action, exact (`ipam.prefix.create`) or a namespace prefix ending with a dot
                 *     (`ipam.` or `ipam.prefix.`).
                 */
                action?: string;
                /** @description Object reference `kind:<uuid>`, or a bare kind such as `prefix`. */
                object?: string;
                /** @description Outcome: `success`, `denied` or `failed`. */
                outcome?: string;
                /** @description Records at or after this time (RFC 3339). */
                from?: components["schemas"]["Timestamp"];
                /** @description Records before this time (RFC 3339). */
                to?: components["schemas"]["Timestamp"];
                /** @description `desc` (newest first, the default) or `asc`. */
                order?: components["schemas"]["SortOrder"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of audit records */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_AuditRecord"];
                };
            };
            /** @description Malformed filter, limit or cursor */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    verify_audit: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The verification report; `intact` is false when the chain is broken */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditVerifyReport"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_audit_record: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Sequence number of the audit record, from 1 */
                seq: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The audit record */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["AuditRecord"];
                };
            };
            /** @description The sequence number is not a positive integer */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No record has this sequence number */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    login_password: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PasswordLogin"];
            };
        };
        responses: {
            /** @description The login is complete (`status: authenticated`) or a second factor is required (`status: second_factor`) */
            200: {
                headers: {
                    /** @description The session cookie `tenko_session` (HttpOnly, SameSite=Strict, Secure); only when the login is complete */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginResponse"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The user name or password was not accepted (`auth.invalid_credentials`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many failed attempts, or the account is locked (`auth.throttled`); `Retry-After` gives the seconds */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    login_recovery: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CodeLogin"];
            };
        };
        responses: {
            /** @description The login is complete; the session cookie is set */
            200: {
                headers: {
                    /** @description The session cookie `tenko_session` */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginResponse"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the challenge is unknown or expired (`auth.challenge_invalid`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The code was not accepted (`auth.invalid_credentials`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many failed attempts (`auth.throttled`); `Retry-After` gives the seconds */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    login_totp: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CodeLogin"];
            };
        };
        responses: {
            /** @description The login is complete; the session cookie is set */
            200: {
                headers: {
                    /** @description The session cookie `tenko_session` */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginResponse"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the challenge is unknown or expired (`auth.challenge_invalid`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The code was not accepted (`auth.invalid_credentials`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many failed attempts (`auth.throttled`); `Retry-After` gives the seconds */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    logout: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The session ended */
            204: {
                headers: {
                    /** @description Removes the session cookie (`Max-Age=0`) */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    change_password: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PasswordChange"];
            };
        };
        responses: {
            /** @description The password changed; the other sessions ended */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PasswordChanged"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The current password is wrong (`auth.password.incorrect`) or the account is the break-glass account (`auth.break_glass.hardware_key_only`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The new password breaks the policy (`auth.password.policy`, with the violations in `errors`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many wrong current passwords (`auth.throttled`); `Retry-After` gives the seconds */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    check_password: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PasswordCheck"];
            };
        };
        responses: {
            /** @description Whether the password would be accepted, and why not */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PasswordCheckResult"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Setup has completed and the request carries no valid session or token (`auth.unauthenticated`, `auth.session_expired`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    regenerate_recovery_codes: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The new codes; the old ones no longer work */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RecoveryCodes"];
                };
            };
            /** @description The account has neither TOTP nor a passkey (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The action needs a fresh authentication (`auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_session: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The session */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SessionInfo"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_sessions: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every session of the user; `current` marks the session of the request */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_SessionSummary"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    revoke_session: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Session identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The session ended */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is not a UUID (`sys.invalid_value`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The user has no such session (`auth.session.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_tokens: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every token of the user */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_TokenInfo"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_token: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TokenCreate"];
            };
        };
        responses: {
            /** @description The token: its secret (`tnk_...`, shown once) and its metadata */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CreatedToken"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the name or lifetime is invalid (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The session is not strong enough (`auth.step_up_required`) or is the break-glass session (`auth.break_glass.hardware_key_only`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The lifetime exceeds the maximum of the profile (`auth.token.lifetime_exceeded`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    revoke_token: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Token identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The token was revoked */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is not a UUID (`sys.invalid_value`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such token (`auth.token.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    remove_totp: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description TOTP was removed */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The action needs a fresh authentication (`auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description TOTP is not enrolled (`auth.totp.not_enrolled`) or the profile requires it (`auth.factor.last_required`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    totp_enroll_finish: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TotpEnrolFinish"];
            };
        };
        responses: {
            /** @description TOTP is enrolled; recovery codes when the account had none; `reauthenticate` says whether the session must log in again to reach the required strength */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FactorEnrolled"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the enrolment is unknown or expired (`auth.challenge_invalid`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The code does not match the new seed (`auth.totp.code_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    totp_enroll_start: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The seed, the `otpauth://` URI and the enrolment id for the finish step; shown once */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TotpEnrolment"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description TOTP is already enrolled (`auth.totp.already_enrolled`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_webauthn_credentials: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every credential of the user */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_CredentialInfo"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_webauthn_credential: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Credential identifier (base64url) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The credential was deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The action needs a fresh authentication (`auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The user has no such credential (`auth.webauthn.credential_not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The profile requires this credential (`auth.factor.last_required`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    webauthn_login_finish: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WebAuthnLoginFinish"];
            };
        };
        responses: {
            /** @description The login is complete (`status: authenticated`); the session cookie is set */
            200: {
                headers: {
                    /** @description The session cookie `tenko_session` */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LoginResponse"];
                };
            };
            /** @description The body or the assertion is malformed or fails verification (`sys.invalid_request`, `auth.challenge_invalid`, `auth.webauthn.*`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The credential is unknown (`auth.invalid_credentials`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The break-glass account needs a hardware key (`auth.break_glass.hardware_key_only`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The break-glass rate limit applies (`auth.throttled`); `Retry-After` gives the seconds */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    webauthn_login_start: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Optional: the account, or the challenge of a password login */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["WebAuthnLoginStart"] | null;
            };
        };
        responses: {
            /** @description The options for `navigator.credentials.get()` and the ceremony id for the finish step */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WebAuthnLoginOptions"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the password challenge is unknown (`auth.challenge_invalid`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    webauthn_register_finish: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["WebAuthnRegisterFinish"];
            };
        };
        responses: {
            /** @description The credential is registered; recovery codes when the account had none */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["FactorEnrolled"];
                };
            };
            /** @description The body or the attestation is malformed or fails verification (`sys.invalid_request`, `auth.challenge_invalid`, `auth.webauthn.*`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The attestation is refused (`auth.webauthn.attestation_required`, `auth.webauthn.attestation_untrusted`, `auth.webauthn.backup_eligible_refused`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The credential is registered already (`auth.webauthn.credential_exists`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    webauthn_register_start: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description Optional: a label, and whether to ask for a security key */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["WebAuthnRegisterStart"] | null;
            };
        };
        responses: {
            /** @description The options for `navigator.credentials.create()` and the ceremony id for the finish step */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WebAuthnRegisterOptions"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the label is invalid (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_custom_fields: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The definitions, by key */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListBody_CustomFieldDef"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_custom_field: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CustomFieldInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or a replayed request */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_CustomFieldDef"];
                };
            };
            /** @description The new definition */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_CustomFieldDef"];
                };
            };
            /** @description Invalid definition (`ipam.custom_field.invalid_definition`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The key exists (`ipam.name_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_custom_field: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Key of the custom field */
                key: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The definition, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CustomFieldDef"];
                };
            };
            /** @description No such field (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_custom_field: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Key of the custom field */
                key: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Removed (`item` is null), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_CustomFieldDef"];
                };
            };
            /** @description No such field (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Objects still use the field (`ipam.in_use`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_custom_field: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Key of the custom field */
                key: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["CustomFieldPatch"];
            };
        };
        responses: {
            /** @description The changed definition, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_CustomFieldDef"];
                };
            };
            /** @description Invalid definition (`ipam.custom_field.invalid_definition`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such field (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Incompatible change (`ipam.custom_field.incompatible_change`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    events: {
        parameters: {
            query?: {
                /**
                 * @description Comma-separated topics: `ipam`, `jobs`, `audit`, `import`, `system`, `admin`; all
                 *     when absent.
                 */
                topics?: string;
                /**
                 * @description Resume after this store revision (the `revision` of a list); `Last-Event-ID` wins
                 *     on reconnects.
                 */
                from?: number;
            };
            header?: {
                /** @description Revision of the last event the client received */
                "Last-Event-ID"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The event stream; each `data` field is an `EventData` (or a `ResetData` for `reset`) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "text/event-stream": components["schemas"]["EventData"];
                };
            };
            /** @description Unknown topic or malformed parameter */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The server is shutting down */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    export_addresses_csv: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    export_hosts_csv: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    export_prefixes_csv: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    health: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The process answers */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Health"];
                };
            };
        };
    };
    ready: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The node serves requests */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Readiness"];
                };
            };
            /** @description Not ready: starting, catching up or shutting down */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_hosts: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only hosts of this tenant (identifier). */
                tenant?: string;
                /** @description Only hosts at this site (identifier). */
                site?: string;
                /** @description Only hosts with this assignment mode: `static`, `reserved`, `dynamic` or `unmanaged`. */
                mode?: string;
                /** @description Only hosts that are locked (`true`) or not locked (`false`) against automation. */
                locked?: boolean;
                /** @description Only hosts that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the name, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `mode`, `created`, `updated`. */
                sort?: string;
                /** @description Deleted hosts: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of hosts */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Host"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_host: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HostInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Host"];
                };
            };
            /** @description The new host, with `ETag`; the plan warnings say, for example, that a reserved host has no MAC address (`ipam.host.reservation_identifier`) */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Host"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken in the tenant (or an interface name twice), the identifier is in use, or the tenant or site is missing (`ipam.name_taken`, `ipam.id_taken`, `ipam.reference_missing`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_hosts: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_host: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Host identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The host, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Host"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such host (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_host: {
        parameters: {
            query?: {
                /** @description Plan the delete and return the plan without writing (API-09). */
                dry_run?: boolean;
                /** @description Warning codes to acknowledge, comma-separated. */
                acknowledge?: string;
                /**
                 * @description Also delete what would otherwise block the delete: the addresses and ranges of a
                 *     prefix, the addresses of a host or an interface.
                 */
                cascade?: boolean;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Host identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted host (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Host"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such host (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Addresses are assigned to the host and `cascade` is not set, or the host is deleted already (`ipam.in_use`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_host: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Host identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["HostPatch"];
            };
        };
        responses: {
            /** @description The changed host, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Host"];
                };
            };
            /** @description Invalid body or parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed, or automation tried to lock or unlock (`auth.forbidden`, `ipam.host.lock_manual_only`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such host (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken in the tenant, the site is missing, or the host is deleted (`ipam.name_taken`, `ipam.reference_missing`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_host_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the host */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_host_interfaces: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only interfaces that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the name, the MAC address, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`. */
                sort?: string;
                /** @description Deleted interfaces: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path: {
                /** @description Host identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of the interfaces of the host */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Interface"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed to read the host (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such host (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_interface: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path: {
                /** @description Host identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["InterfaceInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Interface"];
                };
            };
            /** @description The new interface, with `ETag`; a MAC address that another interface carries is a warning (`ipam.interface.duplicate_mac`) */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Interface"];
                };
            };
            /** @description Invalid body or parameter, or the `host` of the body is another host (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host does not exist or is deleted, the name is taken on the host, or the identifier is in use (`ipam.reference_missing`, `ipam.name_taken`, `ipam.id_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_host: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the host */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Host"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_import: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "multipart/form-data": components["schemas"]["ImportUpload"];
            };
        };
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_import: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_import: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    apply_import: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    set_import_mapping: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    preview_import: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Not implemented yet */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_interfaces: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_interface: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Interface identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The interface, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Interface"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such interface (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_interface: {
        parameters: {
            query?: {
                /** @description Plan the delete and return the plan without writing (API-09). */
                dry_run?: boolean;
                /** @description Warning codes to acknowledge, comma-separated. */
                acknowledge?: string;
                /**
                 * @description Also delete what would otherwise block the delete: the addresses and ranges of a
                 *     prefix, the addresses of a host or an interface.
                 */
                cascade?: boolean;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Interface identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted interface (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Interface"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such interface (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Addresses are assigned to the interface and `cascade` is not set, or the interface is deleted already (`ipam.in_use`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_interface: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Interface identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["InterfacePatch"];
            };
        };
        responses: {
            /** @description The changed interface, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Interface"];
                };
            };
            /** @description Invalid body or parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such interface (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken on the host, or the interface is deleted (`ipam.name_taken`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The host is locked against automation (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_interface_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the interface */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_interface: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the interface */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Interface"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_jobs: {
        parameters: {
            query?: {
                /**
                 * @description Only jobs in one of these states. Repeat the parameter or separate the names with
                 *     commas: `state=waiting&state=queued` and `state=waiting,queued` are the same.
                 */
                state?: components["schemas"]["JobState"][];
                /**
                 * @description Only jobs of one of these kinds, for example `ipam.move`. Repeat the parameter or
                 *     separate the names with commas.
                 */
                kind?: components["schemas"]["JobKind"][];
                /**
                 * @description Only jobs that change this object, written `kind/uuid`, for example
                 *     `host/0190d1c2-0000-7000-8000-000000000001`.
                 */
                target?: string;
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of jobs, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_JobSummary"];
                };
            };
            /** @description A parameter is unknown, repeated or malformed (`sys.invalid_query`, `jobs.query.invalid`) or the cursor is bad (`sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_job: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes) */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Job identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The job with its steps, transitions and preview */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JobDetail"];
                };
            };
            /** @description The identifier is malformed (`jobs.query.invalid`) or a parameter is unknown or malformed (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read the job */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such job (`jobs.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    cancel_job: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Job identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The cancellation was accepted; the job after the request */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JobSummary"];
                };
            };
            /** @description The identifier is malformed (`jobs.query.invalid`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not cancel the job */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such job (`jobs.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The job is rolling back or finished (`jobs.invalid_transition`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    complete_job_step: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Job identifier (UUID) */
                id: string;
                /** @description Zero-based index of the step */
                index: number;
            };
            cookie?: never;
        };
        /** @description An optional note about what was done */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["CompleteStepRequest"] | null;
            };
        };
        responses: {
            /** @description The step is done; the job after the request */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["JobSummary"];
                };
            };
            /** @description A parameter or the body is malformed (`jobs.query.invalid`, `sys.invalid_request`) or the note is longer than 4,096 bytes (`jobs.note.too_long`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not complete steps of the job */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such job or step (`jobs.not_found`, `jobs.step.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The step is not waiting for a person (`jobs.invalid_transition`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    metrics: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Counters and gauges in the OpenMetrics text format */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/openmetrics-text": string;
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The token lacks the metrics scope */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    openapi_document: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The OpenAPI document */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": Record<string, never>;
                };
            };
        };
    };
    list_prefixes: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only prefixes in one of these statuses; repeat the parameter or separate the values with commas */
                status?: components["schemas"]["Status"][];
                /** @description Only prefixes of this VRF (identifier) */
                vrf?: string;
                /**
                 * @description Only prefixes inside this network, for example `192.0.2.0/24` (the network itself included)
                 * @example 192.0.2.0/24
                 */
                within?: string;
                /** @description Only prefixes of this site (identifier) */
                site?: string;
                /** @description Only supernets or only networks */
                role?: components["schemas"]["PrefixRole"];
                /** @description Only prefixes carrying every one of these tags */
                tag?: string[];
                /** @description Case-insensitive text search over the network, the tags and the description */
                q?: string;
                /**
                 * @description Sort fields, `-` in front for descending: `cidr` (default), `status`, `created`, `updated`
                 * @example -updated,cidr
                 */
                sort?: string;
                /** @description `exclude` (default), `include` or `only` soft-deleted prefixes */
                deleted?: components["schemas"]["Deleted"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of prefixes */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Prefix"];
                };
            };
            /** @description A parameter is unknown, repeated or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_prefix: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PrefixInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the earlier result of a repeated `Idempotency-Key` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description The new prefix, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description Invalid prefix (`ipam.validation`, `ipam.prefix.host_bits`) or parameter (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not create prefixes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.prefix.overlap`, `ipam.id_taken`, `ipam.reference_missing`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_prefixes: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_prefix_tree: {
        parameters: {
            query?: {
                /** @description The VRF (identifier); the VRF `default` of the tenant `default` when absent */
                vrf?: string;
                /**
                 * @description Only the prefixes inside this network, for example `192.0.2.0/24`
                 * @example 192.0.2.0/24
                 */
                within?: string;
                /** @description Deepest level to return; 0 is the top level of the answer */
                depth?: number;
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The nodes in pre-order; empty when the VRF has no prefixes or does not exist */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TreeResponse"];
                };
            };
            /** @description A parameter is unknown, repeated or malformed (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_prefix: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The prefix, with `ETag: "<revision>"` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Prefix"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read the prefix */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_prefix: {
        parameters: {
            query?: {
                /** @description Plan the delete and return the plan without writing (API-09). */
                dry_run?: boolean;
                /** @description Warning codes to acknowledge, comma-separated. */
                acknowledge?: string;
                /**
                 * @description Also delete what would otherwise block the delete: the addresses and ranges of a
                 *     prefix, the addresses of a host or an interface.
                 */
                cascade?: boolean;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted prefix (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description A parameter or `If-Match` is malformed (`sys.invalid_query`, `ipam.validation`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not delete the prefix */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Addresses or ranges still use the prefix (`ipam.in_use`) or it is deleted already (`ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_prefix: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PrefixPatch"];
            };
        };
        responses: {
            /** @description The changed prefix, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description Invalid change (`ipam.validation`, `ipam.prefix.host_bits`, `ipam.immutable`) or a malformed `If-Match` (`ipam.validation`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not change the prefix */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.prefix.overlap`, `ipam.prefix.resize_orphans`, `ipam.prefix.has_children`, `ipam.prefix.has_ranges`, `ipam.status.transition`, `ipam.object_deleted`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_prefix_addresses: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Also return the free gaps between the addresses (default false) */
                include_free?: boolean;
            };
            header?: never;
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of addresses and free gaps in address order */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_PrefixAddressItem"];
                };
            };
            /** @description A parameter is unknown, repeated or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read the prefix */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_prefix_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the prefix */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    next_free_address: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        /** @description How to choose and what to store; an empty body means all defaults */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["NextFreeAddress"] | null;
            };
        };
        responses: {
            /** @description The candidate of a dry run, or the earlier result of a repeated `Idempotency-Key` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description The new address, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Address"];
                };
            };
            /** @description Invalid body (`sys.invalid_request`) or values (`ipam.validation`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not create addresses */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No free address (`ipam.address.full`) or a conflict (`ipam.id_taken`, `ipam.reference_missing`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    next_free_prefix: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path: {
                /** @description Prefix identifier of the parent */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NextFreePrefix"];
            };
        };
        responses: {
            /** @description The candidate of a dry run, or the earlier result of a repeated `Idempotency-Key` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description The new prefix, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description Invalid length or values (`ipam.validation`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not create prefixes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No free block (`ipam.prefix.full`), the parent is a network (`ipam.prefix.overlap`), or another conflict (`ipam.id_taken`, `ipam.reference_missing`, `ipam.plan.unacknowledged`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_prefix_ranges: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only ranges of this role */
                role?: components["schemas"]["RangeRole"];
                /** @description Only ranges in one of these statuses; repeat the parameter or separate the values with commas */
                status?: components["schemas"]["Status"][];
                /** @description Only ranges carrying every one of these tags */
                tag?: string[];
                /** @description Case-insensitive text search over the addresses, the tags and the description */
                q?: string;
                /**
                 * @description Sort fields, `-` in front for descending: `first` (default), `created`, `updated`
                 * @example -first
                 */
                sort?: string;
                /** @description `exclude` (default), `include` or `only` soft-deleted ranges */
                deleted?: components["schemas"]["Deleted"];
            };
            header?: never;
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of ranges */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Range"];
                };
            };
            /** @description A parameter is unknown, repeated or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read the prefix */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_range: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path: {
                /** @description Prefix identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NewRange"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the earlier result of a repeated `Idempotency-Key` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Range"];
                };
            };
            /** @description The new range, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Range"];
                };
            };
            /** @description Invalid range (`ipam.validation`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not create ranges */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such prefix (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.range.overlap`, `ipam.range.outside_prefix`, `ipam.range.not_in_network`, `ipam.range.covers_reservation`, `ipam.id_taken`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for another request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_prefix: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the prefix */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Prefix"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_ranges: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_range: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Range identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The range, with `ETag: "<revision>"` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Range"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read the range */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such range (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_range: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Range identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted range (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Range"];
                };
            };
            /** @description A parameter or `If-Match` is malformed (`sys.invalid_query`, `ipam.validation`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not delete the range */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such range (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The range is deleted already (`ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_range: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Range identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RangePatch"];
            };
        };
        responses: {
            /** @description The changed range, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Range"];
                };
            };
            /** @description Invalid change (`ipam.validation`) or a malformed `If-Match` */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not change the range */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such range (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.range.overlap`, `ipam.range.outside_prefix`, `ipam.range.covers_reservation`, `ipam.status.transition`, `ipam.object_deleted`) or a warning that needs `acknowledge` (`ipam.plan.unacknowledged`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_range_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the range */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_range: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the range */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Range"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_roles: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every role with its description */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_RoleInfo"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    search: {
        parameters: {
            query: {
                /**
                 * @description Search text: an address, a network, a name, a DNS name, a MAC address or words of
                 *     a description.
                 */
                q: string;
                /** @description Most hits, 1 to 1,000. The default is 100. */
                limit?: number;
                /** @description Read at least at this store revision. */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Hits, prefixes first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListBody_SearchHit"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_security_settings: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The settings, each toggle with its profile default and markers, and the banner */
            200: {
                headers: {
                    /** @description The revision of the settings, for `If-Match` */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecuritySettingsView"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_security_settings: {
        parameters: {
            query?: never;
            header?: {
                /** @description The revision the client read, as in the `ETag`; a stale revision is refused with 409 */
                "If-Match"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SettingsPatch"];
            };
        };
        responses: {
            /** @description The settings after the change */
            200: {
                headers: {
                    /** @description The new revision of the settings */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecuritySettingsView"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`), a value is invalid (`auth.invalid_request`) or `If-Match` is malformed (`sys.invalid_value`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`auth.conflict`), or a PIN would be the only factor while the vault holds operator secrets (`settings.pin_coupling`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_setup: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The setup state; the profiles are listed while setup is open */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SetupState"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    complete_setup: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SetupRequest"];
            };
        };
        responses: {
            /** @description Setup is complete; the administrator is logged in */
            200: {
                headers: {
                    /** @description The session cookie `tenko_session` */
                    "Set-Cookie"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SessionInfo"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`), or the host name, user name or language is invalid (`auth.setup.invalid_host_name`, `auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The setup token is wrong (`auth.setup.token_invalid`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Setup has already been completed (`auth.setup.closed`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The password breaks the policy of the chosen profile (`auth.password.policy`, with the violations in `errors`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many wrong setup tokens (`auth.throttled`); `Retry-After` gives the seconds */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_sites: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only the children of this site (identifier of the parent). */
                site?: string;
                /** @description Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the name, the Active Directory site, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`. */
                sort?: string;
                /** @description Deleted sites: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of sites */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Site"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_site: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SiteInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Site"];
                };
            };
            /** @description The new site, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Site"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken, the identifier is in use, or the parent is missing (`ipam.name_taken`, `ipam.id_taken`, `ipam.reference_missing`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_sites: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_site: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Site identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The site, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Site"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such site (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_site: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Site identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted site (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Site"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such site (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Live child sites, VLANs, prefixes or hosts belong to the site, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_site: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Site identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["SitePatch"];
            };
        };
        responses: {
            /** @description The changed site, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Site"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such site (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken, the parent would make a cycle or is missing, or the site is deleted (`ipam.name_taken`, `ipam.site.cycle`, `ipam.reference_missing`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_site_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the site */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_site: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the site */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Site"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    set_break_glass: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BreakGlassChange"];
            };
        };
        responses: {
            /** @description The account after the change */
            200: {
                headers: {
                    /** @description The new revision of the user */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserInfo"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the account holds no hardware security key (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The account is the last active administrator (`users.last_administrator`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    system_status: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Status of this node */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SystemStatus"];
                };
            };
            /** @description Not authenticated */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_tags: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Tags with their use counts */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ListBody_TagCount"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_tenants: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the name, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`. */
                sort?: string;
                /** @description Deleted tenants: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of tenants */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Tenant"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_tenant: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TenantInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Tenant"];
                };
            };
            /** @description The new tenant, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Tenant"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken, or the identifier is in use (`ipam.name_taken`, `ipam.id_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_tenants: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_tenant: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Tenant identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The tenant, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Tenant"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such tenant (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_tenant: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Tenant identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted tenant (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Tenant"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such tenant (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Live VRFs or hosts belong to the tenant, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_tenant: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Tenant identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["TenantPatch"];
            };
        };
        responses: {
            /** @description The changed tenant, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Tenant"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such tenant (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken, or the tenant is deleted (`ipam.name_taken`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_tenant_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the tenant */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_tenant: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the tenant */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Tenant"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_users: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every user, ordered by name */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_UserInfo"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_user: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["UserCreate"];
            };
        };
        responses: {
            /** @description The user was created */
            201: {
                headers: {
                    /** @description The revision of the user, for `If-Match` */
                    ETag?: string;
                    /** @description The URL of the new user */
                    Location?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserInfo"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`), or the name, roles or language are invalid (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The user name is taken (`users.name_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The initial password breaks the policy (`auth.password.policy`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_user: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description User identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The user */
            200: {
                headers: {
                    /** @description The revision of the user, for `If-Match` */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserInfo"];
                };
            };
            /** @description The identifier is not a UUID (`sys.invalid_value`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_user: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description User identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The user was deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is not a UUID (`sys.invalid_value`) or is the caller's own account (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The user is the last active administrator (`users.last_administrator`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_user: {
        parameters: {
            query?: never;
            header?: {
                /** @description The revision the client read, as in the `ETag`; a stale revision is refused with 409 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description User identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["UserUpdate"];
            };
        };
        responses: {
            /** @description The user after the change */
            200: {
                headers: {
                    /** @description The new revision of the user */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserInfo"];
                };
            };
            /** @description The identifier is not a UUID or `If-Match` is malformed (`sys.invalid_value`), the body is malformed (`sys.invalid_request`), or a value is invalid (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`auth.conflict`) or the change would leave no active administrator (`users.last_administrator`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The new password breaks the policy (`auth.password.policy`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    set_user_roles: {
        parameters: {
            query?: never;
            header?: {
                /** @description The revision the client read, as in the `ETag`; a stale revision is refused with 409 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description User identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RolesUpdate"];
            };
        };
        responses: {
            /** @description The user after the change */
            200: {
                headers: {
                    /** @description The new revision of the user */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserInfo"];
                };
            };
            /** @description The identifier is not a UUID or `If-Match` is malformed (`sys.invalid_value`), the body is malformed (`sys.invalid_request`), or the roles are invalid (`auth.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`auth.conflict`) or the change would leave no active administrator (`users.last_administrator`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    revoke_user_sessions: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description User identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The sessions ended */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is not a UUID (`sys.invalid_value`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    unlock_user: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description User identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The user after the unlock */
            200: {
                headers: {
                    /** @description The revision of the user */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UserInfo"];
                };
            };
            /** @description The identifier is not a UUID (`sys.invalid_value`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No valid session or token (`auth.unauthenticated`, `auth.session_expired`); an endpoint that needs an interactive session refuses a bearer token the same way */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not do this: it lacks the permission, a personal token tries to administer (users, settings, tokens and sessions need an interactive session), or the action needs a fresh or stronger authentication (`auth.forbidden`, `auth.out_of_scope`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such user (`users.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The authentication service is not configured or not ready (`auth.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_vlans: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only VLANs with one of these statuses: `planned`, `active`, `reserved` or `deprecated`. Repeat the parameter or separate the values with commas. */
                status?: string;
                /** @description Only VLANs of this site (identifier). */
                site?: string;
                /** @description Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the VLAN id, the name, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-vid,name`. Fields: `vid` (the default), `name`, `created`, `updated`. */
                sort?: string;
                /** @description Deleted VLANs: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of VLANs */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Vlan"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_vlan: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VlanInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vlan"];
                };
            };
            /** @description The new VLAN, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vlan"];
                };
            };
            /** @description Invalid body or parameter: the VLAN id is outside 1 to 4094, or the VNI is too large (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The VLAN id exists at the site, the identifier is in use, or the site is missing (`ipam.vlan.duplicate`, `ipam.id_taken`, `ipam.reference_missing`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_vlans: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_vlan: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description VLAN identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The VLAN, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Vlan"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such VLAN (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_vlan: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description VLAN identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted VLAN (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vlan"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such VLAN (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Live prefixes use the VLAN, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_vlan: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description VLAN identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VlanPatch"];
            };
        };
        responses: {
            /** @description The changed VLAN, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vlan"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such VLAN (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The VLAN id exists at the site, the status change is not allowed, the site is missing, or the VLAN is deleted (`ipam.vlan.duplicate`, `ipam.status.transition`, `ipam.reference_missing`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_vlan_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the VLAN */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_vlan: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the VLAN */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vlan"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_vrfs: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only VRFs of this tenant (identifier). */
                tenant?: string;
                /** @description Only objects that carry every one of these tags. Repeat the parameter or separate the tags with commas. */
                tag?: string;
                /** @description Case-insensitive text search over the name, the route distinguisher, the description and the tags. */
                q?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending, for example `-updated,name`. Fields: `name` (the default), `created`, `updated`. */
                sort?: string;
                /** @description Deleted VRFs: `exclude` (the default), `include` or `only` (the restore view). */
                deleted?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of VRFs */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Vrf"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    create_vrf: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VrfInput"];
            };
        };
        responses: {
            /** @description The plan of a dry run, or the first result again for a repeated `Idempotency-Key` (`replayed` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vrf"];
                };
            };
            /** @description The new VRF, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vrf"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken in the tenant, the identifier is in use, or the tenant is missing (`ipam.name_taken`, `ipam.id_taken`, `ipam.reference_missing`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The `Idempotency-Key` was used for a different request (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    bulk_vrfs: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["BulkRequest"];
            };
        };
        responses: {
            /** @description The committed change, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["BulkResponse"];
                };
            };
            /** @description Invalid operation (`ipam.validation`, `ipam.bulk.wrong_collection`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A conflict (`ipam.*`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many operations (`ipam.bulk.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_vrf: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description VRF identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The VRF, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Vrf"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such VRF (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_vrf: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description VRF identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The deleted VRF (`meta.deleted` is set), or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vrf"];
                };
            };
            /** @description Invalid parameter, or `If-Match` is malformed (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such VRF (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Live prefixes belong to the VRF, or it is deleted already (`ipam.in_use`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    update_vrf: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description VRF identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["VrfPatch"];
            };
        };
        responses: {
            /** @description The changed VRF, with `ETag`, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vrf"];
                };
            };
            /** @description Invalid body or parameter (`ipam.validation`, `sys.invalid_request`, `sys.invalid_query`), or `If-Match` is malformed */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such VRF (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken in the tenant, or the VRF is deleted (`ipam.name_taken`, `ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is not JSON (`sys.invalid_request`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_vrf_history: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Identifier of the VRF */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description History entries, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_HistoryEntry"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_cursor`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    restore_vrf: {
        parameters: {
            query?: {
                /** @description Plan the change and return the plan without writing (API-09). */
                dry_run?: boolean;
                /**
                 * @description Warning codes to acknowledge, comma-separated (for example
                 *     `ipam.prefix.nibble_boundary`).
                 */
                acknowledge?: string;
            };
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Identifier of the VRF */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The restored object, or the plan of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WriteResponse_Vrf"];
                };
            };
            /** @description No such object (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not deleted, or a conflict (`ipam.not_deleted`, `ipam.name_taken`, `ipam.address.duplicate`, `ipam.prefix.overlap`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM not configured (`ipam.unavailable`) */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
}
