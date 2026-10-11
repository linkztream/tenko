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
        /** Create a personal or scoped API token, shown once */
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
    "/api/v1/cluster/digests": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Compare the state digests of the members */
        get: operations["get_cluster_digests"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cluster/members": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the controller cluster members */
        get: operations["list_cluster_members"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cluster/members/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Remove a controller from the cluster */
        delete: operations["remove_cluster_member"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cluster/members/{id}/promote": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Promote a learner to a voter */
        post: operations["promote_cluster_member"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/cluster/step-down": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Hand leadership to another controller */
        post: operations["step_down_cluster_leader"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/connectors": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List connector instances */
        get: operations["list_connectors"];
        put?: never;
        /** Create a connector instance */
        post: operations["create_connector"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/connectors/plugins": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List connector plugins */
        get: operations["list_connector_plugins"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/connectors/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a connector instance */
        get: operations["get_connector"];
        put?: never;
        post?: never;
        /** Delete a connector instance */
        delete: operations["delete_connector"];
        options?: never;
        head?: never;
        /** Change a connector instance */
        patch: operations["update_connector"];
        trace?: never;
    };
    "/api/v1/connectors/{id}/check": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Check a connector instance now */
        post: operations["check_connector"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/connectors/{id}/disable": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Disable a connector instance */
        post: operations["disable_connector"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/connectors/{id}/enable": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Enable a connector instance */
        post: operations["enable_connector"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/connectors/{id}/run": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Run a connector instance now */
        post: operations["run_connector"];
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
    "/api/v1/hosts/{id}/credentials": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the credentials of a host */
        get: operations["get_host_credentials"];
        /** Bind and unbind the credentials of a host */
        put: operations["update_host_credentials"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
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
    "/api/v1/hosts/{id}/remote": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the RDP file or SSH URI of a host */
        get: operations["get_host_remote"];
        put?: never;
        post?: never;
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
    "/api/v1/i18n/languages": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the languages of the installation */
        get: operations["get_languages"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/packs": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the language packs with their versions */
        get: operations["list_packs"];
        put?: never;
        /** Upload a language pack */
        post: operations["upload_pack"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/packs/{tag}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the messages of an active language pack */
        get: operations["get_pack"];
        put?: never;
        post?: never;
        /** Remove a language pack, or revert a built-in language */
        delete: operations["delete_pack"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/packs/{tag}/activate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Activate an uploaded language pack */
        post: operations["activate_pack"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/packs/{tag}/candidate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the messages of an uploaded language pack for a preview */
        get: operations["get_pack_candidate"];
        put?: never;
        post?: never;
        /** Discard an uploaded language pack that is not active */
        delete: operations["discard_pack_candidate"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/packs/{tag}/preview": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Preview an uploaded language pack */
        post: operations["preview_pack"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/packs/{tag}/report": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the validation report of a language pack */
        get: operations["get_pack_report"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/i18n/template.xlf": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Export the template of a language pack */
        get: operations["get_template"];
        put?: never;
        post?: never;
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
        /**
         * Apply an import as a job
         * @description Credential columns (login, password) are never IPAM fields: each host's login and
         *     password become one operator secret of that host in the vault. Apply refuses them with
         *     403 `import.credentials.vault_required` unless the server has a vault and the principal
         *     passes both `Action::Create` and `Action::Reveal` on `ObjectKind::Secret` (in practice
         *     an administrator with a password-or-stronger session, the IAM-07 threshold). The problem
         *     carries the parameter `reason`, one of `vault_unavailable`, `step_up_required`,
         *     `forbidden` or `unauthenticated`, and for a step-up `required`, the weakest session
         *     strength that would do. Setting `options.credentials` to `skip` in the mapping leaves the
         *     credential columns out and the rest of the import is applied.
         */
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
        /**
         * Preview the changes of an import: summary, rows and loss report
         * @description Credential columns (login, password) are never IPAM fields: each host's login and
         *     password would become one operator secret of that host in the vault. `credentials`
         *     says how many secrets would be created, replaced or left as they are, whether this
         *     account may store them (`allowed`) and, when it may not, why (`reason`); then
         *     `import.credentials.vault_required` is among the `blockers`. Storing them needs a vault
         *     on the server and a principal that passes both create and reveal on secrets, in practice
         *     an administrator with a password-or-stronger session (IAM-07). Setting
         *     `options.credentials` to `skip` in the mapping leaves them out.
         */
        get: operations["preview_import"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/imports/{id}/rows": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the rows of the latest preview of an import */
        get: operations["list_import_rows"];
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
    "/api/v1/moves": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Preview or start a move to another network */
        post: operations["create_move"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List cluster nodes */
        get: operations["list_nodes"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/enrol": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Enrol a node with a token */
        post: operations["enrol_node"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/enrolments": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List enrolment tokens */
        get: operations["list_enrolments"];
        put?: never;
        /** Create an enrolment token */
        post: operations["create_enrolment"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/enrolments/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        post?: never;
        /** Delete an enrolment token */
        delete: operations["delete_enrolment"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/nodes/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get a cluster node */
        get: operations["get_node"];
        put?: never;
        post?: never;
        /** Revoke a cluster node */
        delete: operations["revoke_node"];
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/observations": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List observed facts */
        get: operations["list_observations"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/observations/{subject}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the picture of one subject across sources */
        get: operations["get_observation"];
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
         *     `{ "type": "free", "data": { first, last, size } }`; `size` is a decimal string. With
         *     `expand=host` the address data of a bound address also carries `interface_detail` and
         *     `host` (see `GET /addresses`). The gaps
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
    "/api/v1/prefixes/{id}/adoption": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the adoption policy of a prefix */
        get: operations["get_adoption_policy"];
        /** Set the adoption policy of a prefix */
        put: operations["set_adoption_policy"];
        post?: never;
        /** Remove the adoption policy of a prefix */
        delete: operations["clear_adoption_policy"];
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
    "/api/v1/proposals": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List proposals */
        get: operations["list_proposals"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/proposals/reconcile": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Run the reconciler now */
        post: operations["reconcile_proposals"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/proposals/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one proposal */
        get: operations["get_proposal"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/proposals/{id}/approve": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Approve a proposal */
        post: operations["approve_proposal"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/proposals/{id}/reject": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reject a proposal */
        post: operations["reject_proposal"];
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
    "/api/v1/secrets": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List operator secrets */
        get: operations["list_secrets"];
        put?: never;
        /** Create an operator secret */
        post: operations["create_secret"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secrets/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get an operator secret */
        get: operations["get_secret"];
        put?: never;
        post?: never;
        /** Delete an operator secret */
        delete: operations["delete_secret"];
        options?: never;
        head?: never;
        /** Update an operator secret */
        patch: operations["update_secret"];
        trace?: never;
    };
    "/api/v1/secrets/{id}/references": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the references of an operator secret */
        get: operations["list_secret_references"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/secrets/{id}/reveal": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Reveal an operator secret */
        post: operations["reveal_secret"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/settings/default-language": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Set the default language of the installation */
        put: operations["set_default_language"];
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
    "/api/v1/system/ca-root": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Download the root certificate of the internal CA as PEM */
        get: operations["get_ca_root"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/kek": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the key-encryption key status of this controller and the installation */
        get: operations["get_kek_status"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/kek/rotate": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Start an online rotation of the key-encryption key */
        post: operations["rotate_kek"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/modules": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the product modules this installation runs */
        get: operations["get_modules"];
        /** Set the product modules this installation runs */
        put: operations["put_modules"];
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
    "/api/v1/system/updates": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the update status: newer releases with their notes and how to install them */
        get: operations["get_updates"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/updates/check": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Ask the release source for new versions now */
        post: operations["check_updates"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/updates/install": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Install a newer version from the release source */
        post: operations["install_update"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/updates/manifest": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        /** Upload a release manifest (air-gapped installations) */
        put: operations["put_update_manifest"];
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/updates/upload": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Install an uploaded release file */
        post: operations["upload_update"];
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/updates/whats-new": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the notes to show this user after an upgrade */
        get: operations["get_whats_new"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/system/updates/whats-new/seen": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Mark the notes of the running version as seen by this user */
        post: operations["mark_whats_new_seen"];
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
    "/api/v1/topology": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get the topology graph */
        get: operations["get_topology"];
        put?: never;
        post?: never;
        delete?: never;
        options?: never;
        head?: never;
        patch?: never;
        trace?: never;
    };
    "/api/v1/topology/nodes/{id}": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** Get one topology node with its ports and neighbours */
        get: operations["get_topology_node"];
        put?: never;
        post?: never;
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
    "/api/v1/vlans/provision": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        get?: never;
        put?: never;
        /** Preview or start creating a VLAN with its network on the network controller */
        post: operations["provision_vlan"];
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
    "/api/v1/vlans/{id}/prefixes": {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** List the prefixes of a VLAN */
        get: operations["list_vlan_prefixes"];
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
        /** @description How many items of a kind get one action. */
        ActionCount: {
            /** @description The action. */
            action: components["schemas"]["ItemAction"];
            /** @description How many. */
            count: number;
            /**
             * @description The item kind: `tenant`, `vrf`, `site`, `vlan`, `prefix`, `host`, `interface`,
             *     `address` or `credential`.
             */
            kind: string;
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
         * @description An address in a list: the address object, and with `expand=host` the interface it is
         *     bound to and that interface's host, so an address grid needs no read per row. Both
         *     members are absent when the address is not bound, when its interface or host is
         *     deleted, and without the expansion.
         */
        AddressRow: components["schemas"]["Address"] & {
            host?: components["schemas"]["HostSummary"] | null;
            interface_detail?: components["schemas"]["InterfaceSummary"] | null;
        };
        /**
         * @description What a prefix's policy adopts without a person (IPAM-15 "auto-adopt in network Z").
         * @enum {string}
         */
        AdoptionMode: "manual" | "adopt_hosts" | "adopt_all";
        /** @description The adoption policy of a prefix, inherited by the prefixes inside it that have none. */
        AdoptionPolicy: {
            /** @description The assignment mode of adopted hosts; `dynamic` by default (IPAM only observes). */
            host_mode?: components["schemas"]["AssignmentMode"];
            /**
             * Format: int32
             * @description Only after this many counted sightings by one source (1 to 1,000; 1 by default).
             */
            min_sightings?: number;
            /** @description What is adopted. */
            mode: components["schemas"]["AdoptionMode"];
            /** @description Only addresses inside a DHCP pool of the prefix. */
            only_dhcp_pools?: boolean;
            /**
             * @description Only devices whose vendor matches one entry: an OUI prefix of the MAC address
             *     (`00:00:5e`, `00-00-5E`) or text the source reports as the vendor (compared
             *     without case). Empty: any vendor. At most 32 entries of 1 to 64 characters.
             */
            vendors?: string[];
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
        /** @description The answer of `POST /imports/{id}/apply`. */
        ApplyAccepted: {
            /** @description The job that applies the import; follow it at `/jobs/{id}`. */
            job_id: string;
        };
        /** @description The body of `POST /imports/{id}/apply`. */
        ApplyRequest: {
            /** @description Plan warning codes acknowledged in addition to the mapping options. */
            acknowledge?: string[];
        };
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
        /**
         * @description A change of how a client is attached, the L2 step of a move (CONN-06): the port profile
         *     of a switch port, or the per-client VLAN override of a client.
         *
         *     Adjacently tagged because variants carry MAC addresses (see `tenko_core::codec`).
         */
        AttachmentChange: {
            /** @description Give a switch port a port profile. */
            data: {
                /** @description The switch, by controller reference. */
                device: string;
                /**
                 * Format: int32
                 * @description The port index.
                 */
                port: number;
                /** @description The profile, by controller reference. */
                profile: string;
            };
            /** @enum {string} */
            type: "set_port_profile";
        } | {
            /** @description Put a client into a network with the per-client VLAN override. */
            data: {
                /** @description The client. */
                mac: components["schemas"]["MacAddr"];
                /** @description The network, by controller reference (for UniFi the network `_id`). */
                network: string;
            };
            /** @enum {string} */
            type: "set_client_vlan";
        } | {
            /** @description Remove a client's per-client VLAN override. */
            data: {
                /** @description The client. */
                mac: components["schemas"]["MacAddr"];
            };
            /** @enum {string} */
            type: "clear_client_vlan";
        };
        /** @description Where a client is attached, as one source reports it. */
        AttachmentView: {
            /** @description The switch or access point. */
            device: string;
            /** @description When the source last reported it. */
            last_seen: components["schemas"]["Timestamp"];
            /** @description The client. */
            mac: components["schemas"]["MacAddr"];
            /** @description The switch port. */
            port?: string | null;
            /** @description The source key. */
            source: string;
            /** @description The wireless network. */
            ssid?: string | null;
            /**
             * Format: int32
             * @description The VLAN.
             */
            vlan?: number | null;
        };
        /**
         * @description The state of an install attempt.
         * @enum {string}
         */
        AttemptState: "installing" | "restarting" | "confirmed" | "rolled_back" | "failed";
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
        /**
         * @description How the audit trail leaves the installation (TGL-21, IAM-18). The audit log itself is
         *     never off; the toggle decides whether export sinks are required. The variants are
         *     ordered from the weakest to the strongest.
         * @enum {string}
         */
        AuditExport: "local" | "optional" | "required";
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
        /**
         * @description An interface a plugin implements.
         * @enum {string}
         */
        Capability: "inventory" | "webhook" | "network_controller" | "actuator" | "migration";
        /** @description A certificate issued to a node, as the registry remembers it. */
        CertificateRef: {
            /** @description End of validity. */
            not_after: components["schemas"]["Timestamp"];
            /** @description Start of validity. */
            not_before: components["schemas"]["Timestamp"];
            /** @description Serial number, lower-case hex. */
            serial: string;
            /** @description SHA-256 of the certificate, lower-case hex. */
            sha256: string;
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
        /**
         * @description Why the scheduled check does not run.
         * @enum {string}
         */
        CheckOff: "air_gapped" | "setting";
        /** @description The node transport of a controller, for `GET /system/status`. */
        ClusterStatus: {
            /**
             * Format: int64
             * @description Nodes connected to this controller now.
             */
            connected: number;
            /** @description The addresses the cluster port listens on; empty while it is off. */
            listening: string[];
            /** @description The protocol majors this controller implements. */
            majors: number[];
            /**
             * Format: int64
             * @description Nodes whose last handshake was refused for want of a common protocol major; each
             *     also has a `cluster.protocol.mismatch` warning.
             */
            mismatched: number;
            /**
             * Format: int64
             * @description Enrolled nodes.
             */
            nodes: number;
            /** @description Software versions of the connected nodes and how many run each. */
            versions: {
                [key: string]: number;
            };
        };
        /**
         * @description What changing the membership needs: the system.
         *     The cluster as one controller sees it: the answer of `GET /cluster/members` and of a
         *     membership change.
         */
        ClusterView: {
            /** @description Whether a membership change is in progress (joint consensus). */
            changing: boolean;
            /**
             * Format: uuid
             * @description The inline job `cluster.edit` of a promotion or removal; absent on `GET`.
             */
            job_id?: string | null;
            /**
             * Format: int64
             * @description The leader it knows, if any.
             */
            leader?: number | null;
            /**
             * @description The members by node id. Replication figures (`matched`, `lag_entries`,
             *     `last_contact_ms`) come from the leader; a follower asks it.
             */
            members: components["schemas"]["MemberView"][];
            /**
             * Format: int64
             * @description The controller that answered.
             */
            node: number;
            /** @description Whether it is in contact with a quorum. */
            quorum: components["schemas"]["QuorumView"];
            /**
             * Format: int64
             * @description The Raft term it knows.
             */
            term: number;
        };
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
        /** @description What the analysis found in one column. */
        ColumnAnalysis: {
            /** @description The column letter. */
            column: string;
            /** @description The header text, if the sheet has a header row and the cell is not empty. */
            header?: string | null;
            /** @description Up to five distinct values (credential columns show [`HIDDEN_SAMPLE`]). */
            samples: string[];
            /** @description Shapes of the data values. */
            shapes: components["schemas"]["ShapeCounts"];
            /** @description The suggested target. */
            suggested: components["schemas"]["Target"];
        };
        /** @description The target of one column. */
        ColumnMapping: {
            /** @description The column letter (`A`). */
            column: string;
            /**
             * @description For one of several address columns: the interface the addresses go on (`nic1`,
             *     from a `Nic1` header by default).
             */
            interface?: string | null;
            /** @description What the column is imported as. */
            target: components["schemas"]["Target"];
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
         * @description What to do when the store already holds an object with different values.
         * @enum {string}
         */
        ConflictPolicy: "update" | "skip" | "fail";
        /** @description A live connection of a node to this controller. */
        ConnectionView: {
            /**
             * Format: int64
             * @description Observation batches waiting in the node's buffer.
             */
            buffered_batches: number;
            /**
             * Format: int64
             * @description Their size in bytes.
             */
            buffered_bytes: number;
            certificate_not_after?: components["schemas"]["Timestamp"] | null;
            /**
             * Format: int64
             * @description The controller the node is connected to; heartbeat figures are known only to that
             *     controller.
             */
            controller?: number | null;
            /**
             * Format: int64
             * @description Batches the node dropped since it started because its buffer was full.
             */
            dropped_batches: number;
            last_beat?: components["schemas"]["Timestamp"] | null;
            /**
             * Format: int32
             * @description The agreed protocol major.
             */
            major: number;
            /** @description The node's address as this controller sees it. */
            peer?: string | null;
            /** @description When the heartbeat stream opened. */
            since: components["schemas"]["Timestamp"];
            /** @description The software version the node reports. */
            version: string;
        };
        /** @description The health of an instance: its process and its remote system. */
        ConnectorHealth: {
            /** @description The plugin process on this node. */
            process: components["schemas"]["SupervisorStatus"];
            remote?: components["schemas"]["HealthReport"] | null;
            remote_error?: components["schemas"]["CodedError"] | null;
        };
        /** Format: uuid */
        ConnectorId: string;
        /** @description A configured connector instance: one plugin, its settings and its secret references. */
        ConnectorInstance: {
            /**
             * Format: int32
             * @description Timeout of one call in seconds; the manifest's default or 30 when absent.
             */
            call_timeout_secs?: number | null;
            /** @description Creation. */
            created: components["schemas"]["Stamp"];
            /** @description Whether the plugin runs and its schedule is active. */
            enabled: boolean;
            /** @description Identifier. */
            id: components["schemas"]["ConnectorId"];
            /** @description The display name, unique (ignoring case). */
            name: string;
            /** @description The plugin name. */
            plugin: string;
            /**
             * Format: int32
             * @description Seconds between scheduled reads; the manifest's default or 300 when absent.
             */
            poll_interval_secs?: number | null;
            /** @description Vault references by secret purpose; only purposes the manifest declares. */
            secrets?: {
                [key: string]: components["schemas"]["SecretRef"];
            };
            /** @description The settings, valid against the plugin's settings schema, with defaults filled in. */
            settings: Record<string, never>;
            /** @description Last change. */
            updated: components["schemas"]["Stamp"];
            /** @description Whether writes through this connector are allowed (TGL-20); off by default. */
            writes_enabled?: boolean;
        };
        /** @description The body of a change request: absent members stay as they are. */
        ConnectorPatch: {
            /**
             * Format: int32
             * @description A new call timeout; `0` returns to the default.
             */
            call_timeout_secs?: number | null;
            /** @description A new display name. */
            name?: string | null;
            /**
             * Format: int32
             * @description A new poll interval; `0` returns to the default.
             */
            poll_interval_secs?: number | null;
            /** @description New secret references (the whole map). */
            secrets?: {
                [key: string]: components["schemas"]["SecretRef"];
            } | null;
            /** @description New settings (the whole object; validated against the schema). */
            settings?: Record<string, never> | null;
            /** @description Whether writes are allowed. */
            writes_enabled?: boolean | null;
        };
        /** @description An instance as the API shows it. */
        ConnectorView: components["schemas"]["ConnectorInstance"] & {
            /** @description The plugin's capabilities, when the plugin is known. */
            capabilities?: components["schemas"]["Capability"][];
            /** @description Health of the process and the remote system. */
            health: components["schemas"]["ConnectorHealth"];
            last_run?: components["schemas"]["LastRun"] | null;
            /** @description The store revision of the instance (for `If-Match` style preconditions). */
            revision: components["schemas"]["Revision"];
        };
        /**
         * @description Which context-specific word a password contained.
         * @enum {string}
         */
        ContextKind: "user_name" | "display_name" | "host_name" | "product";
        /** @description A connector instance that can act as a network controller. */
        ControllerInfo: {
            /** @description Whether the instance is enabled. */
            enabled: boolean;
            /** @description The connector instance. */
            id: components["schemas"]["ConnectorId"];
            /** @description Its display name. */
            name: string;
            /** @description The plugin, such as `unifi`. */
            plugin: string;
            /** @description Whether writes through the instance are allowed (TGL-20). */
            writes_enabled: boolean;
        };
        /** @description How one controller of the installation protects its key-encryption key. */
        ControllerKekView: {
            /**
             * Format: int64
             * @description The controller.
             */
            node: number;
            /** @description The protection at its last start. */
            protection: components["schemas"]["KekProtectionView"];
            /** @description Its provider: `dpapi`, `systemd_creds`, `systemd_credential` or `file`. */
            provider: string;
            /**
             * @description The strongest protection this controller ever had; a `protection` weaker than this is
             *     a downgrade.
             */
            strongest: components["schemas"]["KekProtectionView"];
            /** @description When the controller last started and recorded this. */
            updated_at: components["schemas"]["Timestamp"];
        };
        /**
         * @description How the network gets onto the switches and access points.
         * @enum {string}
         */
        ControllerMode: "automatic" | "unchanged" | "manual";
        /** @description A network on the controller. */
        ControllerNetwork: {
            /** @description The controller's reference (for UniFi the network `_id`, not the VLAN). */
            id: string;
            /** @description Whether Tenko or the controller is managed through this network (never written). */
            management?: boolean;
            /** @description Name. */
            name: string;
            /** @description The gateway subnet. */
            subnet?: string | null;
            /**
             * Format: int32
             * @description The VLAN id; absent for the untagged default network.
             */
            vlan?: number | null;
        };
        /** @description The network step of a provision. */
        ControllerPreview: {
            /** @description The network controllers to choose from. */
            candidates?: components["schemas"]["ControllerInfo"][];
            connector?: components["schemas"]["ControllerInfo"] | null;
            /** @description The read-back diff: what the write changes on the controller. */
            diff?: components["schemas"]["DiffEntry"][];
            /** @description How the network gets there. */
            mode: components["schemas"]["ControllerMode"];
            /** @description The network asked for. */
            network: components["schemas"]["NetworkSpec"];
            read_at?: components["schemas"]["Timestamp"] | null;
            /**
             * @description Why the step is manual (`ipam.vlan.no_controller`, `ipam.vlan.manual_requested`,
             *     `ipam.vlan.controller_ambiguous`, `ipam.vlan.controller_read_only`).
             */
            reason?: string | null;
            /** @description The controller's warnings, in English. */
            warnings?: string[];
        };
        /** @description How a network controller contributed. */
        ControllerStatus: {
            /** @description The connector instance. */
            connector: components["schemas"]["ConnectorId"];
            /** @description Managed devices it reported. */
            devices: number;
            error?: components["schemas"]["CodedError"] | null;
            /** @description Its name. */
            name: string;
            observed_at?: components["schemas"]["Timestamp"] | null;
        };
        /** @description Answer of `POST /nodes/enrolments`: the token, shown once. */
        CreatedEnrolment: {
            /** @description The SHA-256 fingerprint of the internal CA root, for `--ca-fingerprint`. */
            ca_fingerprint: string;
            /** @description The command to run on the node, with the token and the fingerprint filled in. */
            command: string;
            /** @description The stored token. */
            enrolment: components["schemas"]["EnrolmentView"];
            /** @description The token text. It is shown only in this answer and cannot be read again. */
            token: string;
        };
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
        /** @description What happens to the credential columns, in plain words. */
        CredentialNotice: {
            /** @description Whether this account may store them now. */
            allowed: boolean;
            /** @description Secrets that would be replaced because the value changed. */
            changed: number;
            /** @description The same in English, for logs and clients without translations. */
            detail?: string | null;
            /** @description Hosts with a login or password in the source. */
            hosts: number;
            /** @description Secrets that would be created. */
            new: number;
            /**
             * @description Why not, when not allowed, as a code the UI translates: `forbidden`,
             *     `step_up_required`, `unauthenticated` or `vault_unavailable`.
             */
            reason?: string | null;
            /** @description The statement shown to the user (English; the UI translates by the counts). */
            statement: string;
            /** @description Secrets that are already stored with the same value. */
            unchanged: number;
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
        /**
         * @description What to do with credential columns.
         * @enum {string}
         */
        CredentialPolicy: "import" | "skip";
        /**
         * @description The role of a credential on a host.
         * @enum {string}
         */
        CredentialRole: "admin" | "rdp" | "ssh" | "web" | "other";
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
        /** @description The answer of a decision. */
        Decision: {
            /** @description Whether this is a dry run. */
            dry_run: boolean;
            job_id?: components["schemas"]["JobId"] | null;
            plan?: components["schemas"]["PlanView"] | null;
            /** @description The proposal after the decision; on a dry run, as it is. */
            proposal: components["schemas"]["IntentProposal"];
            /** @description The objects the commands created or changed. */
            results: components["schemas"]["ObjectRef"][];
            /**
             * Format: int64
             * @description The revision that committed the decision; `null` on a dry run.
             */
            revision?: number | null;
            /** @description Warnings of the plan. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description `PUT /settings/default-language` and its answer (API-21). */
        DefaultLanguage: {
            /** @description The language tag: a built-in language or an active language pack. */
            language: string;
        };
        /** @description Defaults a manifest suggests for new instances; the host enforces its own bounds. */
        Defaults: {
            /**
             * Format: int32
             * @description Timeout of one call in seconds (1 to 600; the host default is 30).
             */
            call_timeout_secs?: number | null;
            /**
             * Format: int32
             * @description Seconds between inventory polls (60 to 86,400; the host default is 300).
             */
            poll_interval_secs?: number | null;
        };
        /**
         * @description Which soft-deleted objects a list returns (IPAM-09).
         * @enum {string}
         */
        Deleted: "exclude" | "include" | "only";
        /** @description One line of a read-back diff: what the controller has and what the change would set. */
        DiffEntry: {
            /** @description The planned value; absent when the item goes away. */
            after?: string | null;
            /** @description The current value; absent when the item does not exist. */
            before?: string | null;
            /** @description What changes, for example `networks/iot/vlan`. */
            path: string;
        };
        /** @description SHA-256 digest as 64 lowercase hexadecimal characters */
        Digest: string;
        /** @description Answer of `GET /cluster/digests`: the digests of every member at one revision. */
        DigestReport: {
            /** @description Whether every member answered with the same digest at the same revision. */
            agree: boolean;
            /** @description The digests by node id. */
            members: components["schemas"]["MemberDigest"][];
            /**
             * Format: int64
             * @description The revision every member was asked for (the newest one the answering controller
             *     knows, unless the request named one).
             */
            revision: number;
        };
        /** @description DHCPv6 DUID as lowercase hexadecimal */
        Duid: string;
        /**
         * @description What an edge is.
         * @enum {string}
         */
        EdgeKind: "wired" | "wireless" | "lldp" | "uplink" | "vm_host";
        /** @description One end of a link. */
        Endpoint: {
            /** @description The device, as the source names it. */
            device: string;
            /** @description The port. */
            port?: string | null;
        };
        /** @description Body of `POST /nodes/enrol`: a node presents its token and its certificate request. */
        EnrolRequest: {
            /**
             * @description The node's address as the controller should show it; default the address the
             *     request came from.
             */
            address?: string | null;
            /** @description A PKCS#10 certificate signing request over an ECDSA P-256 key, PEM. */
            csr: string;
            /** @description The protocol majors the node implements. */
            majors?: number[];
            /** @description The node's name; the token's name wins when it has one. */
            name?: string | null;
            /**
             * @description The roles the node runs; default the token's roles. Each must be allowed by the
             *     token.
             */
            roles?: string[];
            /** @description The enrolment token. */
            token: string;
            /** @description The node's software version. */
            version?: string;
        };
        /** @description Answer of `POST /nodes/enrol`. */
        EnrolResponse: {
            /** @description The root of the internal CA, PEM: the node trusts only it on the cluster port. */
            ca_root: string;
            /** @description The node certificate, PEM, leaf first. */
            certificate: string;
            /**
             * Format: int32
             * @description The cluster port of the controller the node enrolled with.
             */
            cluster_port?: number | null;
            /**
             * @description `host:port` endpoints of the cluster port; empty: the host the node enrolled through
             *     with `cluster_port`.
             */
            endpoints: string[];
            /**
             * Format: int32
             * @description Seconds between two heartbeats.
             */
            heartbeat_secs: number;
            /** @description The protocol majors the controller implements. */
            majors: number[];
            /** @description The node as registered. */
            node: components["schemas"]["NodeView"];
        };
        /** @description Body of `GET /nodes/enrolments`. */
        EnrolmentList: {
            /** @description Every token, newest first. */
            items: components["schemas"]["EnrolmentView"][];
        };
        /**
         * @description The state of an enrolment token.
         * @enum {string}
         */
        EnrolmentState: "pending" | "used" | "expired";
        /** @description An enrolment token as `GET /nodes/enrolments` shows it (never the secret). */
        EnrolmentView: {
            /** @description When. */
            created_at: components["schemas"]["Timestamp"];
            /**
             * Format: uuid
             * @description Who created it.
             */
            created_by?: string | null;
            /** @description When it stops working. */
            expires_at: components["schemas"]["Timestamp"];
            /**
             * Format: uuid
             * @description The token id.
             */
            id: string;
            /** @description The name the node gets; the node chooses one when absent. */
            name?: string | null;
            /**
             * Format: int64
             * @description Store revision of the record.
             */
            revision: number;
            /** @description The roles the node may take. */
            roles: string[];
            /** @description `pending`, `used` or `expired`. */
            state: components["schemas"]["EnrolmentState"];
            used?: components["schemas"]["TokenUse"] | null;
            /**
             * Format: uuid
             * @description The VRF of the node's observations.
             */
            vrf?: string | null;
        };
        /**
         * @description How to start an installed plugin: an executable, or a script with its interpreter.
         *     Paths are relative to the plugin directory.
         */
        Entry: {
            /** @description Arguments after the executable or script. */
            args?: string[];
            /** @description The executable, relative to the plugin directory. */
            executable?: string | null;
            /**
             * @description The interpreter of a script, found on `PATH` (`python3`, `node`) or as an absolute
             *     path.
             */
            interpreter?: string | null;
            /** @description The script, relative to the plugin directory. */
            script?: string | null;
        };
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
         * @description What a fact is about, within its source: the source's own identity of the thing it
         *     reports. Two reports of one source about one subject are the same fact, refreshed.
         *
         *     Adjacently tagged (`{"type": "address", "data": {...}}`) because variants carry IP
         *     addresses (see the encoding rules in `tenko_core::codec`).
         */
        FactSubject: {
            /** @description A host of an inventory source, by the source's own identifier (CONN-02). */
            data: {
                /** @description The source's identifier (VM id, entity id). */
                external_id: string;
            };
            /** @enum {string} */
            type: "host";
        } | {
            /** @description An address in use in a VRF (probe sightings, later DHCP leases). */
            data: {
                /** @description The address. */
                ip: string;
                /** @description The VRF of the observing source. */
                vrf: components["schemas"]["VrfId"];
            };
            /** @enum {string} */
            type: "address";
        } | {
            /** @description Where a client is attached (network controller). */
            data: {
                /** @description The client. */
                mac: components["schemas"]["MacAddr"];
            };
            /** @enum {string} */
            type: "attachment";
        } | {
            /** @description The open ports of an address (SCAN-08). */
            data: {
                /** @description The address. */
                ip: string;
            };
            /** @enum {string} */
            type: "services";
        } | {
            /** @description The operating system guess of an address (SCAN-08). */
            data: {
                /** @description The address. */
                ip: string;
            };
            /** @enum {string} */
            type: "os";
        } | {
            /** @description A link between two devices (topology, IPAM-20). */
            data: {
                /** @description One end. */
                a: components["schemas"]["Endpoint"];
                /** @description The other end. */
                b: components["schemas"]["Endpoint"];
                /** @description How the link was learned. */
                kind: components["schemas"]["LinkKind"];
            };
            /** @enum {string} */
            type: "link";
        } | {
            /** @description The name a source found for an address (probes). */
            data: {
                /** @description The address. */
                ip: string;
            };
            /** @enum {string} */
            type: "name";
        } | {
            /** @description The vendor of a MAC address (probes). */
            data: {
                /** @description The MAC address. */
                mac: components["schemas"]["MacAddr"];
            };
            /** @enum {string} */
            type: "vendor";
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
        /** @description An uploaded file. */
        FileView: {
            /** @description The detected format. */
            format: components["schemas"]["SourceFormat"];
            /** @description The name as uploaded. */
            name: string;
            /**
             * Format: int64
             * @description Size in bytes.
             */
            size: number;
            text?: components["schemas"]["TextInfo"] | null;
        };
        /** @description DNS name */
        Fqdn: string;
        /** Format: uuid */
        GrantId: string;
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
        /** @description Result of [`Connector::check`]. */
        HealthReport: {
            /** @description When the check ran. */
            checked_at: components["schemas"]["Timestamp"];
            /** @description English detail for the operator. */
            detail?: string | null;
            /** @description Overall health. */
            health: components["schemas"]["RemoteHealth"];
            /**
             * Format: int64
             * @description Round-trip time of the check in milliseconds.
             */
            latency_ms?: number | null;
            /** @description Version the remote system reports. */
            remote_version?: string | null;
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
        /** @description One binding of a change of a host's credentials. */
        HostCredentialBinding: {
            /** @description Its role on the host. */
            role: components["schemas"]["CredentialRole"];
            /** @description The operator secret. */
            secret: components["schemas"]["SecretId"];
        };
        /** @description One credential of a host. */
        HostCredentialItem: {
            /** @description When it was bound. */
            bound_at: components["schemas"]["Timestamp"];
            /** @description The role of the credential on the host. */
            role: components["schemas"]["CredentialRole"];
            /** @description The secret (metadata only). */
            secret: components["schemas"]["OperatorSecretView"];
        };
        /** @description The new set of credentials of a host: every binding not listed is removed. */
        HostCredentialsUpdate: {
            /** @description The bindings: one per secret, at most 32. */
            credentials: components["schemas"]["HostCredentialBinding"][];
        };
        /** @description The credentials bound to a host. */
        HostCredentialsView: {
            /** @description The host. */
            host: components["schemas"]["HostId"];
            /** @description The credentials, by role and name. */
            items: components["schemas"]["HostCredentialItem"][];
            /**
             * Format: int64
             * @description The version of the set, as in the `ETag`; send it as `If-Match` with a change.
             */
            version: number;
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
        /** @description What an address row shows of a host. */
        HostSummary: {
            /** @description Identifier. */
            id: components["schemas"]["HostId"];
            /** @description Locked against automation. */
            lock: boolean;
            /** @description What IPAM may do with the host's addresses. */
            mode: components["schemas"]["AssignmentMode"];
            /** @description Name. */
            name: components["schemas"]["HostName"];
        };
        /**
         * @description A client-chosen idempotency key (`Idempotency-Key` header, API-04): 1 to 255 visible
         *     ASCII characters.
         *
         *     The store scopes keys per principal subject (see `Principal::subject`), so two users
         *     cannot collide on the same key.
         */
        IdempotencyKey: string;
        /** @description Options of the whole import. */
        ImportOptions: {
            /** @description Warning codes of the plan the user acknowledges (IPAM-06). */
            acknowledge?: string[];
            /** @description What to do with existing objects that differ. */
            conflict?: components["schemas"]["ConflictPolicy"];
            /** @description What to do with credential columns. */
            credentials?: components["schemas"]["CredentialPolicy"];
            /** @description Decisions on proposed prefixes; a proposal without a decision is accepted. */
            proposals?: components["schemas"]["ProposalDecision"][];
            /** @description Tenant of hosts that name none; the default tenant when absent. */
            tenant?: string | null;
            /** @description VRF of items that name none; the default VRF when absent. */
            vrf?: string | null;
        };
        /** @description The preview of an import (`GET /imports/{id}/preview`). */
        ImportPreview: {
            /**
             * Format: int64
             * @description The store revision the preview was computed from.
             */
            base_revision: number;
            /**
             * @description Codes of what stops apply (`import.credentials.vault_required`,
             *     `ipam.plan.unacknowledged`, `import.conflict.kept`, a plan error code).
             */
            blockers: string[];
            /** @description Whether apply would be accepted now. */
            can_apply: boolean;
            /** @description The credential statement. */
            credentials: components["schemas"]["CredentialNotice"];
            /** @description The import. */
            id: string;
            /** @description The loss report by sheet, row and column. */
            loss: components["schemas"]["SheetLoss"][];
            plan_error?: components["schemas"]["PlanProblem"] | null;
            /** @description Proposed prefixes for addresses outside every known network. */
            proposals: components["schemas"]["Proposal"][];
            /** @description The first rows (see `total_rows`). */
            rows: components["schemas"]["PreviewRow"][];
            /** @description Per sheet: what it was read as and its row counts. */
            sheets: components["schemas"]["SheetOutcome"][];
            /** @description Counts. */
            summary: components["schemas"]["PreviewSummary"];
            /** @description Rows with data in the whole import. */
            total_rows: number;
            /** @description Warnings of the IPAM plan; those with `requires_ack` must be acknowledged. */
            warnings: components["schemas"]["PlanWarning"][];
        };
        /** @description A page of the rows of the latest preview of an import. */
        ImportRowsPage: {
            /**
             * Format: int64
             * @description The store revision the preview was computed from.
             */
            base_revision: number;
            /** @description The rows of the page, in source order. */
            items: components["schemas"]["PreviewRow"][];
            /** @description The cursor of the next page; `null` after the last row. */
            next_cursor?: string | null;
            /**
             * Format: int64
             * @description Rows in the whole preview.
             */
            total_rows: number;
        };
        /**
         * @description Where an import stands.
         * @enum {string}
         */
        ImportState: "uploaded" | "mapped" | "applying" | "applied" | "failed";
        /** @description The multipart form of `POST /imports`. */
        ImportUpload: {
            /**
             * @description The spreadsheet or CSV files of one import: repeat the part for several files (for
             *     example the files of a CSV export). A part is a file when it has a `filename`. All
             *     files together are limited to 20 MB, and an upload is staged for 24 hours.
             */
            files: string[];
        };
        /**
         * @description An upload with its analysis and mapping (`GET /imports/{id}`, the answer of
         *     `POST /imports` and `PUT /imports/{id}/mapping`).
         */
        ImportView: {
            /** @description Upload time. */
            created: string;
            /** @description When the staged upload is discarded. */
            expires: string;
            /** @description The uploaded files. */
            files: components["schemas"]["FileView"][];
            /** @description The import. */
            id: string;
            /** @description The latest apply job. */
            job_id?: string | null;
            /** @description Whether `mapping` is the user's (`true`) or the suggestion. */
            mapped: boolean;
            /** @description The mapping in force: the user's, else the suggested one. */
            mapping: components["schemas"]["Mapping"];
            /** @description Every sheet with its columns, shapes, samples and suggestion. */
            sheets: components["schemas"]["SheetAnalysis"][];
            /** @description Where it stands. */
            state: components["schemas"]["ImportState"];
            /** @description The targets the mapping step offers (custom fields included). */
            targets: components["schemas"]["TargetInfo"][];
        };
        /** @description How this installation can install a new version. */
        InstallAbility: {
            /** @description `POST /system/updates/install` would start now. */
            from_source: boolean;
            from_source_blocked?: components["schemas"]["InstallBlock"] | null;
            /** @description The policy of TGL-23. */
            policy: components["schemas"]["InstallPolicy"];
            /** @description Containers: the command that pulls the newest image. */
            pull_command?: string | null;
            /**
             * Format: int64
             * @description Seconds a new version has to become ready before it is switched back.
             */
            ready_timeout_secs: number;
            /** @description Installing needs a fresh authentication (step-up). */
            step_up: boolean;
            /** @description `POST /system/updates/upload` is possible. */
            upload: boolean;
            upload_blocked?: components["schemas"]["InstallBlock"] | null;
        };
        /**
         * @description Why an installation path is not available.
         * @enum {string}
         */
        InstallBlock: "container" | "cluster" | "layout_missing" | "unsupervised" | "unsupported_platform" | "upload_only" | "air_gapped" | "no_asset" | "up_to_date" | "in_progress";
        /**
         * @description How an administrator may install a new version (TGL-23).
         * @enum {string}
         */
        InstallPolicy: "ui" | "ui_step_up" | "upload_only";
        /** @description `POST /system/updates/install`. */
        InstallRequest: {
            /** @description The version to install; it must be in the manifest and newer than the running one. */
            version: components["schemas"]["ReleaseVersion"];
        };
        /** @description The answer of `POST /system/updates/install` and `POST /system/updates/upload`. */
        InstallStarted: {
            /**
             * @description The install job: download (or the uploaded file), verification, dry run and switch.
             *     The server restarts into the new version when it succeeds.
             */
            job_id: components["schemas"]["JobId"];
            /** @description The version being installed. */
            version: components["schemas"]["ReleaseVersion"];
        };
        /** @description An address of intent on a node. */
        IntentAddress: {
            /** @description The network. */
            cidr: string;
            /** @description The address. */
            ip: string;
            /** @description Its network. */
            prefix: components["schemas"]["PrefixId"];
            /**
             * Format: int32
             * @description The VLAN id.
             */
            vid?: number | null;
            vlan?: components["schemas"]["VlanId"] | null;
        };
        /**
         * @description The intent objects that match a subject: interfaces by MAC address, addresses by IP
         *     address (in any VRF), hosts by name and through their interfaces. Live objects only.
         */
        IntentMatch: {
            /** @description Addresses. */
            addresses: components["schemas"]["AddressId"][];
            /** @description Hosts. */
            hosts: components["schemas"]["HostId"][];
            /** @description Interfaces. */
            interfaces: components["schemas"]["InterfaceId"][];
            /** @description VRFs of the matching addresses. */
            vrfs: components["schemas"]["VrfId"][];
        };
        /**
         * @description A suggestion of the reconciler: evidence, the commands that would resolve it, and the
         *     decision (IPAM-15). Stored in `ipam.proposals`.
         */
        IntentProposal: {
            adopted_by?: components["schemas"]["PrefixId"] | null;
            /**
             * @description The error code of the last failed adoption; the policy does not try again until
             *     the proposal is replaced.
             */
            adoption_error?: string | null;
            /** @description The commands an approval applies (empty for conflicts, which a person resolves). */
            commands?: components["schemas"]["IpamCommand"][];
            /** @description When it was opened. */
            created: components["schemas"]["Timestamp"];
            decided?: components["schemas"]["Stamp"] | null;
            /** @description The observations behind it. */
            evidence: components["schemas"]["ProposalEvidence"][];
            /**
             * @description SHA-256 over the canonical CBOR of the kind, the subject key, the evidence
             *     identities (sources, subjects, paired addresses) and the commands: equal evidence,
             *     equal fingerprint. A rejection is remembered by it.
             */
            fingerprint: components["schemas"]["Digest"];
            /** @description Identifier. */
            id: components["schemas"]["ProposalId"];
            /**
             * @description The subject key: kind and subject, unique among open proposals
             *     (`discovered_host/mac:00:00:5e:00:53:01`).
             */
            key: string;
            /** @description The kind. */
            kind: components["schemas"]["IntentProposalKind"];
            /** @description Named parameters of the summary, for translation. */
            params?: {
                [key: string]: string;
            };
            /** @description The rejection reason, or why it expired. */
            reason?: string | null;
            /** @description The objects its commands created or changed, once accepted. */
            results?: components["schemas"]["ObjectRef"][];
            /**
             * Format: int64
             * @description Store revision (filled when read; `ETag` and `If-Match` of the decisions).
             */
            revision?: number;
            /**
             * @description The rule that produced it, a stable code such as
             *     `ipam.reconcile.discovered_mac`; the UI translates it with [`Self::params`].
             */
            rule: string;
            /** @description How urgent it is. */
            severity: components["schemas"]["ProposalSeverity"];
            /** @description The decision state. */
            state: components["schemas"]["IntentProposalState"];
            /** @description The subject. */
            subject: components["schemas"]["ProposalSubject"];
            /** @description English one-line summary. */
            summary: string;
            superseded_by?: components["schemas"]["ProposalId"] | null;
            /** @description When it last changed. */
            updated: components["schemas"]["Timestamp"];
        };
        /**
         * @description What a proposal is about.
         * @enum {string}
         */
        IntentProposalKind: "discovered_host" | "orphaned_intent" | "address_mismatch" | "conflict" | "outside_prefixes";
        /**
         * @description The decision state of a proposal.
         * @enum {string}
         */
        IntentProposalState: "open" | "accepted" | "rejected" | "expired" | "superseded";
        /**
         * @description When an intent object (an address or an interface) was last matched by a current
         *     observation; written by the reconciler at most once per refresh interval.
         */
        IntentSighting: {
            /** @description The latest matching sighting (the source's time). */
            at: components["schemas"]["Timestamp"];
            /** @description The observation behind it. */
            observation: components["schemas"]["ObservationId"];
            /** @description The source of that sighting. */
            source: string;
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
        /** @description What an address row shows of an interface. */
        InterfaceSummary: {
            duid?: components["schemas"]["Duid"] | null;
            /** @description Identifier. */
            id: components["schemas"]["InterfaceId"];
            mac?: components["schemas"]["MacAddr"] | null;
            /** @description Name, such as `eth0`. */
            name: string;
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
        /**
         * @description What reconciling did to an item.
         * @enum {string}
         */
        ItemAction: "create" | "update" | "unchanged" | "kept";
        /** @description A model item, by natural key. */
        ItemKey: {
            /** @enum {string} */
            kind: "vlan";
            /** @description Site name, `None` for global. */
            site?: string | null;
            /**
             * Format: int32
             * @description VLAN id.
             */
            vid: number;
        } | {
            /** @description The network. */
            cidr: string;
            /** @enum {string} */
            kind: "prefix";
            /** @description VRF name (lowercase). */
            vrf: string;
        } | {
            /** @enum {string} */
            kind: "host";
            /** @description Host name. */
            name: string;
        } | {
            /** @description Host name. */
            host: string;
            /** @enum {string} */
            kind: "interface";
            /** @description Interface name. */
            name: string;
        } | {
            /** @description The address. */
            ip: string;
            /** @enum {string} */
            kind: "address";
            /** @description VRF name (lowercase). */
            vrf: string;
        } | {
            /** @description Host name. */
            host: string;
            /** @enum {string} */
            kind: "credential";
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
            node?: components["schemas"]["NodeId"] | null;
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
        /** @description One key generation of the installation, as this controller sees it. */
        KekGenerationView: {
            /** @description Whether the generation wraps new data keys. */
            active: boolean;
            created_at?: components["schemas"]["Timestamp"] | null;
            /** @description The identifier that envelopes name. */
            id: string;
            /** @description Whether this controller holds the generation. */
            loaded: boolean;
            protection?: components["schemas"]["KekProtectionView"] | null;
        };
        /** @description How a key-encryption key is protected at rest. */
        KekProtectionView: {
            /**
             * @description A stable code: `dpapi_user`, `dpapi_machine`, `systemd_creds_host`,
             *     `systemd_creds_tpm2`, `plain_file` or `memory`. The UI localizes by this code.
             */
            code: string;
            /** @description A short English description, for logs and support. */
            text: string;
            /** @description Whether the protection is weak enough to warn about: a plain key file or memory only. */
            weak: boolean;
        };
        /**
         * @description Where an online rotation of the key-encryption key stands.
         * @enum {string}
         */
        KekRotationPhase: "requested" | "distributing" | "rewrapping" | "done" | "failed";
        /** @description An online rotation of the key-encryption key: in progress, or the last one. */
        KekRotationView: {
            /** @description Why the rotation failed. */
            error?: string | null;
            finished_at?: components["schemas"]["Timestamp"] | null;
            /** @description The new generation, once the leader created it. */
            generation?: string | null;
            /** @description Where the rotation stands. */
            phase: components["schemas"]["KekRotationPhase"];
            /** @description When an administrator asked for it. */
            requested_at: components["schemas"]["Timestamp"];
            /** @description Who asked, as a principal subject such as `user:<id>`. */
            requested_by: string;
            /**
             * Format: int64
             * @description How many envelopes are re-wrapped under the new generation so far.
             */
            rewrapped: number;
            /**
             * @description Controllers that could not be reached while the generation was distributed; each
             *     fetches it when it starts.
             */
            unreachable: number[];
            /** @description When the phase last changed. */
            updated_at: components["schemas"]["Timestamp"];
            /** @description Reachable controllers that have not taken the new generation yet. */
            waiting_for: number[];
        };
        /** @description The key-encryption keys of this controller and of the installation. */
        KekStatusView: {
            /** @description The active generation, which wraps new data keys. */
            active: string;
            /** @description How every controller of the installation protects its key, by node. */
            controllers: components["schemas"]["ControllerKekView"][];
            /**
             * Format: int64
             * @description The KEK epoch of the active generation; it grows with every activation.
             */
            epoch: number;
            /** @description Every generation of the installation and every generation loaded here, oldest first. */
            generations: components["schemas"]["KekGenerationView"][];
            /**
             * @description Generations of the installation that this controller does not hold; it fetches them
             *     from a member.
             */
            missing: string[];
            /**
             * Format: int64
             * @description The controller that answers.
             */
            node: number;
            /** @description The protection of its active key-encryption key. */
            protection: components["schemas"]["KekProtectionView"];
            /** @description Its provider: `dpapi`, `systemd_creds`, `systemd_credential` or `file`. */
            provider: string;
            /** @description Plain generation files that this controller refused to load. */
            refused: components["schemas"]["RefusedGenerationView"][];
            rotation?: components["schemas"]["KekRotationView"] | null;
            strongest?: components["schemas"]["KekProtectionView"] | null;
            /**
             * @description Conditions to look at: `vault.kek.weak`, `vault.kek.downgrade`, `vault.kek.missing`
             *     and `vault.kek.rotation_failed`.
             */
            warnings: components["schemas"]["StatusWarning"][];
        };
        /** @description The key-encryption key fragment of `GET /system/status`. */
        KekSummaryView: {
            /** @description The active generation. */
            active: string;
            /**
             * Format: int64
             * @description The KEK epoch.
             */
            epoch: number;
            /**
             * Format: int64
             * @description How many generations this controller holds.
             */
            generations: number;
            /** @description The protection of its active key-encryption key. */
            protection: components["schemas"]["KekProtectionView"];
            /**
             * @description The provider of this controller: `dpapi`, `systemd_creds`, `systemd_credential` or
             *     `file`.
             */
            provider: string;
            rotation?: components["schemas"]["KekRotationPhase"] | null;
        };
        /** @description A language the UI offers to everyone (`GET /i18n/languages`). */
        LanguageInfo: {
            /** @description Whether the UI has the language built in. */
            built_in: boolean;
            /**
             * @description The content hash of the active uploaded pack, which `GET /i18n/packs/{tag}` serves;
             *     absent for a built-in language without an uploaded override.
             */
            hash?: string | null;
            /** @description The language's name in itself. */
            name: string;
            /** @description The BCP 47 tag. */
            tag: string;
        };
        /** @description The languages of the installation (`GET /i18n/languages`). */
        LanguageList: {
            /** @description The installation's default language, once setup has run. */
            default_language?: string | null;
            /** @description The built-in languages, then the active uploaded ones by tag. */
            languages: components["schemas"]["LanguageInfo"][];
        };
        /** @description The last reveal of a secret: who and when, never the value or the reason. */
        LastReveal: {
            /** @description When. */
            at: components["schemas"]["Timestamp"];
            host?: components["schemas"]["HostId"] | null;
            user?: components["schemas"]["UserId"] | null;
            /** @description Their login name at the time. */
            user_name?: string | null;
        };
        /** @description The last run of an instance. */
        LastRun: {
            /**
             * Format: int32
             * @description Failed runs in a row, this one included.
             */
            consecutive_failures?: number;
            /** @description The cursor of the last successful inventory read, for an incremental next poll. */
            cursor?: string | null;
            error?: components["schemas"]["CodedError"] | null;
            /** @description When it ended. */
            finished_at: components["schemas"]["Timestamp"];
            job?: components["schemas"]["JobId"] | null;
            last_full_at?: components["schemas"]["Timestamp"] | null;
            last_success_at?: components["schemas"]["Timestamp"] | null;
            /**
             * Format: int32
             * @description Observations handed on.
             */
            observations: number;
            /** @description How it ended. */
            outcome: components["schemas"]["RunOutcome"];
            /**
             * Format: int32
             * @description Pages read.
             */
            pages: number;
            /** @description When it started. */
            started_at: components["schemas"]["Timestamp"];
            /** @description What started it. */
            trigger: components["schemas"]["RunTrigger"];
            /** @description Values the host dropped or replaced (at most 20). */
            warnings?: string[];
        };
        /**
         * @description How a link was learned.
         * @enum {string}
         */
        LinkKind: "lldp" | "uplink" | "wired" | "wireless";
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
        /** @description Loss report entries by severity. */
        LossCounts: {
            /** @description Errors (values or rows not imported). */
            error: number;
            /** @description Information. */
            info: number;
            /** @description Warnings. */
            warning: number;
        };
        /** @description One loss report entry. */
        LossItem: {
            /** @description Stable code (`import.address.unparsable`). */
            code: string;
            /** @description Column letter, when the entry is about a column or cell. */
            column?: string | null;
            /** @description English explanation with the offending value. */
            detail: string;
            /**
             * Format: int32
             * @description Row number (1-based), when the entry is about a row or cell.
             */
            row?: number | null;
            /** @description How serious it is. */
            severity: components["schemas"]["Severity"];
        };
        /** @description MAC address, lowercase and colon-separated (00:00:5e:00:53:01) */
        MacAddr: string;
        /** @description A plugin manifest. */
        Manifest: {
            /** @description The interfaces the plugin implements. */
            capabilities: components["schemas"]["Capability"][];
            /** @description Defaults the host applies to new instances. */
            defaults?: components["schemas"]["Defaults"];
            /** @description One or two English sentences for the operator. */
            description: string;
            entry?: components["schemas"]["Entry"] | null;
            /** @description Where to read more. */
            homepage?: string | null;
            /** @description SPDX licence expression of the plugin. */
            license?: string | null;
            /**
             * Format: int32
             * @description The manifest format; `1`.
             */
            manifest_version: number;
            /**
             * @description The plugin name: lowercase ASCII letters, digits and `-`, starting with a letter, at
             *     most 63 characters. Unique among the plugins of an installation.
             */
            name: string;
            /**
             * @description The network targets the plugin contacts, shown to the operator before an instance
             *     is created.
             */
            network?: components["schemas"]["NetworkTarget"][];
            /**
             * @description The platforms the plugin runs on: `any` (scripts) or `<os>-<arch>` as Rust names
             *     them, for example `linux-x86_64`, `linux-aarch64`, `windows-x86_64`.
             */
            platforms: string[];
            /** @description The protocol major versions the plugin speaks. */
            protocol: number[];
            /** @description The secrets the plugin may receive. The host injects nothing else. */
            secrets?: components["schemas"]["SecretDecl"][];
            /**
             * @description The JSON Schema of the settings of an instance (see the module documentation for
             *     the supported subset). Absent means no settings.
             */
            settings?: Record<string, never>;
            /**
             * @description The plugin version (semantic versioning, `MAJOR.MINOR.PATCH` with an optional
             *     pre-release and build suffix).
             */
            version: string;
        };
        /** @description The stored release manifest. */
        ManifestInfo: {
            /** @description When it was fetched or uploaded. */
            at: components["schemas"]["Timestamp"];
            /** @description Where it came from. */
            origin: components["schemas"]["ManifestOrigin"];
            /** @description Releases it lists. */
            releases: number;
        };
        /**
         * @description Where the stored release manifest came from.
         * @enum {string}
         */
        ManifestOrigin: "fetched" | "uploaded";
        /** @description One problem of a manifest or of instance settings. */
        ManifestProblem: {
            /** @description What is wrong, in English. */
            message: string;
            /**
             * @description JSON pointer of the offending member, for example `/secrets/0/purpose`; empty for
             *     the document as a whole.
             */
            path: string;
        };
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
        /** @description The mapping of an import: one entry per sheet, and the options. */
        Mapping: {
            /** @description Options. */
            options?: components["schemas"]["ImportOptions"];
            /** @description Sheet mappings, in upload order. */
            sheets: components["schemas"]["SheetMapping"][];
        };
        /**
         * @description Where the network of a sheet comes from.
         * @enum {string}
         */
        MaskSource: "index" | "name" | "row_count" | "addresses" | "user";
        /** @description The state digest of one member. */
        MemberDigest: {
            /**
             * Format: int64
             * @description Rows in the digest.
             */
            entries?: number | null;
            /** @description Why the member gave no digest (an error code), if it did not. */
            error?: string | null;
            /**
             * Format: int64
             * @description The member.
             */
            node: number;
            /**
             * Format: int64
             * @description The revision the digest covers.
             */
            revision?: number | null;
            /** @description The SHA-256 over every table at that revision, lower-case hex. */
            sha256?: string | null;
            /**
             * Format: int64
             * @description Non-empty tables in the digest.
             */
            tables?: number | null;
        };
        /**
         * @description Whether a member votes.
         * @enum {string}
         */
        MemberRole: "voter" | "learner";
        /** @description One member of the controller cluster. */
        MemberView: {
            /** @description Its cluster port as `host:port`. */
            address?: string | null;
            /**
             * Format: int32
             * @description The data format its binary knows.
             */
            data_format?: number | null;
            joined_at?: components["schemas"]["Timestamp"] | null;
            /**
             * Format: int64
             * @description Log entries it is behind the leader.
             */
            lag_entries?: number | null;
            /**
             * Format: int64
             * @description Milliseconds since the leader last heard from it.
             */
            last_contact_ms?: number | null;
            /** @description Whether it leads. */
            leader: boolean;
            /**
             * Format: int64
             * @description The last log index known to match the leader's log.
             */
            matched?: number | null;
            /** @description Its name in the node registry. */
            name?: string | null;
            /**
             * Format: int64
             * @description The node id (also its Raft id).
             */
            node: number;
            /** @description Voter or learner. */
            role: components["schemas"]["MemberRole"];
            /** @description The software version it reported when it joined or last started. */
            version?: string | null;
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
        /** @description A refused handshake. */
        MismatchRecord: components["schemas"]["VersionMismatch"] & {
            /** @description When it happened. */
            at: components["schemas"]["Timestamp"];
            /** @description The software version the node reported. */
            version: string;
        };
        /**
         * @description A product module that an installation can enable or disable (OPS-25).
         * @enum {string}
         */
        Module: "ipam" | "dns" | "dhcp" | "discovery";
        /**
         * @description What happens to a module change that the running server cannot apply by itself.
         * @enum {string}
         */
        ModuleRestart: "none" | "scheduled" | "required";
        /** @description Product modules in canonical order: ipam, dns, dhcp, discovery (OPS-25). */
        ModuleSet: ("ipam" | "dns" | "dhcp" | "discovery")[];
        /** @description `GET /system/modules` and the answer of `PUT /system/modules` (OPS-25). */
        ModuleSettings: {
            /**
             * @description The modules the next start runs: `modules` of `tenko.toml` when it sets them, else
             *     the installation's choice, else every module.
             */
            configured: components["schemas"]["ModuleSet"];
            /** @description `tenko.toml` sets the modules; the installation's choice cannot change them. */
            pinned: boolean;
            /** @description Whether a restart is pending to apply `configured`. */
            restart: components["schemas"]["ModuleRestart"];
            /** @description The modules the server runs now. */
            running: components["schemas"]["ModuleSet"];
        };
        /** @description `PUT /system/modules`: what the installation is for (the first-run wizard asks). */
        ModulesRequest: {
            /** @description The modules to run. */
            modules: components["schemas"]["ModuleSet"];
        };
        /** @description Where the network controller sees a device now. */
        MoveAttachment: {
            /** @description The switch or access point, by controller reference. */
            device: string;
            /** @description Its name. */
            device_name: string;
            /** @description Wired or wireless. */
            medium: components["schemas"]["MoveMedium"];
            /** @description The network the device is in now, by controller reference. */
            network?: string | null;
            /** @description Its name. */
            network_name?: string | null;
            /**
             * Format: int32
             * @description The switch port.
             */
            port?: number | null;
            /** @description The port's name. */
            port_name?: string | null;
            /** @description The port's profile now, by controller reference. */
            profile?: string | null;
            /** @description Its name. */
            profile_name?: string | null;
            /** @description The wireless network. */
            ssid?: string | null;
            /**
             * Format: int32
             * @description The VLAN the device is in now.
             */
            vlan?: number | null;
        };
        /** @description The DNS change of an item. */
        MoveDns: {
            /** @description The name. */
            name: string;
            /** @description What it will point to. */
            new?: string | null;
            /** @description What the name points to now. */
            old?: string | null;
        };
        /** @description One address that moves. */
        MoveItem: {
            dns?: components["schemas"]["MoveDns"] | null;
            host?: components["schemas"]["HostId"] | null;
            /** @description The host's name. */
            host_name?: string | null;
            interface?: components["schemas"]["InterfaceId"] | null;
            /** @description The L2 step: how the device gets into the target VLAN. */
            l2?: components["schemas"]["MoveL2"];
            mac?: components["schemas"]["MacAddr"] | null;
            mode?: components["schemas"]["AssignmentMode"] | null;
            /** @description The identifier the new address will have. */
            new_address: components["schemas"]["AddressId"];
            /**
             * @description The address after the move.
             * @example 198.51.100.10
             */
            new_ip: string;
            /** @description The address that moves. */
            object: components["schemas"]["ObjectRef"];
            /**
             * @description The address now.
             * @example 192.0.2.10
             */
            old_ip: string;
            /** @description Why not (`ipam.move.host_part_*`). */
            reason?: string | null;
            /** @description What the request named (the address itself or its host). */
            requested: components["schemas"]["ObjectRef"];
            /** @description Whether the host part stays. */
            same_host_part: boolean;
            /** @description The steps of the item's job, in order. */
            steps: components["schemas"]["MoveStepPreview"][];
            /** @description Warnings of this item. */
            warnings?: components["schemas"]["PlanWarning"][];
        };
        /** @description The job of one item. */
        MoveJob: {
            /** @description Its job. */
            job_id: components["schemas"]["JobId"];
            /** @description The address that moves. */
            object: components["schemas"]["ObjectRef"];
        };
        /** @description The L2 step of a device, as previewed (IPAM-19 step 4). */
        MoveL2: {
            /** @description What happens. */
            action: components["schemas"]["MoveL2Action"];
            attachment?: components["schemas"]["MoveAttachment"] | null;
            change?: components["schemas"]["AttachmentChange"] | null;
            connector?: components["schemas"]["ControllerInfo"] | null;
            /**
             * @description What changes on the controller, from its state as read for the preview; the job
             *     records the controller's own read-back diff when it writes.
             */
            diff?: components["schemas"]["DiffEntry"][];
            /** @description The name of the controller's network for the target VLAN. */
            network_name?: string | null;
            /** @description Notes about the change (`ipam.move.l2.note.*`). */
            notes?: string[];
            /**
             * Format: int32
             * @description How many other devices are on the switch port.
             */
            others_on_port?: number | null;
            problem?: components["schemas"]["MoveL2Problem"] | null;
            /** @description The name of the port profile the port gets. */
            profile_name?: string | null;
            read_at?: components["schemas"]["Timestamp"] | null;
            /** @description Why a person moves the device, or why there is no step (`ipam.move.l2.*`). */
            reason?: string | null;
            /**
             * @description The SSIDs that carry the target VLAN: joining one is a change on the device itself
             *     (CONN-18).
             */
            ssids?: string[];
            with?: components["schemas"]["AddressId"] | null;
        };
        /**
         * @description How a device gets into the target VLAN (IPAM-19 step 4).
         * @enum {string}
         */
        MoveL2Action: "port_profile" | "client_vlan" | "manual" | "unchanged" | "shared";
        /** @description The refusal or controller error behind a manual L2 step. */
        MoveL2Problem: {
            /** @description The code, such as `connect.guardrail.uplink` or `connect.unreachable`. */
            code: string;
            /** @description English detail. */
            detail: string;
        };
        /**
         * @description How a device is attached.
         * @enum {string}
         */
        MoveMedium: "wired" | "wireless";
        /** @description The preview of a move (the dry run). */
        MovePreview: {
            /**
             * Format: int64
             * @description The store revision the preview was computed at.
             */
            base_revision: number;
            /** @description The network controllers that were read for the L2 steps. */
            controllers?: components["schemas"]["ControllerInfo"][];
            /**
             * @description Fingerprint of what would run: the addresses, the steps and the L2 changes. A
             *     submit with it as `expect_fingerprint` runs this plan or nothing.
             */
            fingerprint?: string;
            /** @description One item per moved address. */
            items: components["schemas"]["MoveItem"][];
            /**
             * Format: int32
             * @description How many jobs run at once.
             */
            parallelism: number;
            /** @description The target. */
            target: components["schemas"]["MoveTarget"];
            /**
             * Format: int32
             * @description The observation timeout in seconds.
             */
            timeout_secs: number;
            /** @description How the timeout was chosen. */
            timeout_source: components["schemas"]["MoveTimeoutSource"];
            /** @description Warning codes that need an acknowledgement before a submit. */
            unacknowledged?: string[];
            /** @description Every warning of the move (also listed per item where it belongs). */
            warnings?: components["schemas"]["PlanWarning"][];
        };
        /** @description A move request. */
        MoveRequest: {
            /** @description Warning codes the caller acknowledges. */
            acknowledge?: string[];
            /**
             * @description The `fingerprint` of the preview the caller confirms: a submit whose plan differs
             *     answers 409 `ipam.move.plan_changed` and starts nothing.
             */
            expect_fingerprint?: string | null;
            /** @description Hosts or addresses to move. */
            objects: components["schemas"]["ObjectRef"][];
            /**
             * Format: int32
             * @description How many of the move's jobs run at once; the configured parallelism when absent.
             */
            parallelism?: number | null;
            /** @description The target network prefix. */
            target: components["schemas"]["PrefixId"];
            /**
             * Format: int32
             * @description Observation timeout in seconds, 300 to 604,800; half the target's DHCP lease (else
             *     3,600) when absent.
             */
            timeout_secs?: number | null;
        };
        /** @description One step of an item, as previewed. */
        MoveStepPreview: {
            /** @description Whether Tenko does it; otherwise a person ticks it off. */
            automatic: boolean;
            /**
             * @description `ipam.intent`, `dhcp.manual`, `dns.manual`, `device.manual`, `l2.move`, `observe`
             *     or `cleanup`.
             */
            kind: string;
            /**
             * @description References and values for the text and for automation (prefix, VLAN, address,
             *     MAC).
             */
            params: {
                [key: string]: string;
            };
            /** @description The engine's step kind (`ipam.move.intent`, ...). */
            step_kind: string;
            /** @description English description. */
            text: string;
        };
        /** @description The answer of a submitted move. */
        MoveSubmitted: {
            /** @description The job group of the move. */
            group: string;
            /** @description The items as computed at submit, to compare with the preview. */
            items: components["schemas"]["MoveItem"][];
            /** @description One job per item, in item order. */
            jobs: components["schemas"]["MoveJob"][];
            /**
             * Format: int32
             * @description How many jobs run at once.
             */
            parallelism: number;
            /** @description Whether an earlier answer was returned for a repeated idempotency key. */
            replayed?: boolean;
            /**
             * Format: int32
             * @description The observation timeout in seconds.
             */
            timeout_secs: number;
            /** @description Warnings of the move. */
            warnings?: components["schemas"]["PlanWarning"][];
        };
        /** @description The target of a move. */
        MoveTarget: {
            /**
             * @description Its network.
             * @example 198.51.100.0/24
             */
            cidr: string;
            /**
             * Format: int32
             * @description The longest DHCP lease of its pools, in seconds.
             */
            lease_secs?: number | null;
            /** @description The prefix. */
            prefix: components["schemas"]["PrefixId"];
            /**
             * Format: int32
             * @description The VLAN id.
             */
            vid?: number | null;
            vlan?: components["schemas"]["VlanId"] | null;
            /** @description Its VRF. */
            vrf: components["schemas"]["VrfId"];
        };
        /**
         * @description How the observation timeout of a move was chosen.
         * @enum {string}
         */
        MoveTimeoutSource: "request" | "lease" | "default";
        /** @description A neighbour of a node across one edge. */
        Neighbour: {
            /** @description The edge. */
            edge: string;
            /** @description The kind of the edge. */
            edge_kind: components["schemas"]["EdgeKind"];
            /** @description Its kind. */
            kind: components["schemas"]["NodeKind"];
            /** @description Its label. */
            label: string;
            /** @description The neighbour. */
            node: string;
            /** @description The port on this node's side. */
            port?: string | null;
            /** @description The port on the neighbour's side. */
            remote_port?: string | null;
            /** @description The wireless network of the edge. */
            ssid?: string | null;
            /**
             * Format: int32
             * @description The VLAN of the edge.
             */
            vlan?: number | null;
        };
        /** @description A network of a controller with the VLAN it carries. */
        NetworkInView: components["schemas"]["ControllerNetwork"] & {
            /** @description The controller. */
            connector: components["schemas"]["ConnectorId"];
        };
        /**
         * @description The network Tenko asks a controller to have for a VLAN: the controller's DHCP off, or
         *     relaying to the given servers (Tenko serves DHCP).
         */
        NetworkSpec: {
            /** @description DHCP relay targets; empty means the controller's DHCP is off. */
            dhcp_relay?: string[];
            /** @description The network name on the controller. */
            name: string;
            /**
             * Format: int32
             * @description The VLAN id.
             */
            vid: number;
        };
        /**
         * @description A network target a plugin contacts: the host named by a settings member, or a fixed
         *     host.
         */
        NetworkTarget: {
            /** @description What the target is, for the operator. */
            description: string;
            /** @description A fixed host name or IP address. */
            host?: string | null;
            /** @description The ports, when known. */
            ports?: number[];
            /**
             * @description A JSON pointer to the settings member that holds the address (a URI, host name or
             *     IP address), for example `/url`.
             */
            setting?: string | null;
        };
        /** @description The body of a create request. */
        NewConnector: {
            /**
             * Format: int32
             * @description Timeout of one call in seconds (1 to 600).
             */
            call_timeout_secs?: number | null;
            /** @description Whether the instance starts enabled. */
            enabled?: boolean;
            /** @description The display name. */
            name: string;
            /** @description The plugin name. */
            plugin: string;
            /**
             * Format: int32
             * @description Seconds between scheduled reads (60 to 86,400).
             */
            poll_interval_secs?: number | null;
            /** @description Vault references by secret purpose. */
            secrets?: {
                [key: string]: components["schemas"]["SecretRef"];
            };
            /** @description The settings; validated against the plugin's settings schema. */
            settings?: Record<string, never>;
            /** @description Whether writes are allowed (TGL-20). */
            writes_enabled?: boolean;
        };
        /** @description Body of `POST /nodes/enrolments`. */
        NewEnrolment: {
            /**
             * Format: int64
             * @description Seconds until the token expires: 60 to 604,800 (seven days); default 3,600.
             */
            expires_in_secs?: number | null;
            /** @description The name the node gets; without it the node chooses one (its host name). */
            name?: string | null;
            /** @description The roles the node may take (`probe`, `dns`, `dhcp`); default `probe`. */
            roles?: string[];
            /**
             * Format: uuid
             * @description The VRF of the node's observations; default the default VRF.
             */
            vrf?: string | null;
        };
        /** @description A new operator secret. */
        NewOperatorSecret: {
            /** @description What it is. */
            kind: components["schemas"]["SecretKind"];
            /** @description The name: 1 to 128 visible characters. */
            name: string;
            /** @description Notes (at most 2,000 characters). Notes are not secret: never put a value here. */
            notes?: string | null;
            /**
             * @description Purpose tags: up to 16, each 1 to 64 characters of `a-z`, `0-9`, `.`, `_` and `-`
             *     (upper case is folded).
             */
            tags?: string[];
            /** @description The user name that goes with it (at most 256 characters). */
            username?: string | null;
            /**
             * @description The value, as text (1 byte to 64 KiB). Stored encrypted; never returned except by
             *     the reveal.
             */
            value: components["schemas"]["SecretString"];
        };
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
            /**
             * Format: int32
             * @description DHCP lease time in seconds, 60 to 31,536,000 (`dhcp_pool` ranges only); half of it is
             *     the default timeout of moves into the prefix.
             */
            lease_secs?: number | null;
            /** @description What the range is for. */
            role: components["schemas"]["RangeRole"];
            status?: components["schemas"]["Status"] | null;
            /** @description Tags. */
            tags?: components["schemas"]["Tag"][];
        };
        /** @description A VLAN the job creates. */
        NewVlan: {
            /** @description Free text. */
            description?: string | null;
            /** @description Name. */
            name: string;
            site?: components["schemas"]["SiteId"] | null;
            /** @description Tags. */
            tags?: components["schemas"]["Tag"][];
            /**
             * Format: int32
             * @description VLAN id, 1 to 4094, unique per site.
             */
            vid: number;
            /**
             * Format: int32
             * @description VXLAN network identifier.
             */
            vni?: number | null;
        };
        /** @description A network prefix the job creates for the VLAN. */
        NewVlanPrefix: {
            /**
             * @description The network.
             * @example 198.51.100.0/24
             */
            cidr: string;
            /** @description Free text. */
            description?: string | null;
            vrf?: components["schemas"]["VrfId"] | null;
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
        /** @description The intent behind a node. */
        NodeIntent: {
            /** @description Its live addresses. */
            addresses: components["schemas"]["IntentAddress"][];
            /** @description The host. */
            host: components["schemas"]["HostId"];
            /** @description Its assignment mode. */
            mode: components["schemas"]["AssignmentMode"];
            /** @description Its name. */
            name: string;
        };
        /**
         * @description What a node is.
         * @enum {string}
         */
        NodeKind: "router" | "switch" | "access_point" | "hypervisor" | "vm" | "container" | "host" | "device";
        /** @description Identity and roles of the node. */
        NodeStatus: {
            id?: components["schemas"]["NodeId"] | null;
            /** @description Roles this node runs: `controller`, `dns`, `dhcp`, `probe`. */
            roles: string[];
        };
        /** @description A node as `GET /nodes` shows it: the stored record and the live connection. */
        NodeView: {
            /** @description The address the node gave at enrolment, else the address it enrolled from. */
            address?: string | null;
            /** @description The newest certificate. */
            certificate: components["schemas"]["CertificateRef"];
            /**
             * @description Whether the node is connected to a controller of the cluster now (this one or
             *     another; `connection.controller` names it).
             */
            connected: boolean;
            connection?: components["schemas"]["ConnectionView"] | null;
            /** @description When the node enrolled. */
            enrolled_at: components["schemas"]["Timestamp"];
            /**
             * Format: uuid
             * @description The user who created the enrolment token.
             */
            enrolled_by?: string | null;
            /**
             * Format: int64
             * @description The node id.
             */
            id: number;
            last_seen?: components["schemas"]["Timestamp"] | null;
            /** @description Its name. */
            name: string;
            /** @description Protocol negotiation, with the last refused handshake. */
            protocol: components["schemas"]["ProtocolState"];
            renewed_at?: components["schemas"]["Timestamp"] | null;
            /**
             * Format: int64
             * @description Store revision of the record (the `ETag`).
             */
            revision: number;
            /** @description Its roles: `probe`, `dns`, `dhcp`. */
            roles: string[];
            /** @description The software version the node reported last. */
            version?: string | null;
            /**
             * Format: uuid
             * @description The VRF of its observations when a batch names none.
             */
            vrf?: string | null;
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
        /** @description The last sighting of an intent object. */
        ObjectSighting: {
            /** @description The address or interface. */
            object: components["schemas"]["ObjectRef"];
            /** @description Its last sighting. */
            sighting: components["schemas"]["IntentSighting"];
        };
        /** @description An observation a waiting step needs. */
        ObservationCondition: {
            /** @description Any one of these satisfies the condition. */
            any_of: components["schemas"]["ObservedPredicate"][];
            /** @description The object the job waits for (usually the host). */
            subject: components["schemas"]["ObjectRef"];
        };
        /** Format: uuid */
        ObservationId: string;
        /** @description The source of an observation. */
        ObservationSource: {
            /** @description How it saw the subject. */
            method: components["schemas"]["ProbeMethod"];
            /** @description The probe node. */
            node: components["schemas"]["NodeId"];
            /** @enum {string} */
            type: "probe";
        } | {
            /** @description The connector. */
            connector: components["schemas"]["ConnectorId"];
            /** @enum {string} */
            type: "inventory";
        } | {
            /** @description The connector. */
            connector: components["schemas"]["ConnectorId"];
            /** @enum {string} */
            type: "network_controller";
        } | {
            /** @enum {string} */
            type: "dns_record";
            /** @description The zone. */
            zone: components["schemas"]["Fqdn"];
        } | {
            /** @description The DHCP node. */
            node: components["schemas"]["NodeId"];
            /** @enum {string} */
            type: "dhcp_lease";
        };
        /**
         * @description What was observed.
         *
         *     Adjacently tagged (`{"type": "address", "data": {...}}`) because variants carry IP
         *     addresses; see the encoding rules in [`crate::codec`].
         */
        Observed: {
            /** @description An address in use, with the MAC behind it when known. */
            data: {
                /** @description The address. */
                ip: string;
                mac?: components["schemas"]["MacAddr"] | null;
                /** @description The VRF the observing source belongs to. */
                vrf: components["schemas"]["VrfId"];
            };
            /** @enum {string} */
            type: "address";
        } | {
            /** @description A host from an inventory source. */
            data: components["schemas"]["ObservedHost"];
            /** @enum {string} */
            type: "host";
        } | {
            /** @description Open TCP ports (SCAN-08). */
            data: {
                /** @description The address scanned. */
                ip: string;
                /** @description Open ports. */
                open_tcp: number[];
                /** @description The open ports that answered a TLS handshake. */
                tls_tcp?: number[];
            };
            /** @enum {string} */
            type: "services";
        } | {
            /** @description An operating system guess (SCAN-08). */
            data: {
                /**
                 * Format: int32
                 * @description Confidence in percent.
                 */
                confidence: number;
                /** @description Free-text guess, such as `Linux 6.x`. */
                guess: string;
                /** @description The address scanned. */
                ip: string;
            };
            /** @enum {string} */
            type: "os";
        } | {
            /** @description Where a client is attached (switch port or wireless network). */
            data: {
                /** @description The switch or access point, as the controller names it. */
                device: string;
                /** @description The client. */
                mac: components["schemas"]["MacAddr"];
                /** @description The switch port. */
                port?: string | null;
                /** @description The wireless network. */
                ssid?: string | null;
                /**
                 * Format: int32
                 * @description The VLAN the client is in.
                 */
                vlan?: number | null;
            };
            /** @enum {string} */
            type: "attachment";
        } | {
            /** @description A link between two devices (IPAM-20 topology edges). */
            data: {
                /** @description One end. */
                a: components["schemas"]["Endpoint"];
                /** @description The other end. */
                b: components["schemas"]["Endpoint"];
                /** @description How the link was learned. */
                kind: components["schemas"]["LinkKind"];
            };
            /** @enum {string} */
            type: "link";
        } | {
            /**
             * @description A name a source found for an address (reverse DNS, mDNS, LLMNR, SNMP). A name is
             *     not a sighting of the address.
             */
            data: {
                /** @description The address. */
                ip: string;
                /** @description The name, such as `printer.example.net`. */
                name: string;
            };
            /** @enum {string} */
            type: "name";
        } | {
            /**
             * @description The organisation a MAC address is registered to (its OUI), or the manufacturer a
             *     device reports.
             */
            data: {
                /** @description The MAC address. */
                mac: components["schemas"]["MacAddr"];
                /** @description The vendor name. */
                vendor: string;
            };
            /** @enum {string} */
            type: "vendor";
        };
        /**
         * @description One source's knowledge of one subject: the latest report as the source gave it, with
         *     first and last sighting. Facts of different sources are never merged; the view across
         *     sources is computed when read ([`super::view`]).
         */
        ObservedFact: {
            counted_at?: components["schemas"]["Timestamp"] | null;
            expires_at?: components["schemas"]["Timestamp"] | null;
            /** @description When the source first reported the subject (its time). */
            first_seen: components["schemas"]["Timestamp"];
            /** @description When the source last reported the subject (its time). */
            last_seen: components["schemas"]["Timestamp"];
            /** @description The observation that last changed the fact (or first reported it). */
            observation: components["schemas"]["ObservationId"];
            /**
             * @description The latest report, with every attribute the source gave (name, MAC and IP
             *     addresses, OS, platform, hypervisor node, tags, attachment, ports).
             */
            observed: components["schemas"]["Observed"];
            /** @description When the fact was last written. */
            received_at: components["schemas"]["Timestamp"];
            /**
             * Format: int64
             * @description Store revision of the fact (filled when read).
             */
            revision?: number;
            /**
             * Format: int32
             * @description Reports of the subject, counted at most once per refresh interval (the adoption
             *     constraint "after N sightings").
             */
            sightings?: number;
            /** @description The source. */
            source: components["schemas"]["ObservationSource"];
            /** @description The canonical text of the source ([`source_key`]). */
            source_key: string;
            /** @description The subject. */
            subject: components["schemas"]["FactSubject"];
            /** @description The canonical text of the subject ([`FactSubject::key`]). */
            subject_key: string;
        };
        /** @description A host as an inventory source reports it (CONN-02). */
        ObservedHost: {
            /** @description The source's own identifier (VM id, entity id), stable across polls. */
            external_id: string;
            /** @description IP addresses. */
            ips?: string[];
            /** @description MAC addresses. */
            macs?: components["schemas"]["MacAddr"][];
            /** @description Name as the source shows it. */
            name?: string | null;
            /** @description Operating system. */
            os?: string | null;
            /** @description The parent host's `external_id` (the hypervisor node of a VM). */
            parent?: string | null;
            /** @description Platform, such as `qemu`, `lxc` or `esphome`. */
            platform?: string | null;
            /** @description Tags from the source. */
            tags?: string[];
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
         * @description A change of an operator secret. Absent members stay; `null` clears `username` and
         *     `notes`.
         */
        OperatorSecretPatch: {
            kind?: components["schemas"]["SecretKind"] | null;
            /** @description A new name. */
            name?: string | null;
            /** @description New notes; `null` clears them. */
            notes?: string | null;
            /** @description New purpose tags (the whole list). */
            tags?: string[] | null;
            /** @description A new user name; `null` clears it. */
            username?: string | null;
            value?: components["schemas"]["SecretString"] | null;
        };
        /** @description An operator secret: metadata only, never the value. */
        OperatorSecretView: {
            /** @description When it was created. */
            created_at: components["schemas"]["Timestamp"];
            /** @description The hosts it is bound to, with the role. */
            hosts: components["schemas"]["SecretHostRef"][];
            /** @description The secret. */
            id: components["schemas"]["SecretId"];
            /** @description What it is. */
            kind: components["schemas"]["SecretKind"];
            last_revealed?: components["schemas"]["LastReveal"] | null;
            /** @description The name (not unique). */
            name: string;
            /** @description Notes. */
            notes?: string | null;
            /** @description Where it came from. */
            origin: components["schemas"]["SecretOrigin"];
            revision?: components["schemas"]["Revision"] | null;
            /**
             * @description Purpose tags (lower case, sorted), for example `api_key` or `unifi`; a connector form
             *     offers the secrets whose tags include the purpose it needs.
             */
            tags: string[];
            /** @description When its metadata or value last changed. */
            updated_at: components["schemas"]["Timestamp"];
            /** @description The user name that goes with it. */
            username?: string | null;
            /** @description When its value was last written (creation, replacement, key rotation). */
            value_updated_at: components["schemas"]["Timestamp"];
        };
        /** @description A language and its packs, for administrators (`GET /i18n/packs`). */
        PackInfo: {
            active?: components["schemas"]["PackVersion"] | null;
            /** @description Whether the UI has the language built in (it can be overridden, never removed). */
            built_in: boolean;
            candidate?: components["schemas"]["PackVersion"] | null;
            /** @description The language's name in itself. */
            name: string;
            /** @description The life cycle state. */
            status: components["schemas"]["PackStatus"];
            /** @description The BCP 47 tag. */
            tag: string;
        };
        /** @description Every language with its packs (`GET /i18n/packs`). */
        PackList: {
            /**
             * Format: int32
             * @description The number of keys of the running UI.
             */
            keys: number;
            /** @description The built-in languages, then the others by tag. */
            packs: components["schemas"]["PackInfo"][];
        };
        /** @description The messages of a pack, ready for the UI (`GET /i18n/packs/{tag}`). */
        PackMessages: {
            /** @description The content hash of the messages (also the `ETag`). */
            hash: string;
            /**
             * @description ICU message text by key; keys the pack lacks fall back to the built-in language of the
             *     same tag, then to English.
             */
            messages: {
                [key: string]: string;
            };
            /** @description The BCP 47 tag. */
            tag: string;
        };
        /**
         * @description Where a pack version came from.
         * @enum {string}
         */
        PackOrigin: "upload" | "data_dir";
        /** @description A problem found in a pack. */
        PackProblem: {
            /** @description The stable code, for example `i18n.pack.icu`. */
            code: string;
            /** @description English explanation. */
            detail: string;
            /** @description The unit, when the problem belongs to one. */
            key?: string | null;
            /**
             * Format: int32
             * @description The 1-based line in the document.
             */
            line?: number | null;
            /** @description Error or warning. */
            severity: components["schemas"]["PackSeverity"];
        };
        /** @description The validation report of a pack. */
        PackReport: {
            /** @description Who made the pack. */
            author: string;
            /** @description The language's name in itself. */
            display_name: string;
            /** @description Units whose key the running UI does not have; they are not used. */
            extra: string[];
            /** @description Keys of the running UI the pack does not translate; they show in English. */
            missing: string[];
            /**
             * Format: int32
             * @description `translated` in percent of `total`, rounded down (100 when the UI has no keys).
             */
            percent: number;
            /** @description Errors of single units (left out) and warnings. */
            problems: components["schemas"]["PackProblem"][];
            /** @description Units translated from an English text that has changed since; they are used. */
            stale: string[];
            /** @description The BCP 47 tag (`trgLang`). */
            tag: string;
            /**
             * Format: int32
             * @description The keys of the running UI.
             */
            total: number;
            /**
             * Format: int32
             * @description The keys the pack translates usably.
             */
            translated: number;
            /** @description The pack's own version. */
            version: string;
        };
        /**
         * @description How bad a problem is.
         * @enum {string}
         */
        PackSeverity: "error" | "warning";
        /**
         * @description Where a language is in its life cycle.
         * @enum {string}
         */
        PackStatus: "built_in" | "uploaded" | "previewed" | "active";
        /** @description An accepted upload (`POST /i18n/packs`): the language and the report of the new version. */
        PackUpload: {
            /** @description The language after the upload; the new version is its candidate. */
            pack: components["schemas"]["PackInfo"];
            /** @description The validation report. */
            report: components["schemas"]["PackReport"];
        };
        /** @description The multipart form of `POST /i18n/packs`. */
        PackUploadForm: {
            /**
             * Format: binary
             * @description The XLIFF 2.0 document, at most 2 MiB; its `trgLang` names the language.
             */
            file: string;
        };
        /** @description One uploaded version of a pack. */
        PackVersion: {
            /** @description Who made the pack. */
            author?: string;
            /** @description The language's name in itself. */
            display_name: string;
            /** @description The content hash of its messages (the `ETag` of `GET /i18n/packs/{tag}`). */
            hash: string;
            /** @description The SHA-256 of the uploaded document, hex. */
            id: string;
            /** @description Where it came from. */
            origin: components["schemas"]["PackOrigin"];
            /**
             * Format: int32
             * @description `translated` in percent of `total`, rounded down.
             */
            percent: number;
            previewed_at?: components["schemas"]["Timestamp"] | null;
            previewed_by?: components["schemas"]["Principal"] | null;
            /**
             * Format: int32
             * @description Keys of the running UI when it was uploaded.
             */
            total: number;
            /**
             * Format: int32
             * @description Keys of the running UI the version translates, when it was uploaded.
             */
            translated: number;
            /** @description When it was uploaded or imported. */
            uploaded_at: components["schemas"]["Timestamp"];
            /** @description Who uploaded it. */
            uploaded_by: components["schemas"]["Principal"];
            /** @description The pack's own version. */
            version?: string;
        };
        /**
         * @description One page of a list (plan section 4): the items, the opaque cursor of the next page and
         *     the store revision the page was read at.
         *
         *     A client that wants live updates subscribes to `GET /events` from `revision`; a client
         *     that wants the next page passes `next_cursor` back as `cursor`. The cursor is opaque and
         *     bound to the query that produced it.
         */
        Page_AddressRow: {
            /** @description The items of this page, at most `limit` of them. */
            items: (components["schemas"]["Address"] & {
                host?: components["schemas"]["HostSummary"] | null;
                interface_detail?: components["schemas"]["InterfaceSummary"] | null;
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
        Page_ConnectorView: {
            /** @description The items of this page, at most `limit` of them. */
            items: (components["schemas"]["ConnectorInstance"] & {
                /** @description The plugin's capabilities, when the plugin is known. */
                capabilities?: components["schemas"]["Capability"][];
                /** @description Health of the process and the remote system. */
                health: components["schemas"]["ConnectorHealth"];
                last_run?: components["schemas"]["LastRun"] | null;
                /** @description The store revision of the instance (for `If-Match` style preconditions). */
                revision: components["schemas"]["Revision"];
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
        Page_IntentProposal: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                adopted_by?: components["schemas"]["PrefixId"] | null;
                /**
                 * @description The error code of the last failed adoption; the policy does not try again until
                 *     the proposal is replaced.
                 */
                adoption_error?: string | null;
                /** @description The commands an approval applies (empty for conflicts, which a person resolves). */
                commands?: components["schemas"]["IpamCommand"][];
                /** @description When it was opened. */
                created: components["schemas"]["Timestamp"];
                decided?: components["schemas"]["Stamp"] | null;
                /** @description The observations behind it. */
                evidence: components["schemas"]["ProposalEvidence"][];
                /**
                 * @description SHA-256 over the canonical CBOR of the kind, the subject key, the evidence
                 *     identities (sources, subjects, paired addresses) and the commands: equal evidence,
                 *     equal fingerprint. A rejection is remembered by it.
                 */
                fingerprint: components["schemas"]["Digest"];
                /** @description Identifier. */
                id: components["schemas"]["ProposalId"];
                /**
                 * @description The subject key: kind and subject, unique among open proposals
                 *     (`discovered_host/mac:00:00:5e:00:53:01`).
                 */
                key: string;
                /** @description The kind. */
                kind: components["schemas"]["IntentProposalKind"];
                /** @description Named parameters of the summary, for translation. */
                params?: {
                    [key: string]: string;
                };
                /** @description The rejection reason, or why it expired. */
                reason?: string | null;
                /** @description The objects its commands created or changed, once accepted. */
                results?: components["schemas"]["ObjectRef"][];
                /**
                 * Format: int64
                 * @description Store revision (filled when read; `ETag` and `If-Match` of the decisions).
                 */
                revision?: number;
                /**
                 * @description The rule that produced it, a stable code such as
                 *     `ipam.reconcile.discovered_mac`; the UI translates it with [`Self::params`].
                 */
                rule: string;
                /** @description How urgent it is. */
                severity: components["schemas"]["ProposalSeverity"];
                /** @description The decision state. */
                state: components["schemas"]["IntentProposalState"];
                /** @description The subject. */
                subject: components["schemas"]["ProposalSubject"];
                /** @description English one-line summary. */
                summary: string;
                superseded_by?: components["schemas"]["ProposalId"] | null;
                /** @description When it last changed. */
                updated: components["schemas"]["Timestamp"];
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
        Page_NodeView: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description The address the node gave at enrolment, else the address it enrolled from. */
                address?: string | null;
                /** @description The newest certificate. */
                certificate: components["schemas"]["CertificateRef"];
                /**
                 * @description Whether the node is connected to a controller of the cluster now (this one or
                 *     another; `connection.controller` names it).
                 */
                connected: boolean;
                connection?: components["schemas"]["ConnectionView"] | null;
                /** @description When the node enrolled. */
                enrolled_at: components["schemas"]["Timestamp"];
                /**
                 * Format: uuid
                 * @description The user who created the enrolment token.
                 */
                enrolled_by?: string | null;
                /**
                 * Format: int64
                 * @description The node id.
                 */
                id: number;
                last_seen?: components["schemas"]["Timestamp"] | null;
                /** @description Its name. */
                name: string;
                /** @description Protocol negotiation, with the last refused handshake. */
                protocol: components["schemas"]["ProtocolState"];
                renewed_at?: components["schemas"]["Timestamp"] | null;
                /**
                 * Format: int64
                 * @description Store revision of the record (the `ETag`).
                 */
                revision: number;
                /** @description Its roles: `probe`, `dns`, `dhcp`. */
                roles: string[];
                /** @description The software version the node reported last. */
                version?: string | null;
                /**
                 * Format: uuid
                 * @description The VRF of its observations when a batch names none.
                 */
                vrf?: string | null;
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
        Page_ObservedFact: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                counted_at?: components["schemas"]["Timestamp"] | null;
                expires_at?: components["schemas"]["Timestamp"] | null;
                /** @description When the source first reported the subject (its time). */
                first_seen: components["schemas"]["Timestamp"];
                /** @description When the source last reported the subject (its time). */
                last_seen: components["schemas"]["Timestamp"];
                /** @description The observation that last changed the fact (or first reported it). */
                observation: components["schemas"]["ObservationId"];
                /**
                 * @description The latest report, with every attribute the source gave (name, MAC and IP
                 *     addresses, OS, platform, hypervisor node, tags, attachment, ports).
                 */
                observed: components["schemas"]["Observed"];
                /** @description When the fact was last written. */
                received_at: components["schemas"]["Timestamp"];
                /**
                 * Format: int64
                 * @description Store revision of the fact (filled when read).
                 */
                revision?: number;
                /**
                 * Format: int32
                 * @description Reports of the subject, counted at most once per refresh interval (the adoption
                 *     constraint "after N sightings").
                 */
                sightings?: number;
                /** @description The source. */
                source: components["schemas"]["ObservationSource"];
                /** @description The canonical text of the source ([`source_key`]). */
                source_key: string;
                /** @description The subject. */
                subject: components["schemas"]["FactSubject"];
                /** @description The canonical text of the subject ([`FactSubject::key`]). */
                subject_key: string;
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
        Page_OperatorSecretView: {
            /** @description The items of this page, at most `limit` of them. */
            items: {
                /** @description When it was created. */
                created_at: components["schemas"]["Timestamp"];
                /** @description The hosts it is bound to, with the role. */
                hosts: components["schemas"]["SecretHostRef"][];
                /** @description The secret. */
                id: components["schemas"]["SecretId"];
                /** @description What it is. */
                kind: components["schemas"]["SecretKind"];
                last_revealed?: components["schemas"]["LastReveal"] | null;
                /** @description The name (not unique). */
                name: string;
                /** @description Notes. */
                notes?: string | null;
                /** @description Where it came from. */
                origin: components["schemas"]["SecretOrigin"];
                revision?: components["schemas"]["Revision"] | null;
                /**
                 * @description Purpose tags (lower case, sorted), for example `api_key` or `unifi`; a connector form
                 *     offers the secrets whose tags include the purpose it needs.
                 */
                tags: string[];
                /** @description When its metadata or value last changed. */
                updated_at: components["schemas"]["Timestamp"];
                /** @description The user name that goes with it. */
                username?: string | null;
                /** @description When its value was last written (creation, replacement, key rotation). */
                value_updated_at: components["schemas"]["Timestamp"];
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
                /** @description An address object, with its interface and host when the list expands them. */
                data: components["schemas"]["AddressRow"];
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
                /** @description The grants of a scoped token. */
                grants?: components["schemas"]["TokenGrant"][];
                /** @description The token id. */
                id: components["schemas"]["ApiTokenId"];
                last_used_at?: components["schemas"]["Timestamp"] | null;
                /** @description The name. */
                name: string;
                /** @description The first characters of the token. */
                prefix: string;
                /** @description A scoped token (IAM-10); absent for a personal token. */
                scoped?: boolean;
                /** @description The special scopes of a scoped token. */
                scopes?: components["schemas"]["TokenScope"][];
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
                /** @description A service account (IAM-10); absent for a person. */
                kind?: components["schemas"]["UserKind"];
                /** @description The fixed UI language. */
                language?: string | null;
                last_login_at?: components["schemas"]["Timestamp"] | null;
                lock?: components["schemas"]["AccountLock"] | null;
                /** @description The login name. */
                name: string;
                owner?: components["schemas"]["UserId"] | null;
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
        /** @description A problem that stops the plan, as in problem details. */
        PlanProblem: {
            /** @description Stable code (`ipam.prefix.overlap`). */
            code: string;
            /** @description English explanation. */
            detail: string;
            /** @description Named parameters for the translated message. */
            params?: {
                [key: string]: string;
            };
            /**
             * Format: int32
             * @description HTTP status the code maps to.
             */
            status: number;
        };
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
        /** @description A plugin and whether it can run here. */
        PluginInfo: {
            manifest?: components["schemas"]["Manifest"] | null;
            /** @description The plugin name (the directory name of an installed plugin). */
            name: string;
            /** @description What is wrong with it. */
            problems?: components["schemas"]["ManifestProblem"][];
            /** @description Where it comes from. */
            source: components["schemas"]["PluginSource"];
            /**
             * @description Whether instances of it can run on this host: a valid manifest, this platform, a
             *     common protocol version.
             */
            usable: boolean;
        };
        /** @description The plugins of this node. */
        PluginList: {
            /** @description Bundled plugins first, then installed ones by name. */
            items: components["schemas"]["PluginInfo"][];
        };
        /**
         * @description Where a plugin comes from.
         * @enum {string}
         */
        PluginSource: "bundled" | "installed";
        /** @description The adoption policy of one prefix as the API shows it. */
        PolicyView: {
            /** @description The policy in force: its own, an inherited one, or the default (`manual`). */
            effective: components["schemas"]["AdoptionPolicy"];
            policy?: components["schemas"]["AdoptionPolicy"] | null;
            /** @description The prefix. */
            prefix: components["schemas"]["PrefixId"];
            /**
             * Format: int64
             * @description The revision of its own policy (`ETag`, `If-Match`); 0 without one.
             */
            revision: number;
            source?: components["schemas"]["PrefixId"] | null;
            updated?: components["schemas"]["Stamp"] | null;
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
            /** @description An address object, with its interface and host when the list expands them. */
            data: components["schemas"]["AddressRow"];
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
        /** @description The prefix of a provision. */
        PrefixTarget: {
            /**
             * @description The network.
             * @example 198.51.100.0/24
             */
            cidr: string;
            /** @description The identifier the prefix will have. */
            id: components["schemas"]["PrefixId"];
            vrf?: components["schemas"]["VrfId"] | null;
        };
        /** @description One source row of the preview. */
        PreviewRow: {
            /** @description What it creates, updates or leaves unchanged. */
            items: components["schemas"]["RowItem"][];
            /** @description Sheet and row. */
            location: components["schemas"]["SourceLocation"];
            /** @description What became of the row. */
            status: components["schemas"]["RowStatus"];
        };
        /** @description The counts of a preview. */
        PreviewSummary: {
            /** @description Chunks the apply job will write. */
            chunks: number;
            /** @description Items per kind and action, ordered by kind and action. */
            counts: components["schemas"]["ActionCount"][];
            /** @description English lines such as `21 hosts created`. */
            lines: string[];
            /** @description Loss report entries by severity. */
            loss: components["schemas"]["LossCounts"];
            plan?: components["schemas"]["PlanSummary"] | null;
            /** @description Source rows by outcome. */
            rows: components["schemas"]["RowCounts"];
        };
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
         * @description How a probe saw its subject.
         * @enum {string}
         */
        ProbeMethod: "arp" | "nd" | "mdns" | "lldp" | "icmp" | "tcp_syn" | "os_fingerprint" | "snmp" | "tcp_connect" | "reverse_dns" | "llmnr" | "arp_sweep";
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
        /** @description The state of a supervised plugin process. */
        ProcessState: {
            /** @enum {string} */
            state: "stopped";
        } | {
            /**
             * Format: int32
             * @description The start attempt since the last healthy run, from 1.
             */
            attempt: number;
            /** @enum {string} */
            state: "starting";
        } | {
            /**
             * Format: int32
             * @description The process id.
             */
            pid?: number | null;
            /**
             * Format: int32
             * @description The protocol version in use.
             */
            protocol: number;
            /** @description Since when. */
            since: components["schemas"]["Timestamp"];
            /** @enum {string} */
            state: "running";
            /** @description The plugin version. */
            version: string;
        } | {
            /**
             * Format: int32
             * @description The start attempt that follows.
             */
            attempt: number;
            /** @enum {string} */
            state: "backoff";
            /** @description When the next start happens. */
            until: components["schemas"]["Timestamp"];
        } | {
            /** @enum {string} */
            state: "circuit_open";
            /** @description When the trial start happens. */
            until: components["schemas"]["Timestamp"];
        } | {
            /** @enum {string} */
            state: "failed";
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
        /** @description Body of `POST /cluster/members/{id}/promote`. */
        PromoteRequest: {
            /**
             * @description Promote although the result has an even number of voters or the learner is not
             *     caught up.
             */
            force?: boolean;
            /**
             * Format: int64
             * @description A voter to remove in the same change: replaces a dead voter without passing
             *     through an even number of voters.
             */
            replace?: number | null;
        };
        /** @description A proposed prefix for addresses outside every known network (rule 4). */
        Proposal: {
            /** @description Whether it is created (the mapping options decide; accepted by default). */
            accepted: boolean;
            /** @description The addresses it would hold. */
            addresses: string[];
            /**
             * @description The proposed network.
             * @example 198.51.100.64/26
             */
            cidr: string;
            /** @description Where the first of its addresses comes from. */
            origin: components["schemas"]["SourceLocation"];
            /** @description The VRF name; the import's target VRF when absent. */
            vrf?: string | null;
        };
        /** @description The user's decision on a proposed prefix. */
        ProposalDecision: {
            /** @description Whether to create it (the default when no decision is given). */
            accept: boolean;
            /**
             * @description The proposed network, as the preview listed it.
             * @example 198.51.100.64/26
             */
            cidr: string;
        };
        /** @description One observation behind a proposal, as it was when the proposal was written. */
        ProposalEvidence: {
            /** @description First sighting by this source. */
            first_seen: components["schemas"]["Timestamp"];
            /** @description The IP address, if any. */
            ip?: string | null;
            /** @description Last sighting by this source. */
            last_seen: components["schemas"]["Timestamp"];
            mac?: components["schemas"]["MacAddr"] | null;
            /** @description The name the source gives, if any. */
            name?: string | null;
            /** @description The observation that last changed the fact. */
            observation: components["schemas"]["ObservationId"];
            /**
             * Format: int32
             * @description Counted sightings by this source.
             */
            sightings?: number;
            /** @description The source. */
            source: components["schemas"]["ObservationSource"];
            /** @description The canonical text of the source. */
            source_key: string;
            /** @description The canonical text of the fact's subject. */
            subject_key: string;
        };
        /** Format: uuid */
        ProposalId: string;
        /**
         * @description How urgent a proposal is.
         * @enum {string}
         */
        ProposalSeverity: "info" | "warning" | "critical";
        /** @description What a proposal concerns: the observed identity and the intent objects involved. */
        ProposalSubject: {
            /** @description The network (outside-prefix proposals). */
            cidr?: string | null;
            /** @description The IP address. */
            ip?: string | null;
            mac?: components["schemas"]["MacAddr"] | null;
            /** @description The name a source gives the device. */
            name?: string | null;
            /** @description The intent objects involved (hosts, interfaces, addresses). */
            objects?: components["schemas"]["ObjectRef"][];
            prefix?: components["schemas"]["PrefixId"] | null;
            vrf?: components["schemas"]["VrfId"] | null;
        };
        /** @description The protocol state of a node: what it offered and what was agreed. */
        ProtocolState: {
            /**
             * Format: int32
             * @description The major agreed in the last successful handshake.
             */
            agreed?: number | null;
            mismatch?: components["schemas"]["MismatchRecord"] | null;
            /** @description The majors the node offered in its last handshake. */
            offered?: number[];
        };
        /**
         * @description The kind of quorum state of a controller.
         * @enum {string}
         */
        QuorumKind: "single" | "healthy" | "electing" | "isolated";
        /** @description The quorum state of a controller (OPS-26), for `GET /system/status` and `/cluster`. */
        QuorumView: {
            applied?: components["schemas"]["Revision"] | null;
            last_contact?: components["schemas"]["Timestamp"] | null;
            since?: components["schemas"]["Timestamp"] | null;
            /** @description The state. */
            state: components["schemas"]["QuorumKind"];
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
            /**
             * Format: int32
             * @description DHCP lease time in seconds, 60 to 31,536,000 (`dhcp_pool` ranges only); half of it
             *     is the default timeout of moves into the prefix (IPAM-19).
             */
            lease_secs?: number | null;
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
            /**
             * Format: int32
             * @description New DHCP lease time in seconds (`dhcp_pool` ranges only); `null` clears it.
             */
            lease_secs?: number | null;
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
        /** @description What one run did. */
        ReconcileReport: {
            /**
             * Format: int32
             * @description Proposals adopted by a policy.
             */
            adopted: number;
            /**
             * Format: int32
             * @description Adoptions that failed (recorded on the proposal).
             */
            adoption_failures: number;
            /** @description When the run started. */
            at: components["schemas"]["Timestamp"];
            /**
             * Format: int32
             * @description Proposals whose observation no longer holds.
             */
            expired: number;
            /**
             * Format: int32
             * @description Move jobs whose observation step was confirmed.
             */
            moves_confirmed: number;
            /**
             * Format: int32
             * @description Proposals opened.
             */
            opened: number;
            /**
             * Format: int32
             * @description Open proposals whose evidence was refreshed.
             */
            refreshed: number;
            /**
             * Format: int64
             * @description The revision of the proposal write; `null` when nothing changed.
             */
            revision?: number | null;
            /**
             * Format: int32
             * @description Last sightings of intent objects written.
             */
            sightings: number;
            /**
             * Format: int32
             * @description Proposals replaced by newer ones.
             */
            superseded: number;
            /**
             * Format: int32
             * @description Subjects not opened again because a person rejected the same evidence.
             */
            suppressed: number;
            /**
             * Format: int32
             * @description Open proposals left as they were.
             */
            unchanged: number;
        };
        /** @description New recovery codes, shown once. */
        RecoveryCodes: {
            /** @description The codes. */
            codes: components["schemas"]["SecretString"][];
        };
        /**
         * @description A plain generation file that this controller refused to load because a sealed generation
         *     is older (the protection would silently drop).
         */
        RefusedGenerationView: {
            /** @description The file name, without its directory. */
            file: string;
            /**
             * Format: int32
             * @description The generation number in the file name.
             */
            generation: number;
            /** @description The protection of the file (plain). */
            protection: components["schemas"]["KekProtectionView"];
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
        /** @description The body of a rejection. */
        RejectRequest: {
            /**
             * @description Why the proposal is rejected; at most 1,024 bytes, no control characters other than
             *     line breaks and tabs. Blank counts as no reason.
             */
            reason?: string | null;
        };
        /** @description One release. Also the body of the release endpoints. */
        Release: {
            /** @description Markdown: what the operator must do; present when `requires_action` is set. */
            action?: string | null;
            /** @description The downloadable files, one per platform. */
            assets?: components["schemas"]["ReleaseAsset"][];
            /** @description Release date, `YYYY-MM-DD`. */
            date: string;
            /**
             * Format: int32
             * @description Format of the data directory this release writes.
             */
            format?: number | null;
            /** @description Container image of the release, for example `ghcr.io/example/tenko:0.2.0`. */
            image?: string | null;
            /** @description Markdown: the changelog section of the version. */
            notes: string;
            /** @description The operator must do something when upgrading to this release. */
            requires_action?: boolean;
            /** @description The release contains security fixes. */
            security?: boolean;
            /** @description The version of the release. */
            version: components["schemas"]["ReleaseVersion"];
        };
        /** @description One downloadable file of a release. */
        ReleaseAsset: {
            /** @description File name, for example `tenko-0.2.0-linux-x86_64`. */
            name: string;
            /**
             * @description `<os>-<arch>` as Rust's `std::env::consts::OS` and `ARCH` name them: `linux-x86_64`,
             *     `linux-aarch64`, `windows-x86_64`.
             */
            platform: string;
            /** @description SHA-256 of the file: 64 lowercase hexadecimal digits. */
            sha256: string;
            /** @description Detached signature; reserved for signed releases (API-19) and not checked yet. */
            signature?: string | null;
            /**
             * Format: int64
             * @description Size of the file in bytes.
             */
            size: number;
            /** @description Absolute `http` or `https` URL, or a URL relative to the manifest URL. */
            url: string;
        };
        /**
         * @description The release manifest (`releases.json`): every release of the product with its notes and
         *     downloads.
         */
        ReleaseManifest: {
            /** @description The project the manifest describes; always `tenko`. */
            project: string;
            /** @description The releases; [`ReleaseManifest::parse`] sorts them newest first. */
            releases: components["schemas"]["Release"][];
            /**
             * Format: int32
             * @description Format of the manifest; the only schema is 1.
             */
            schema: number;
        };
        /**
         * @description Release version: MAJOR.MINOR.PATCH with an optional pre-release and build metadata, ordered by SemVer 2.0.0 precedence.
         * @example 1.2.0
         * @example 1.2.0-rc.1
         */
        ReleaseVersion: string;
        /**
         * @description Health of a remote system.
         * @enum {string}
         */
        RemoteHealth: "healthy" | "degraded" | "unreachable";
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
         * @description TGL-24: what revealing an operator secret takes (IAM-16, API-11). The PIN coupling rule
         *     (IAM-07) holds in every profile on top of it: a PIN-strength session never reveals, and
         *     personal API tokens never reveal.
         */
        RevealPolicy: {
            /**
             * @description Reveal only a secret that is bound to the host the request names: the host the
             *     person is looking at (Hardened). The secrets page cannot reveal then.
             */
            bound_host_only: boolean;
            /** @description The authentication a reveal needs. */
            step_up: components["schemas"]["RevealStepUp"];
        };
        /** @description A reveal request. */
        RevealRequest: {
            host?: components["schemas"]["HostId"] | null;
            /** @description Why, in the person's words (at most 200 characters); written to the audit record. */
            reason?: string | null;
        };
        /**
         * @description The authentication a reveal of an operator secret needs (TGL-24). The variants are
         *     ordered from the weakest to the strongest.
         * @enum {string}
         */
        RevealStepUp: "session" | "fresh" | "passkey";
        /**
         * @description A revealed value. Sent once with `Cache-Control: no-store`, never stored for an
         *     idempotent replay; the reveal is in the audit log.
         */
        RevealedSecret: {
            /**
             * Format: int32
             * @description Seconds after which the UI clears the value from the clipboard.
             */
            clear_after_secs: number;
            /** @description The secret. */
            id: components["schemas"]["SecretId"];
            /** @description What it is. */
            kind: components["schemas"]["SecretKind"];
            /** @description When the reveal was recorded in the audit log. */
            revealed_at: components["schemas"]["Timestamp"];
            /** @description The user name that goes with it. */
            username?: string | null;
            /** @description The value (the password of an imported login). */
            value: components["schemas"]["SecretString"];
        };
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
        RoleName: "admin" | "operator" | "viewer" | "auditor";
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
        /** @description Rows of the source by outcome. */
        RowCounts: {
            /** @description Address-only rows of pre-filled lists (free addresses). */
            free: number;
            /** @description Rows that produced something. */
            imported: number;
            /** @description Rows left out. */
            skipped: number;
            /** @description Rows with data. */
            total: number;
        };
        /** @description One item of a preview row. */
        RowItem: {
            /** @description What happens to it. */
            action: components["schemas"]["ItemAction"];
            /** @description The item. */
            key: components["schemas"]["ItemKey"];
        };
        /**
         * @description What became of a source row.
         * @enum {string}
         */
        RowStatus: "free" | "imported" | "skipped";
        /** @description The relying party as shown by the browser. */
        RpEntity: {
            /** @description The RP ID: the host name of the installation. */
            id: string;
            /** @description A human-readable name. */
            name: string;
        };
        /** @description The answer to a run request: the job that runs the connector. */
        RunAccepted: {
            /** @description The job (`GET /jobs/{id}` shows its progress). */
            job: components["schemas"]["JobId"];
        };
        /**
         * @description How a run ended.
         * @enum {string}
         */
        RunOutcome: "succeeded" | "failed";
        /**
         * @description What started a run.
         * @enum {string}
         */
        RunTrigger: "schedule" | "manual";
        /**
         * @description A scope rule in the API (IAM-01): `{"kind": "prefix", "value": {"id": "...",
         *     "subtree": true}}`. Grants use `vrf`, `site` and `prefix`; `tenant` and `object` are
         *     part of the model and not granted in Phase 1.
         */
        ScopeRule: {
            /** @enum {string} */
            kind: "tenant";
            /** @description Objects of a tenant. */
            value: components["schemas"]["TenantId"];
        } | {
            /** @enum {string} */
            kind: "vrf";
            /** @description Objects of a VRF. */
            value: components["schemas"]["VrfId"];
        } | {
            /** @enum {string} */
            kind: "site";
            /** @description Objects of a site, and with `subtree` those of its child sites. */
            value: {
                /** @description The site. */
                id: components["schemas"]["SiteId"];
                /** @description Whether child sites are included. */
                subtree: boolean;
            };
        } | {
            /** @enum {string} */
            kind: "prefix";
            /** @description A prefix and the objects directly in it, and with `subtree` everything inside it. */
            value: {
                /** @description The prefix. */
                id: components["schemas"]["PrefixId"];
                /** @description Whether child prefixes are included. */
                subtree: boolean;
            };
        } | {
            /** @enum {string} */
            kind: "object";
            /** @description One object. */
            value: components["schemas"]["ObjectRef"];
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
        /** @description A connector instance that references a secret. */
        SecretConnectorReference: {
            /** @description The connector instance. */
            connector: components["schemas"]["ConnectorId"];
            /** @description Its name. */
            name: string;
            /** @description Its plugin. */
            plugin: string;
            /** @description The purpose the secret serves for the plugin. */
            purpose: string;
        };
        /** @description A secret a plugin may receive. */
        SecretDecl: {
            /** @description What the secret is, for the operator. */
            description: string;
            /**
             * @description The purpose: lowercase ASCII letters, digits and `_`, starting with a letter, at most
             *     64 characters, for example `password` or `api_key`. Unique in the manifest.
             */
            purpose: string;
            /** @description Whether an instance needs it. */
            required?: boolean;
        };
        /** @description A host a secret is bound to. */
        SecretHostRef: {
            /** @description The host. */
            host: components["schemas"]["HostId"];
            /** @description The role of the credential on it. */
            role: components["schemas"]["CredentialRole"];
        };
        /** @description A host that binds a secret. */
        SecretHostReference: {
            /** @description Whether the host is deleted. */
            deleted?: boolean;
            /** @description The host. */
            host: components["schemas"]["HostId"];
            /** @description Its name, when the host still exists. */
            name?: string | null;
            /** @description The role of the credential on it. */
            role: components["schemas"]["CredentialRole"];
        };
        /** Format: uuid */
        SecretId: string;
        /**
         * @description What an operator secret is.
         * @enum {string}
         */
        SecretKind: "password" | "api_key" | "ssh_key" | "token" | "other";
        /**
         * @description Where an operator secret came from.
         * @enum {string}
         */
        SecretOrigin: "manual" | "import";
        /**
         * @description A reference to a vault secret, resolved at call time (ADR 0006). Connectors and other
         *     consumers store references, never secret values.
         */
        SecretRef: {
            /** @description The secret. */
            secret: components["schemas"]["SecretId"];
        };
        /** @description What references a secret. A secret with any reference cannot be deleted. */
        SecretReferences: {
            /** @description The connector instances that use it. */
            connectors: components["schemas"]["SecretConnectorReference"][];
            /** @description The hosts that bind it as a credential. */
            hosts: components["schemas"]["SecretHostReference"][];
            /** @description The secret. */
            id: components["schemas"]["SecretId"];
        };
        /** Format: password */
        SecretString: string;
        /** @description The authentication part of the security settings: the profile and TGL-01 to TGL-07. */
        SecuritySettings: {
            audit_export?: components["schemas"]["AuditExport"] | null;
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
            secret_reveal?: components["schemas"]["RevealPolicy"] | null;
            /** @description TGL-04: session lifetime. */
            session: components["schemas"]["SessionLifetime"];
            /**
             * Format: int32
             * @description TGL-05: API token maximum lifetime in days; `None` allows non-expiring tokens.
             */
            token_max_days?: number | null;
            updates?: components["schemas"]["UpdatePolicy"] | null;
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
        /** @description One scoped grant as a session shows it. */
        SessionGrant: {
            /** @description Whether the holder may delegate it. */
            delegable: boolean;
            /** @description The grant. */
            id: components["schemas"]["GrantId"];
            /** @description The role. */
            role: components["schemas"]["RoleName"];
            /** @description Where it applies. */
            scope: components["schemas"]["ScopeRule"];
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
            /** @description The scoped grants of the account (IAM-01), for display gating; the server decides. */
            grants?: components["schemas"]["SessionGrant"][];
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
            audit_export?: components["schemas"]["AuditExport"] | null;
            breach_check?: components["schemas"]["BreachMode"] | null;
            lockout?: components["schemas"]["LockoutMode"] | null;
            mfa?: components["schemas"]["MfaRequirement"] | null;
            /** @description TGL-03. */
            passkey_for_admins?: boolean | null;
            password_policy?: components["schemas"]["PasswordPolicy"] | null;
            profile?: components["schemas"]["Profile"] | null;
            secret_reveal?: components["schemas"]["RevealPolicy"] | null;
            session?: components["schemas"]["SessionLifetime"] | null;
            token_max_lifetime?: components["schemas"]["TokenMaxLifetime"] | null;
            updates?: components["schemas"]["UpdatePolicy"] | null;
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
        /**
         * @description The answer of `POST /setup`: the administrator's new session, plus the SHA-256 fingerprint
         *     of the internal CA root when the installation runs the internal CA, so that the wizard can
         *     offer the root for installation and the fingerprint to compare it with.
         */
        SetupResponse: components["schemas"]["SessionInfo"] & {
            /** @description SHA-256 fingerprint (hex) of the internal CA root; absent in the other TLS modes. */
            ca_fingerprint?: string | null;
        };
        /** @description `GET /setup`. */
        SetupState: {
            /** @description Whether setup is still open. */
            open: boolean;
            /** @description The profiles to choose from (while open). */
            profiles?: components["schemas"]["ProfileInfo"][];
        };
        /**
         * @description How serious a loss report entry is.
         * @enum {string}
         */
        Severity: "info" | "warning" | "error";
        /** @description How many values of a column have each shape. */
        ShapeCounts: {
            /** @description Addresses. */
            address: number;
            /** @description Networks and addresses with a prefix length. */
            cidr: number;
            /** @description DUIDs. */
            duid: number;
            /** @description Empty cells. */
            empty: number;
            /** @description MAC addresses. */
            mac: number;
            /** @description Numbers. */
            number: number;
            /** @description Address ranges. */
            range: number;
            /** @description Text. */
            text: number;
        };
        /** @description What the analysis found in one sheet. */
        SheetAnalysis: {
            /** @description Columns. */
            columns: components["schemas"]["ColumnAnalysis"][];
            /** @description Rows after the header with at least one value. */
            data_rows: number;
            /** @description The file the sheet comes from. */
            file: string;
            /** @description Whether the `Index` sheet lists the sheet's network or address. */
            listed_in_index: boolean;
            mask_source?: components["schemas"]["MaskSource"] | null;
            /**
             * @description Where the column roles of a sheet without header come from: the sheet whose header
             *     layout was borrowed.
             */
            roles_from?: string | null;
            /** @description Rows up to the last non-empty one. */
            rows: number;
            /** @description The sheet name (unique within the import). */
            sheet: string;
            /** @description The suggested mapping of the sheet. */
            suggested: components["schemas"]["SheetMapping"];
            /** @description Columns up to the widest row. */
            width: number;
        };
        /**
         * @description What a sheet is.
         * @enum {string}
         */
        SheetKind: "index" | "network" | "host" | "list" | "skip";
        /** @description The loss report entries of one sheet. */
        SheetLoss: {
            /** @description Entries in source order. */
            entries: components["schemas"]["LossItem"][];
            /** @description The sheet; `None` for entries about the whole import. */
            sheet?: string | null;
        };
        /** @description The mapping of one sheet. */
        SheetMapping: {
            /**
             * @description The network of a [`SheetKind::Network`] sheet.
             * @example 192.0.2.0/24
             */
            cidr?: string | null;
            /** @description Column targets; columns not listed are ignored. */
            columns?: components["schemas"]["ColumnMapping"][];
            /**
             * Format: int32
             * @description The header row, 1-based; `None` when the data starts in row 1.
             */
            header_row?: number | null;
            /** @description What the sheet is. */
            kind: components["schemas"]["SheetKind"];
            /** @description The sheet name (unique within the import). */
            sheet: string;
        };
        /** @description What became of a sheet. */
        SheetOutcome: {
            /** @description Its network, for network sheets. */
            cidr?: string | null;
            /** @description Address-only rows of a pre-filled list (free addresses). */
            free: number;
            /** @description Rows that produced something. */
            imported: number;
            /** @description What it was read as. */
            kind: components["schemas"]["SheetKind"];
            /** @description Rows with data after the header. */
            rows: number;
            /** @description The sheet. */
            sheet: string;
            /** @description Rows left out (see the loss report). */
            skipped: number;
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
        /**
         * @description The format of an uploaded file.
         * @enum {string}
         */
        SourceFormat: "csv" | "xlsx" | "xls" | "ods";
        /**
         * @description Where in the source an item came from: sheet, row and column for spreadsheets, a path or
         *     object name for other sources.
         */
        SourceLocation: {
            /** @description Column letter or header. */
            column?: string | null;
            /**
             * Format: int32
             * @description Row number, 1-based as shown by spreadsheet programs.
             */
            row?: number | null;
            /** @description Sheet, file or object collection. */
            sheet?: string | null;
        };
        /** @description The SSH hand-off: the URI for the operating system's SSH handler, without a secret. */
        SshHandoff: {
            /** @description The target: a DNS name, an IP address or the host name. */
            host: string;
            /**
             * Format: int32
             * @description The port.
             */
            port: number;
            /** @description `ssh://[user@]host[:port]`; the port only when it is not 22. */
            uri: string;
            /** @description The user name, when one is known. */
            username?: string | null;
        };
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
        /** @description Answer of `POST /cluster/step-down`. */
        StepDown: {
            /**
             * Format: int64
             * @description The controller that leads now.
             */
            leader: number;
            /**
             * Format: int64
             * @description The controller that led before.
             */
            previous: number;
            /**
             * Format: int64
             * @description The term of the new leadership.
             */
            term: number;
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
            /**
             * @description Whether this controller reaches a quorum (OPS-26). Absent in answers of servers
             *     that predate the controller cluster: a single controller.
             */
            quorum?: components["schemas"]["QuorumView"];
            /** @description Last applied revision. */
            revision: components["schemas"]["Revision"];
            /** @description `memory`, `leader`, `follower`, `learner`, `candidate` or `shutdown`. */
            role: string;
        };
        /**
         * @description The picture of one subject across sources, computed from its facts. Lists are sorted
         *     and without duplicates; they draw on the current facts, or on every fact when none is
         *     current.
         */
        SubjectSummary: {
            /** @description Attachments, one per source and MAC address. */
            attachments: components["schemas"]["AttachmentView"][];
            /** @description Whether any fact is current. */
            current: boolean;
            first_seen?: components["schemas"]["Timestamp"] | null;
            /** @description IP addresses. */
            ips: string[];
            last_seen?: components["schemas"]["Timestamp"] | null;
            /** @description MAC addresses. */
            macs: components["schemas"]["MacAddr"][];
            /**
             * @description Names: inventory names and the names probes found (reverse DNS, mDNS, LLMNR,
             *     SNMP), as reported.
             */
            names: string[];
            /** @description Open TCP ports (SCAN-08). */
            open_tcp: number[];
            /** @description Operating systems: inventory OS and probe OS guesses. */
            os: string[];
            /** @description Parent hosts (the hypervisor node of a VM). */
            parents: string[];
            /** @description Platforms (`qemu`, `lxc`, `esphome`). */
            platforms: string[];
            /** @description The sources with a current fact. */
            sources: string[];
            /** @description Tags from the sources. */
            tags: string[];
            /** @description The open TCP ports that answered a TLS handshake. */
            tls_tcp?: number[];
            /** @description Vendors of the MAC addresses (OUI) or as devices report them. */
            vendors?: string[];
        };
        /** @description The computed view of one subject. */
        SubjectView: {
            /**
             * @description Every fact that names the subject: current facts first, then by last sighting,
             *     newest first.
             */
            facts: components["schemas"]["ObservedFact"][];
            /** @description The intent objects that match. */
            intent: components["schemas"]["IntentMatch"];
            /**
             * Format: int64
             * @description The revision of the view.
             */
            revision: number;
            /** @description The last sightings of the matching addresses and interfaces. */
            sightings: components["schemas"]["ObjectSighting"][];
            /** @description The subject as asked: `mac:<mac>`, `ip:<ip>` or `name:<name>`. */
            subject: string;
            /** @description The picture across sources. */
            summary: components["schemas"]["SubjectSummary"];
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
        /** @description What the supervisor publishes. */
        SupervisorStatus: components["schemas"]["ProcessState"] & {
            /** @description When the status last changed. */
            changed_at: components["schemas"]["Timestamp"];
            /**
             * Format: int32
             * @description Failures since the last healthy run.
             */
            consecutive_failures: number;
            last_error?: components["schemas"]["CodedError"] | null;
            /**
             * Format: int32
             * @description How many times the plugin was started after its first start.
             */
            restarts: number;
        };
        /**
         * @description Components that act as [`Principal::System`].
         * @enum {string}
         */
        SystemComponent: "setup" | "api" | "auth" | "vault" | "store" | "ipam" | "import" | "jobs" | "reconciler" | "connector" | "scan" | "cluster" | "audit_export" | "backup" | "languages" | "leader";
        /** @description Body of `GET /system/status`. */
        SystemStatus: {
            cluster?: components["schemas"]["ClusterStatus"] | null;
            kek?: components["schemas"]["KekSummaryView"] | null;
            /**
             * @description The product modules this installation runs (OPS-25); the UI shows only their
             *     areas. Absent in answers of servers that predate the module switch: all modules.
             */
            modules?: components["schemas"]["ModuleSet"];
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
        /**
         * @description Import target: `ignore`, `address`, `prefix`, `mask`, `host`, `dns_name`, `description`, `status`, `mode`, `lock`, `mac`, `duid`, `client_id`, `interface`, `interfaces`, `vlan`, `vlan_name`, `site`, `vrf`, `tenant`, `role`, `alloc`, `alarm_warn`, `alarm_crit`, `tags`, `login`, `password` or `custom.<key>`
         * @example address
         */
        Target: string;
        /** @description A target the mapping step offers. */
        TargetInfo: {
            /** @description Whether values become operator secrets in the vault instead of IPAM fields. */
            credential: boolean;
            /** @description English label (the UI translates by `target`). */
            label: string;
            /** @description The target. */
            target: components["schemas"]["Target"];
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
        /** @description How a text file was decoded. */
        TextInfo: {
            /** @description Whether the file started with a byte order mark (always the case for UTF-16). */
            bom: boolean;
            /** @description The field delimiter: `,`, `;` or a tab. */
            delimiter: string;
            /** @description The encoding: `UTF-8`, `windows-1252`, `UTF-16LE` or `UTF-16BE`. */
            encoding: string;
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
        /**
         * @description `POST /auth/tokens` and `POST /access/service-accounts/{id}/tokens`. With `grants` or
         *     `scopes` the token is a scoped token (IAM-10): it acts with the intersection of its
         *     grants and the owner's, never more. Without them, `POST /auth/tokens` creates a
         *     personal token that acts with the owner's roles and grants.
         */
        TokenCreate: {
            /**
             * Format: int32
             * @description Lifetime in days; defaults to the TGL-05 maximum (or no expiry where it allows).
             */
            expires_in_days?: number | null;
            /**
             * @description The grants of a scoped token: each a role no higher than one the owner holds, over
             *     the whole installation or a scope inside one of the owner's grants.
             */
            grants?: components["schemas"]["TokenGrant"][] | null;
            /** @description A name for the token. */
            name: string;
            /** @description The special scopes of a scoped token: `metrics`, `audit:read`. */
            scopes?: components["schemas"]["TokenScope"][];
        };
        /** @description One grant of a scoped token: a role, globally or over one scope rule. */
        TokenGrant: {
            /** @description The role. */
            role: components["schemas"]["RoleName"];
            scope?: components["schemas"]["ScopeRule"] | null;
        };
        /** @description A personal token without its secret. */
        TokenInfo: {
            /** @description When it was created. */
            created_at: components["schemas"]["Timestamp"];
            expires_at?: components["schemas"]["Timestamp"] | null;
            /** @description The grants of a scoped token. */
            grants?: components["schemas"]["TokenGrant"][];
            /** @description The token id. */
            id: components["schemas"]["ApiTokenId"];
            last_used_at?: components["schemas"]["Timestamp"] | null;
            /** @description The name. */
            name: string;
            /** @description The first characters of the token. */
            prefix: string;
            /** @description A scoped token (IAM-10); absent for a personal token. */
            scoped?: boolean;
            /** @description The special scopes of a scoped token. */
            scopes?: components["schemas"]["TokenScope"][];
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
         * @description A special scope of a scoped token, beyond its grants (IAM-10, S3-Q7).
         * @enum {string}
         */
        TokenScope: "metrics" | "audit:read";
        /** @description The enrolment a token was used for. */
        TokenUse: {
            /** @description When. */
            at: components["schemas"]["Timestamp"];
            /** @description The node that enrolled. */
            node: components["schemas"]["NodeId"];
        };
        /**
         * @description An event topic. `GET /events?topics=ipam,jobs` subscribes to a subset; no `topics`
         *     parameter subscribes to all of them except `metrics`, which a client names to receive it.
         * @enum {string}
         */
        Topic: "ipam" | "jobs" | "audit" | "import" | "system" | "admin" | "connectors" | "discovery" | "secrets" | "cluster" | "metrics";
        /** @description An edge of the graph. */
        TopologyEdge: {
            /** @description One end: the switch, access point or hypervisor for client edges. */
            a: string;
            /** @description The port at `a`. */
            a_port?: string | null;
            /** @description The other end. */
            b: string;
            /** @description The port at `b`. */
            b_port?: string | null;
            /** @description Stable identifier, from the kind, the ends and their ports. */
            id: string;
            /** @description What it is. */
            kind: components["schemas"]["EdgeKind"];
            /** @description Source keys of the facts behind the edge. */
            sources: string[];
            /** @description The wireless network of a wireless edge. */
            ssid?: string | null;
            /**
             * Format: int32
             * @description The VLAN of a client edge.
             */
            vlan?: number | null;
        };
        /** @description The graph: nodes, edges and a summary, computed from one store revision. */
        TopologyGraph: {
            /** @description Edges, by identifier. */
            edges: components["schemas"]["TopologyEdge"][];
            /** @description Nodes, by identifier. */
            nodes: components["schemas"]["TopologyNode"][];
            /**
             * Format: int64
             * @description The store revision the graph was computed from.
             */
            revision: number;
            /** @description Counts and context. */
            summary: components["schemas"]["TopologySummary"];
        };
        /** @description A node of the graph: one device as every source sees it, with the intent joined in. */
        TopologyNode: {
            host?: components["schemas"]["HostId"] | null;
            /**
             * @description Stable identifier: `h-` and the host for a device of intent, `c-` for a device of a
             *     network controller, `i-` for an inventory host, `m-` and the MAC address, `n-` for a
             *     device named by a probe, `a-` for an address.
             */
            id: string;
            /** @description IP addresses. */
            ips?: string[];
            /** @description What it is. */
            kind: components["schemas"]["NodeKind"];
            /**
             * @description The best name: the host of intent, the controller's name, the inventory name, a
             *     probe's name, the vendor with the MAC address, the MAC or IP address.
             */
            label: string;
            last_seen?: components["schemas"]["Timestamp"] | null;
            /** @description MAC addresses. */
            macs?: components["schemas"]["MacAddr"][];
            /** @description The model a controller reports. */
            model?: string | null;
            /** @description The operating system an inventory or probe reports. */
            os?: string | null;
            /** @description The most specific networks of intent that hold its addresses. */
            prefixes?: components["schemas"]["PrefixId"][];
            site?: components["schemas"]["SiteId"] | null;
            /** @description Source keys of the facts behind the node (`intent` for a host of intent). */
            sources: string[];
            /** @description Wireless networks an access point broadcasts or a client uses. */
            ssids?: string[];
            /**
             * @description The subject to look the node up across sources (`GET /observations/{subject}`): its
             *     first MAC address, else its first IP address.
             */
            subject?: string | null;
            /** @description The vendor of the first MAC address. */
            vendor?: string | null;
            /**
             * @description VLAN ids the node is in: client attachments, the VLANs of its networks, the
             *     untagged VLANs of its ports.
             */
            vlans?: number[];
        };
        /** @description One node with its ports, neighbours and intent (`GET /topology/nodes/{id}`). */
        TopologyNodeView: {
            intent?: components["schemas"]["NodeIntent"] | null;
            /** @description Every neighbour, also those across edges without a port on this side. */
            neighbours: components["schemas"]["Neighbour"][];
            /** @description The node. */
            node: components["schemas"]["TopologyNode"];
            /** @description Its ports with what hangs on each; with `port`, only that port. */
            ports: components["schemas"]["TopologyPort"][];
            /**
             * Format: int64
             * @description The store revision of the graph.
             */
            revision: number;
        };
        /** @description A port of a node and what hangs on it. */
        TopologyPort: {
            /** @description The controller's name of the port. */
            name?: string | null;
            /**
             * Format: int32
             * @description The untagged VLAN the controller reports.
             */
            native_vlan?: number | null;
            /** @description Everything seen behind the port. */
            neighbours: components["schemas"]["Neighbour"][];
            /** @description The port as the sources name it. */
            port: string;
            /** @description Link state, when a controller reports it. */
            up?: boolean | null;
            /** @description Whether the controller marks it as an uplink. */
            uplink?: boolean;
        };
        /** @description Counts and context of a graph. */
        TopologySummary: {
            /** @description Edges in the answer per kind. */
            by_edge_kind: {
                [key: string]: number;
            };
            /** @description Nodes in the answer per kind. */
            by_kind: {
                [key: string]: number;
            };
            computed_at?: components["schemas"]["Timestamp"] | null;
            /** @description The network controllers and how their last read went. */
            controllers: components["schemas"]["ControllerStatus"][];
            /** @description Edges in the answer. */
            edges: number;
            /** @description The networks the controllers report, with their VLANs. */
            networks: components["schemas"]["NetworkInView"][];
            /** @description Nodes in the answer. */
            nodes: number;
            /** @description The sites of the nodes in the answer. */
            sites: components["schemas"]["SiteId"][];
            /** @description Edges of the whole graph before filtering. */
            total_edges: number;
            /** @description Nodes of the whole graph before filtering. */
            total_nodes: number;
            /** @description Whether the answer was cut at the node limit. */
            truncated?: boolean;
            /** @description The VLANs of the nodes in the answer, by VLAN id. */
            vlans: components["schemas"]["VlanInView"][];
        };
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
        /** @description The last install attempt. */
        UpdateAttempt: {
            /** @description When it reached this state. */
            at: components["schemas"]["Timestamp"];
            /** @description The version before. */
            from: components["schemas"]["ReleaseVersion"];
            job_id?: components["schemas"]["JobId"] | null;
            /** @description The code of a failure or of the reason for a switch back. */
            reason?: string | null;
            /** @description Where it stands. */
            state: components["schemas"]["AttemptState"];
            /** @description The version installed. */
            to: components["schemas"]["ReleaseVersion"];
        };
        /** @description The scheduled check of the release source. */
        UpdateCheck: {
            /** @description Whether the check runs. */
            enabled: boolean;
            /**
             * Format: int32
             * @description Hours between two checks.
             */
            interval_hours: number;
            last_checked?: components["schemas"]["Timestamp"] | null;
            /** @description The code of the last failed check, for example `update.fetch_failed`. */
            last_error?: string | null;
            off_reason?: components["schemas"]["CheckOff"] | null;
            /** @description The URL of the release manifest. */
            source: string;
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
        /**
         * @description How an administrator may install a new version from the UI (TGL-23, OPS-24).
         * @enum {string}
         */
        UpdateInstall: "ui" | "ui_step_up" | "upload_only";
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
        /**
         * @description TGL-23: the in-app update check and install (OPS-24). The check sends nothing but the
         *     running version; `updates.air_gapped` in `tenko.toml` stops it regardless.
         */
        UpdatePolicy: {
            /** @description Check the release source daily. */
            check: boolean;
            /** @description How a new version may be installed. */
            install: components["schemas"]["UpdateInstall"];
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
        /** @description `GET /system/updates`. */
        UpdateStatus: {
            attempt?: components["schemas"]["UpdateAttempt"] | null;
            /** @description The scheduled check. */
            check: components["schemas"]["UpdateCheck"];
            /**
             * Format: int32
             * @description The data-directory format of the running binary.
             */
            format: number;
            /** @description How a new version can be installed. */
            install: components["schemas"]["InstallAbility"];
            latest?: components["schemas"]["ReleaseVersion"] | null;
            manifest?: components["schemas"]["ManifestInfo"] | null;
            /** @description The platform of this server, `<os>-<arch>`. */
            platform: string;
            /** @description The releases newer than the running one, newest first, with their notes. */
            releases: components["schemas"]["Release"][];
            /** @description A newer release needs an action when upgrading. */
            requires_action: boolean;
            /** @description The running version. */
            running: components["schemas"]["ReleaseVersion"];
            /** @description A newer release fixes security issues. */
            security: boolean;
            /** @description A release newer than the running one exists. */
            update_available: boolean;
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
            /** @description Global roles; may be empty for an account that acts through scoped grants only. */
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
            /** @description A service account (IAM-10); absent for a person. */
            kind?: components["schemas"]["UserKind"];
            /** @description The fixed UI language. */
            language?: string | null;
            last_login_at?: components["schemas"]["Timestamp"] | null;
            lock?: components["schemas"]["AccountLock"] | null;
            /** @description The login name. */
            name: string;
            owner?: components["schemas"]["UserId"] | null;
            /** @description The password must be changed. */
            password_change_required: boolean;
            /** @description The revision for `If-Match`. */
            revision: components["schemas"]["Revision"];
            /** @description Global roles. */
            roles: components["schemas"]["RoleName"][];
        };
        /**
         * @description What kind of account a user record is (IAM-10).
         * @enum {string}
         */
        UserKind: "person" | "service";
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
        /**
         * @description The two sides share no protocol major (`cluster.protocol.unsupported`, HTTP 409).
         *
         *     Both lists are kept as they were offered, sorted ascending and without duplicates.
         */
        VersionMismatch: {
            /** @description The majors this side implements, sorted ascending and deduplicated. */
            ours: number[];
            /** @description The majors the other side offered, sorted ascending and deduplicated. */
            theirs: number[];
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
        /** @description One VLAN in view, for the legend. */
        VlanInView: {
            /** @description Its name. */
            name?: string | null;
            /** @description Nodes in it. */
            nodes: number;
            /**
             * Format: int32
             * @description The VLAN id.
             */
            vid: number;
            vlan?: components["schemas"]["VlanId"] | null;
        };
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
        /** @description The preview of a provision (the dry run, API-09). */
        VlanProvisionPreview: {
            /**
             * Format: int64
             * @description The store revision the preview was computed at.
             */
            base_revision: number;
            /** @description The network step. */
            controller: components["schemas"]["ControllerPreview"];
            plan?: components["schemas"]["PlanView"] | null;
            prefix?: components["schemas"]["PrefixTarget"] | null;
            /** @description The steps of the job, in order. */
            steps: components["schemas"]["VlanStepPreview"][];
            /** @description Warning codes that need an acknowledgement before a submit. */
            unacknowledged?: string[];
            /** @description The VLAN. */
            vlan: components["schemas"]["VlanTarget"];
            /** @description Every warning: of the IPAM plan and of the network step. */
            warnings?: components["schemas"]["PlanWarning"][];
        };
        /** @description A request to create a VLAN with its network (IPAM-03). */
        VlanProvisionRequest: {
            /** @description Warning codes the caller acknowledges. */
            acknowledge?: string[];
            connector?: components["schemas"]["ConnectorId"] | null;
            create?: components["schemas"]["NewVlan"] | null;
            /**
             * @description DHCP relay targets of the network (Tenko serves DHCP); the controller's DHCP is off
             *     when empty.
             */
            dhcp_relay?: string[];
            /** @description Leave the controller alone: a person creates the network. */
            manual?: boolean;
            /** @description The network name on the controller; the VLAN name when absent. */
            network_name?: string | null;
            prefix?: components["schemas"]["NewVlanPrefix"] | null;
            vlan?: components["schemas"]["VlanId"] | null;
        };
        /** @description The answer of a submitted provision. */
        VlanProvisionSubmitted: {
            /** @description The job. */
            job_id: components["schemas"]["JobId"];
            prefix?: components["schemas"]["PrefixId"] | null;
            /** @description The preview as computed at submit, to compare with the dry run. */
            preview: components["schemas"]["VlanProvisionPreview"];
            /** @description Whether an earlier answer was returned for a repeated idempotency key. */
            replayed?: boolean;
            /** @description The VLAN. */
            vlan: components["schemas"]["VlanId"];
        };
        /** @description One step of the job, as previewed. */
        VlanStepPreview: {
            /** @description Whether Tenko does it; otherwise a person ticks it off. */
            automatic: boolean;
            /** @description `ipam.intent`, `l2.network`, `l2.manual` or `activate`. */
            kind: string;
            /** @description Values for the text (VLAN id, name, network, connector). */
            params: {
                [key: string]: string;
            };
            /** @description The engine's step kind (`ipam.vlan.intent`, ...). */
            step_kind: string;
            /** @description English description. */
            text: string;
        };
        /** @description The VLAN of a provision. */
        VlanTarget: {
            /** @description Whether it exists already. */
            existing: boolean;
            /** @description The VLAN (the identifier it will have when the job creates it). */
            id: components["schemas"]["VlanId"];
            /** @description Its name. */
            name: string;
            site?: components["schemas"]["SiteId"] | null;
            /** @description Its status now, or `planned` for a new one. */
            status: components["schemas"]["Status"];
            /**
             * Format: int32
             * @description The VLAN id.
             */
            vid: number;
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
        /** @description `GET /system/updates/whats-new`: the notes to show a user once after an upgrade. */
        WhatsNew: {
            last_seen?: components["schemas"]["ReleaseVersion"] | null;
            /** @description The releases after `last_seen` up to the running one, newest first. */
            releases: components["schemas"]["Release"][];
            /** @description The running version. */
            running: components["schemas"]["ReleaseVersion"];
            /** @description Whether to show the notes now: the user saw an older version's notes. */
            show: boolean;
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
                /** @description `host`: each address bound to an interface also carries `interface_detail` (`id`, `name`, `mac`, `duid`) and `host` (`id`, `name`, `mode`, `lock`), read from the same view as the page. Both are absent for an unbound address, when the interface or host is deleted, and when the principal may not read interfaces and hosts. Does not change the cursor. */
                expand?: string;
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
                    "application/json": components["schemas"]["Page_AddressRow"];
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
            /** @description The session is not strong enough (`auth.step_up_required`) is the break-glass session (`auth.break_glass.hardware_key_only`), or a grant of a scoped token goes beyond the owner's (`auth.grant.exceeds_own`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The lifetime exceeds the maximum of the profile (`auth.token.lifetime_exceeded`), a grant names a global-only role (`auth.grant.invalid_role`) or a scope that cannot be granted or does not exist (`auth.grant.invalid_scope`) */
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
    get_cluster_digests: {
        parameters: {
            query?: {
                /** @description The revision to compare at; default the newest revision the answering controller applied */
                revision?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The digest of every member at one revision */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DigestReport"];
                };
            };
            /** @description The revision is not a number (`sys.invalid_query`) */
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
            /** @description Not allowed to read nodes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The controller is still starting (`cluster.member.starting`) */
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
    list_cluster_members: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The cluster as this controller sees it */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClusterView"];
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
            /** @description Not allowed to read nodes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No leader is known to answer the replication figures (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`) */
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
    remove_cluster_member: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Node id of the member */
                id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The cluster after the change */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClusterView"];
                };
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to change the controller cluster (an administrator right) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The node is not a member (`cluster.member.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The change would remove the last voter (`cluster.member.last_voter`), another change is in progress (`cluster.member.changing`) or the controller is not part of a cluster (`cluster.single`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No leader is known to take the change (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`) */
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
    promote_cluster_member: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Node id of the learner */
                id: number;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["PromoteRequest"];
            };
        };
        responses: {
            /** @description The cluster after the change */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ClusterView"];
                };
            };
            /** @description The identifier or the body is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to change the controller cluster (an administrator right) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The node, or the voter to replace, is not a member (`cluster.member.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The result would have an even number of voters (`cluster.member.even_voters`), the learner is too far behind or out of contact (`cluster.member.not_caught_up`), another change is in progress (`cluster.member.changing`) or the controller is not part of a cluster (`cluster.single`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No leader is known to take the change (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`) */
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
    step_down_cluster_leader: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The controller that led, the one that leads now and the new term */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["StepDown"];
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
            /** @description Not allowed to change the controller cluster (an administrator right) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No other voter is caught up (`cluster.member.no_successor`), a membership change is in progress (`cluster.member.changing`) or the controller is not part of a cluster (`cluster.single`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No leader is known (`cluster.member.not_leader`) or the controller is still starting (`cluster.member.starting`) */
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
    list_connectors: {
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
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of connector instances by name; empty without permission to read connectors */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_ConnectorView"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`) */
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
    create_connector: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NewConnector"];
            };
        };
        responses: {
            /** @description The new instance, with `ETag` */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ConnectorView"];
                };
            };
            /** @description The body is not valid JSON (`sys.invalid_request`) */
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
            /** @description Not allowed to create connectors, or to reveal a referenced secret (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Another instance has the name (`connect.instance.name_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Unknown or unusable plugin (`connect.plugin.unknown`, `connect.plugin.unusable`), invalid settings (`connect.settings.invalid`, with field errors), secret references (`connect.secret.undeclared`, `connect.secret.missing`, `connect.secret.not_found`, `connect.secret.not_operator`) or values (`connect.instance.name`, `connect.instance.poll_interval`, `connect.instance.call_timeout`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_connector_plugins: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The plugins; empty without permission to read connectors */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PluginList"];
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
    get_connector: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes) */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The instance, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ConnectorView"];
                };
            };
            /** @description The identifier or a parameter is malformed (`sys.invalid_request`, `sys.invalid_query`) */
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
            /** @description Not allowed to read the instance */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
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
    delete_connector: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to delete the instance */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The instance changed at the same time (`connect.instance.conflict`) */
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
    update_connector: {
        parameters: {
            query?: never;
            header?: {
                /** @description Apply only to this revision (the `ETag` of a read) */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ConnectorPatch"];
            };
        };
        responses: {
            /** @description The changed instance, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ConnectorView"];
                };
            };
            /** @description The identifier, `If-Match` or the body is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to change the instance, or to reveal a referenced secret (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The name is taken (`connect.instance.name_taken`) or the instance changed since `If-Match` (`connect.instance.conflict`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Invalid settings, secret references or values, as for create */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    check_connector: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The health of the remote system */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HealthReport"];
                };
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to run the instance */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The instance is disabled (`connect.instance.disabled`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The plugin is not running (`connect.plugin.unavailable`, `connect.plugin.unusable`) or the vault or audit log is not available */
            503: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The plugin did not answer in time (`connect.timeout`) */
            504: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    disable_connector: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The instance, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ConnectorView"];
                };
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to change the instance */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The instance changed at the same time (`connect.instance.conflict`) */
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
    enable_connector: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The instance, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ConnectorView"];
                };
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to change the instance */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The instance changed at the same time (`connect.instance.conflict`) */
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
    run_connector: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Connector identifier (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The run was submitted as a job */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RunAccepted"];
                };
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to run the instance */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such instance (`connect.instance.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The instance is disabled (`connect.instance.disabled`) or its plugin reads nothing (`connect.instance.nothing_to_run`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The job engine is not available (`connect.jobs_unavailable`) */
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
                 * @description Comma-separated topics: `ipam`, `jobs`, `audit`, `import`, `system`, `admin`,
                 *     `connectors`, `discovery`, `secrets`, `cluster`, `metrics`; all except `metrics` when
                 *     absent.
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
            query?: {
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description `addresses.csv`: UTF-8 with a byte order mark, comma separated, CRLF line ends */
            200: {
                headers: {
                    /** @description `no-store` */
                    "Cache-Control"?: string;
                    /** @description `attachment; filename="addresses.csv"` */
                    "Content-Disposition"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "text/csv": string;
                };
            };
            /** @description Unknown or malformed query parameter (`sys.invalid_query`) */
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
    export_hosts_csv: {
        parameters: {
            query?: {
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description `hosts.csv`: UTF-8 with a byte order mark, comma separated, CRLF line ends */
            200: {
                headers: {
                    /** @description `no-store` */
                    "Cache-Control"?: string;
                    /** @description `attachment; filename="hosts.csv"` */
                    "Content-Disposition"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "text/csv": string;
                };
            };
            /** @description Unknown or malformed query parameter (`sys.invalid_query`) */
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
    export_prefixes_csv: {
        parameters: {
            query?: {
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description `prefixes.csv`: UTF-8 with a byte order mark, comma separated, CRLF line ends */
            200: {
                headers: {
                    /** @description `no-store` */
                    "Cache-Control"?: string;
                    /** @description `attachment; filename="prefixes.csv"` */
                    "Content-Disposition"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "text/csv": string;
                };
            };
            /** @description Unknown or malformed query parameter (`sys.invalid_query`) */
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
    get_host_credentials: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Host identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The credentials of the host, with `ETag` (the version of the set) */
            200: {
                headers: {
                    /** @description The version of the set, for `If-Match` */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HostCredentialsView"];
                };
            };
            /** @description The identifier is not a UUID (`sys.invalid_request`) */
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
    update_host_credentials: {
        parameters: {
            query?: never;
            header?: {
                /** @description The version of the set the client read, as in the `ETag`; a stale version is refused with 409 */
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
                "application/json": components["schemas"]["HostCredentialsUpdate"];
            };
        };
        responses: {
            /** @description The credentials of the host after the change, with `ETag` */
            200: {
                headers: {
                    /** @description The new version of the set */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["HostCredentialsView"];
                };
            };
            /** @description The body or `If-Match` is malformed (`sys.invalid_request`, `sys.invalid_value`) */
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
            /** @description Not allowed (`auth.forbidden`, `auth.step_up_required`) */
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
            /** @description `If-Match` is stale or the set changed meanwhile (`vault.host_credentials.conflict`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many bindings or a secret twice (`vault.secret.invalid`), or a secret that is not an operator secret (`vault.host_credentials.secret_missing`) */
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
    get_host_remote: {
        parameters: {
            query: {
                /** @description `rdp` or `ssh`. */
                protocol: "rdp" | "ssh";
                /** @description An interface of the host to connect through. */
                interface?: components["schemas"]["InterfaceId"];
                /** @description An IP address of the host, or the DNS name of one of its addresses, used as given. */
                address?: string;
                /** @description The TCP port, 1 to 65535 (default 3389 for RDP, 22 for SSH). */
                port?: number;
                /** @description The user name; by default the one of the credential bound to the host. */
                user?: string;
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
            /** @description For `rdp` an `.rdp` file as an attachment (CRLF line ends, it prompts for the password); for `ssh` the URI */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/x-rdp": string;
                    "application/json": components["schemas"]["SshHandoff"];
                };
            };
            /** @description A parameter is missing, unknown or malformed (`sys.invalid_query`) */
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
            /** @description The interface or address does not belong to the host (`remote.interface_unknown`, `remote.address_unknown`) */
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
    get_languages: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The languages users may choose */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["LanguageList"];
                };
            };
        };
    };
    list_packs: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every language with its versions */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackList"];
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
            /** @description Not allowed (`auth.forbidden`) */
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
    upload_pack: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "multipart/form-data": components["schemas"]["PackUploadForm"];
            };
        };
        responses: {
            /** @description Validated and stored as the candidate of its language */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackUpload"];
                };
            };
            /** @description No file, several files or a malformed multipart body (`i18n.upload.empty`, `i18n.upload.malformed`) */
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Over 2 MiB (`i18n.pack.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not a usable pack (`i18n.pack.invalid`, the problems in `errors`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No embedded UI to check against (`i18n.unavailable`) */
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
    get_pack: {
        parameters: {
            query?: {
                /** @description The hash from `GET /i18n/languages`: the answer may then be cached for a year. */
                hash?: string;
            };
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The messages, with the content hash as ETag */
            200: {
                headers: {
                    /** @description The content hash in quotes */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackMessages"];
                };
            };
            /** @description Not modified (If-None-Match) */
            304: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description No active uploaded pack for the tag (`i18n.pack.not_found`) */
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
    delete_pack: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Removed */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Nothing uploaded for the tag (`i18n.pack.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The installation's default language (`i18n.pack.default_language`) */
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
    activate_pack: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The language with its new active version */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackInfo"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No candidate (`i18n.pack.no_candidate`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not previewed yet (`i18n.pack.not_previewed`) */
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
    get_pack_candidate: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The messages of the candidate */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackMessages"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No candidate (`i18n.pack.no_candidate`) */
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
    discard_pack_candidate: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The language without the candidate */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackInfo"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No candidate (`i18n.pack.no_candidate`) */
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
    preview_pack: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The language with its candidate marked previewed */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackInfo"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No candidate (`i18n.pack.no_candidate`) */
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
    get_pack_report: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description BCP 47 language tag */
                tag: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The report */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PackReport"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Nothing uploaded for the tag (`i18n.pack.not_found`) */
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
    get_template: {
        parameters: {
            query?: {
                /**
                 * @description The language whose current messages fill the targets; the source language (`en`) by
                 *     default, whose template has the English text as every target.
                 */
                language?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The XLIFF 2.0 document */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/xliff+xml": string;
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not a language tag (`i18n.pack.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No embedded UI (`i18n.unavailable`) */
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
            /** @description The upload with its sheets, columns and suggested mapping */
            201: {
                headers: {
                    /** @description The URL of the new import */
                    Location?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ImportView"];
                };
            };
            /** @description No file in the upload, or the multipart body is malformed (`import.upload.empty`, `import.upload.malformed`) */
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
            /** @description The upload exceeds the size limit (`import.upload.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A file is not CSV or a workbook (`import.upload.unsupported`) */
            415: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A file cannot be read (`import.upload.unreadable`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Import not configured (`import.unavailable`) */
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
            /** @description The upload with its analysis and mapping */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ImportView"];
                };
            };
            /** @description The identifier is not a UUID (`sys.invalid_request`) */
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
            /** @description No such import (`import.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`) */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Import not configured (`import.unavailable`) */
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
            /** @description The upload is discarded */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is not a UUID (`sys.invalid_request`) */
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
            /** @description No such import (`import.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The import is being applied (`import.state.conflict`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`) */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Import not configured (`import.unavailable`) */
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
    apply_import: {
        parameters: {
            query?: never;
            header?: {
                /** @description Repeating a POST with the same key returns the first result (API-04). */
                "Idempotency-Key"?: string | null;
            };
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        /** @description Optional; an empty body means no extra acknowledgements */
        requestBody?: {
            content: {
                "application/json": components["schemas"]["ApplyRequest"] | null;
            };
        };
        responses: {
            /** @description The apply job was accepted; follow it at `/jobs/{id}` */
            202: {
                headers: {
                    /** @description The URL of the job */
                    Location?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ApplyAccepted"];
                };
            };
            /** @description The identifier is not a UUID, or the body is not valid JSON for an apply request (`sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`), or the credential columns cannot be stored (`import.credentials.vault_required`, parameter `reason`: `vault_unavailable`, `step_up_required`, `forbidden` or `unauthenticated`; parameter `required`: the weakest session strength for a step-up) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such import (`import.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The plan has warnings that need an acknowledgement or conflicts, or the import is busy (`import.plan.blocked`, `import.state.conflict`, or the plan's own error) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`) */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The body is too large (`sys.body_too_large`) */
            413: {
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
            /** @description Import not configured (`import.unavailable`) */
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
        requestBody: {
            content: {
                "application/json": components["schemas"]["Mapping"];
            };
        };
        responses: {
            /** @description The upload with the mapping in force (`mapped` is true) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ImportView"];
                };
            };
            /** @description The identifier is not a UUID, or the body is not valid JSON for a mapping (`sys.invalid_request`) */
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
            /** @description No such import (`import.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The import is being applied (`import.state.conflict`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`) */
            410: {
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
            /** @description The mapping does not fit the upload (`import.mapping.invalid`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Import not configured (`import.unavailable`) */
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
    preview_import: {
        parameters: {
            query?: {
                /** @description How many source rows to list, 1 to 1,000. The summary and the loss report always cover the whole import. */
                rows?: number;
            };
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The preview */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ImportPreview"];
                };
            };
            /** @description The identifier is not a UUID, or a query parameter is unknown or out of range (`sys.invalid_request`, `sys.invalid_query`) */
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
            /** @description No such import (`import.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`) */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Import not configured (`import.unavailable`) */
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
    list_import_rows: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 200) */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor` */
                cursor?: string;
            };
            header?: never;
            path: {
                /** @description Import identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of preview rows */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ImportRowsPage"];
                };
            };
            /** @description The identifier is not a UUID, a parameter is unknown or out of range, or the cursor is malformed (`sys.invalid_request`, `sys.invalid_query`, `sys.invalid_cursor`) */
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
            /** @description No such import (`import.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No preview for the current mapping, or the mapping changed since the cursor was made (`import.preview.stale`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The upload expired or was lost in a restart (`import.expired`, `import.upload.lost`) */
            410: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Import not configured (`import.unavailable`) */
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
    create_move: {
        parameters: {
            query?: {
                /** @description Compute the preview without starting anything (API-09). */
                dry_run?: boolean;
                /** @description For a dry run: read at least at this store revision. */
                at_least?: number;
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
                "application/json": components["schemas"]["MoveRequest"];
            };
        };
        responses: {
            /** @description The preview of a dry run */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MovePreview"];
                };
            };
            /** @description The jobs of the move, one per moved address, in one job group */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["MoveSubmitted"];
                };
            };
            /** @description Invalid request (`ipam.move.invalid_request`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
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
            /** @description An object or the target does not exist (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A warning needs an acknowledgement (`ipam.plan.unacknowledged`), the plan differs from the confirmed preview (`ipam.move.plan_changed`), the target is full (`ipam.address.full`) or an object is deleted (`ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description An object cannot move (`ipam.move.unmanaged`, `ipam.move.nothing_to_move`, `ipam.move.already_in_target`, `ipam.move.family_mismatch`, `ipam.move.unsupported_object`, `ipam.move.target_not_network`), or the idempotency key was used for another move (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A host is locked (`ipam.host.locked`) */
            423: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM or the job engine is not configured (`ipam.unavailable`, `ipam.move.no_engine`) */
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
    list_nodes: {
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
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of nodes by id; empty without permission to read nodes */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_NodeView"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`) */
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
    enrol_node: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["EnrolRequest"];
            };
        };
        responses: {
            /** @description The node, its certificate and the CA root (`Cache-Control: no-store`) */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrolResponse"];
                };
            };
            /** @description The body is not valid JSON (`sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The token is not valid (`cluster.enrolment.invalid_token`), was used (`cluster.enrolment.used`) or expired (`cluster.enrolment.expired`) */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The token does not allow a requested role (`cluster.enrolment.roles`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No common protocol major (`cluster.protocol.unsupported`) or the name is taken (`cluster.node.name_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The certificate request (`cluster.ca.invalid_csr`), the name (`cluster.node.name`) or the address (`cluster.node.address`) is not usable */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_enrolments: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Every token, newest first */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["EnrolmentList"];
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
            /** @description Not allowed to enrol nodes */
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
    create_enrolment: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NewEnrolment"];
            };
        };
        responses: {
            /** @description The token, shown once (`Cache-Control: no-store`) */
            201: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["CreatedEnrolment"];
                };
            };
            /** @description The body is not valid JSON (`sys.invalid_request`) */
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
            /** @description Not allowed to enrol nodes, or a controller token without a sign-in in the last five minutes (`auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A node has the name (`cluster.node.name_taken`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The role controller beside another role (`cluster.enrolment.roles`), a lifetime outside 60 s to 7 days or a controller token for more than an hour (`cluster.enrolment.lifetime`), or a bad name (`cluster.node.name`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    delete_enrolment: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Token id (UUID) */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to enrol nodes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such token (`cluster.enrolment.not_found`) */
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
    get_node: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Node id */
                id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The node, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["NodeView"];
                };
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to read nodes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such node (`cluster.node.not_found`) */
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
    revoke_node: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Node id */
                id: number;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Revoked */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier is malformed (`sys.invalid_request`) */
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
            /** @description Not allowed to revoke nodes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such node (`cluster.node.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The node changed at the same time (`cluster.node.conflict`) */
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
    list_observations: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only facts of this source: a source key such as `inventory:<connector>`, or a connector identifier (which matches the inventory and the network controller source of the connector). */
                source?: string;
                /** @description Only facts about this kind of subject: `host`, `address`, `attachment`, `services`, `os`, `link`, `name` or `vendor`. */
                type?: string;
                /** @description Only facts that name this MAC address (`00-00-5E-00-53-01` or `00:00:5e:00:53:01`). */
                mac?: string;
                /** @description Only facts that name this IP address. */
                ip?: string;
                /** @description Only facts that name an IP address inside this network, such as `192.0.2.0/24`. */
                within?: string;
                /** @description Case-insensitive text search over the subject, the name, the operating system, the platform, the parent, the tags and the attachment device. */
                q?: string;
                /** @description `true`: only facts that count as current now; `false`: only expired facts. */
                current?: boolean;
                /** @description Sort order: comma-separated fields, `-` in front for descending. Fields: `last_seen` (the default, newest first), `first_seen`, `source`, `subject`. */
                sort?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of facts */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_ObservedFact"];
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
    get_observation: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description A MAC address (`00-00-5E-00-53-01` or `00:00:5e:00:53:01`), an IP address or a name (compared without case). */
                subject: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The facts that name the subject, the picture across sources, the intent objects that match and their last sightings */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SubjectView"];
                };
            };
            /** @description The subject is not a MAC address, an IP address or a name (`ipam.validation`), or a parameter is unknown (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read observations */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No source has observed the subject (`ipam.not_found`) */
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
                /** @description `host`: each address bound to an interface also carries `interface_detail` (`id`, `name`, `mac`, `duid`) and `host` (`id`, `name`, `mode`, `lock`), read from the same view as the page. Both are absent for an unbound address, when the interface or host is deleted, and when the principal may not read interfaces and hosts. Does not change the cursor. */
                expand?: string;
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
    get_adoption_policy: {
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
            /** @description The policy view, with `ETag: "<revision>"` of the prefix's own policy (`"0"` without one) */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PolicyView"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`) */
            400: {
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
            /** @description The prefix is deleted (`ipam.object_deleted`) */
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
    set_adoption_policy: {
        parameters: {
            query?: never;
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
                "application/json": components["schemas"]["AdoptionPolicy"];
            };
        };
        responses: {
            /** @description The policy view after the change, with `ETag` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PolicyView"];
                };
            };
            /** @description The policy is invalid (`ipam.adoption.invalid`), the body is malformed (`sys.invalid_request`), or a parameter is unknown (`sys.invalid_query`) */
            400: {
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
            /** @description The prefix is deleted (`ipam.object_deleted`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.revision_mismatch`); `"0"` means that the prefix has no policy of its own */
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
    clear_adoption_policy: {
        parameters: {
            query?: never;
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
            /** @description The policy view after the change: no policy of its own, the inherited one in force */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["PolicyView"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`) */
            400: {
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
            /** @description The prefix is deleted (`ipam.object_deleted`) */
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
    list_proposals: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Only proposals of these kinds: `discovered_host`, `orphaned_intent`, `address_mismatch`, `conflict` or `outside_prefixes`. Repeat the parameter or separate the kinds with commas. */
                kind?: string;
                /** @description Only proposals in these states: `open`, `accepted`, `rejected`, `expired` or `superseded`. Repeat the parameter or separate the states with commas. Every state when absent. */
                state?: string;
                /** @description Only proposals of these severities: `info`, `warning` or `critical`. */
                severity?: string;
                /** @description Only proposals about this prefix (identifier): its own subject, an address or a network inside it, or the prefix among the involved objects. */
                prefix?: string;
                /** @description Only proposals about this subject: a MAC address, an IP address, an object identifier, or text contained in the subject name or key. */
                subject?: string;
                /** @description Sort order: comma-separated fields, `-` in front for descending. Fields: `created` (the default, newest first), `updated`, `severity`, `kind`, `state`, `last_seen`. */
                sort?: string;
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of proposals */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_IntentProposal"];
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
            /** @description The prefix filter names no prefix (`ipam.not_found`) */
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
    reconcile_proposals: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description What the run did: proposals opened, refreshed, superseded, expired and adopted, and the revision of its write */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ReconcileReport"];
                };
            };
            /** @description A parameter is unknown (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not decide proposals */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The reconciler does not run on this server (`ipam.reconciler.unavailable`) */
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
    get_proposal: {
        parameters: {
            query?: {
                /** @description Read at least at this store revision (read-your-writes). */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description Proposal identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The proposal, with `ETag: "<revision>"` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["IntentProposal"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not read the proposal */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such proposal (`ipam.proposal.not_found`) */
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
    approve_proposal: {
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
                /** @description Proposal identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The decision: the accepted proposal, the revision, the inline job and the objects changed, with `ETag` of the proposal; on a dry run the proposal as it is and the plan, with nothing written */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Decision"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`, `sys.invalid_request`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not approve proposals, or not make one of the changes */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such proposal (`ipam.proposal.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The proposal is decided already (`ipam.proposal.not_open`), suggests no change (`ipam.proposal.nothing_to_apply`), a warning needs an acknowledgement (`ipam.plan.unacknowledged`), or the change conflicts with intent (`ipam.name_taken`, `ipam.address.duplicate`, `ipam.reference_missing`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.proposal.revision_mismatch`) */
            412: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A host of the change is locked (`ipam.host.locked`) */
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
    reject_proposal: {
        parameters: {
            query?: never;
            header?: {
                /**
                 * @description The revision the client read, as `"12"`; the write fails with 412
                 *     `ipam.revision_mismatch` when the object changed since.
                 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Proposal identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["RejectRequest"];
            };
        };
        responses: {
            /** @description The decision: the rejected proposal and the revision, with `ETag` of the proposal */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Decision"];
                };
            };
            /** @description The reason is over 1,024 bytes or has control characters (`ipam.validation`), the body is malformed (`sys.invalid_request`), or a parameter is unknown (`sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The principal may not decide proposals */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such proposal (`ipam.proposal.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The proposal is decided already (`ipam.proposal.not_open`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description If-Match is stale (`ipam.proposal.revision_mismatch`) */
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
    list_secrets: {
        parameters: {
            query?: {
                /** @description Page size, 1 to 1,000 (default 100). */
                limit?: number;
                /** @description Opaque cursor from the previous page's `next_cursor`. */
                cursor?: string;
                /** @description Read at least this store revision (read-your-writes after a write). */
                at_least?: number;
                /** @description Case-insensitive text search over the name, the user name and the tags. */
                q?: string;
                /** @description Only secrets of this kind. */
                kind?: components["schemas"]["SecretKind"];
                /** @description Only secrets that carry this purpose tag. */
                tag?: string;
                /** @description Only secrets bound to this host. */
                host?: components["schemas"]["HostId"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description A page of operator secrets by name; empty without permission to read secrets */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_OperatorSecretView"];
                };
            };
            /** @description A parameter is unknown or malformed (`sys.invalid_query`) or the cursor is bad (`sys.invalid_cursor`) */
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
    create_secret: {
        parameters: {
            query?: never;
            header?: {
                /** @description Makes a retried request safe; a replay answers the first response */
                "Idempotency-Key"?: string | null;
            };
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["NewOperatorSecret"];
            };
        };
        responses: {
            /** @description The new secret (metadata only), with `ETag` */
            201: {
                headers: {
                    /** @description The revision of the metadata */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperatorSecretView"];
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
            /** @description No valid session or token */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed, or the session is weaker than a password (`auth.forbidden`, `auth.step_up_required` with `required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description An account that may reveal secrets signs in with a PIN alone (`vault.pin_coupling`, parameter `accounts`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The value exceeds 64 KiB (`vault.secret.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A value is invalid (`vault.secret.invalid`, parameter `field`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    get_secret: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Secret identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The secret (metadata only), with `ETag` */
            200: {
                headers: {
                    /** @description The revision of the metadata */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperatorSecretView"];
                };
            };
            /** @description The identifier is not a UUID (`sys.invalid_request`) */
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such operator secret (`vault.secret.not_found`) */
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
    delete_secret: {
        parameters: {
            query?: never;
            header?: {
                /** @description The revision the client read, as in the `ETag`; a stale revision is refused with 409 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Secret identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Deleted */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
            };
            /** @description The identifier or `If-Match` is malformed (`sys.invalid_request`, `sys.invalid_value`) */
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
            /** @description Not allowed (`auth.forbidden`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such operator secret (`vault.secret.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Still referenced (`vault.secret.in_use`, parameters `hosts` and `connectors` with the counts), or `If-Match` is stale (`vault.secret.conflict`) */
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
    update_secret: {
        parameters: {
            query?: never;
            header?: {
                /** @description The revision the client read, as in the `ETag`; a stale revision is refused with 409 */
                "If-Match"?: string | null;
            };
            path: {
                /** @description Secret identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["OperatorSecretPatch"];
            };
        };
        responses: {
            /** @description The secret after the change, with `ETag` */
            200: {
                headers: {
                    /** @description The new revision of the metadata */
                    ETag?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["OperatorSecretView"];
                };
            };
            /** @description The body or `If-Match` is malformed (`sys.invalid_request`, `sys.invalid_value`) */
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
            /** @description Not allowed (`auth.forbidden`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such operator secret (`vault.secret.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `If-Match` is stale or the secret changed meanwhile (`vault.secret.conflict`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The value exceeds 64 KiB (`vault.secret.too_large`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A value is invalid (`vault.secret.invalid`, parameter `field`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    list_secret_references: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Secret identifier */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The hosts and connector instances that reference the secret */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["SecretReferences"];
                };
            };
            /** @description The identifier is not a UUID (`sys.invalid_request`) */
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such operator secret (`vault.secret.not_found`) */
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
    reveal_secret: {
        parameters: {
            query?: never;
            header?: never;
            path: {
                /** @description Secret identifier */
                id: string;
            };
            cookie?: never;
        };
        /** @description The host in view and the reason; the body may be empty */
        requestBody: {
            content: {
                "application/json": components["schemas"]["RevealRequest"];
            };
        };
        responses: {
            /** @description The value, sent once with `Cache-Control: no-store` */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["RevealedSecret"];
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
            /** @description No valid session */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`, also for personal tokens), a step-up is needed (`auth.step_up_required`, parameter `required`: `password`, `fresh` or `passkey`), the policy reveals only secrets bound to the host in view (`vault.reveal.host_required`), or the secret is not bound to the host named (`vault.reveal.not_bound`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No such operator secret (`vault.secret.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The reason is invalid (`vault.secret.invalid`) or the stored value is not text (`vault.secret.not_text`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Too many reveals (`vault.reveal.rate_limited`), with `Retry-After` */
            429: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
        };
    };
    set_default_language: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["DefaultLanguage"];
            };
        };
        responses: {
            /** @description The default language now in force */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["DefaultLanguage"];
                };
            };
            /** @description The body is malformed (`sys.invalid_request`) or the tag is not an active language (`auth.invalid_request`, field `language`) */
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
            /** @description A concurrent change (`auth.conflict`) */
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
                    "application/json": components["schemas"]["SetupResponse"];
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
    get_ca_root: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The root certificate of the internal CA */
            200: {
                headers: {
                    /** @description `public, max-age=3600` */
                    "Cache-Control"?: string;
                    /** @description `attachment; filename="tenko-ca-root.pem"` */
                    "Content-Disposition"?: string;
                    [name: string]: unknown;
                };
                content: {
                    "application/x-pem-file": string;
                };
            };
            /** @description The listener does not use the internal CA (`tls.no_internal_ca`) */
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
    get_kek_status: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The key-encryption key status */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["KekStatusView"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description This server has no key-encryption key service (`sys.not_implemented`) */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`) */
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
    rotate_kek: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The rotation is requested; the status shows it in phase `requested` */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["KekStatusView"];
                };
            };
            /** @description No valid session */
            401: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed (`auth.forbidden`), or the session was not signed in within the last five minutes (`auth.step_up_required`, parameter `required`: `fresh`); personal tokens are refused with `auth.forbidden` */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A rotation is already running (`vault.kek.rotation_in_progress`), or a concurrent request won (`sys.store.precondition_failed`; repeat the request) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description This server has no key-encryption key service (`sys.not_implemented`) */
            501: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The store is unavailable (`sys.store.no_quorum`, `sys.store.timeout`, `sys.store.shutting_down`) */
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
    get_modules: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The running and the configured modules */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ModuleSettings"];
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
            /** @description No module service (`modules.unavailable`) */
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
    put_modules: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["ModulesRequest"];
            };
        };
        responses: {
            /** @description Stored; the running and the configured modules */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["ModuleSettings"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description `modules` in tenko.toml decides (`modules.pinned`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No module service (`modules.unavailable`) */
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
    get_updates: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The update status */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UpdateStatus"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No update service (`update.unavailable`) */
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
    check_updates: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The update status after the check */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UpdateStatus"];
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The check is off: air-gapped or switched off in the settings (`update.check_off`, parameter `reason`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The release source did not answer with a valid manifest (`update.fetch_failed`, `update.manifest.*`) */
            502: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No update service (`update.unavailable`) */
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
    install_update: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody: {
            content: {
                "application/json": components["schemas"]["InstallRequest"];
            };
        };
        responses: {
            /** @description The install job started; follow it on the `jobs` topic */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstallStarted"];
                };
            };
            /** @description The version is not in the manifest or not newer (`update.version_unknown`, `update.not_newer`) */
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
            /** @description Not allowed, or a fresh authentication is needed (`auth.forbidden`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description This installation cannot install from the UI now (`update.install_blocked`, parameter `reason`: an `InstallBlock`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No update service (`update.unavailable`) */
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
    put_update_manifest: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description The release manifest, at most 1 MiB */
        requestBody: {
            content: {
                "application/json": components["schemas"]["ReleaseManifest"];
            };
        };
        responses: {
            /** @description The manifest is stored; the update status */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["UpdateStatus"];
                };
            };
            /** @description The manifest is invalid (`update.manifest.json`, `update.manifest.invalid`, `update.manifest.schema`, `update.manifest.project`, `update.manifest.too_large`) */
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
            /** @description Not allowed (`auth.forbidden`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No update service (`update.unavailable`) */
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
    upload_update: {
        parameters: {
            query: {
                /**
                 * @description The version of the uploaded file; the manifest must list it with a file for this
                 *     platform, whose SHA-256 the upload must match.
                 */
                version: components["schemas"]["ReleaseVersion"];
            };
            header?: never;
            path?: never;
            cookie?: never;
        };
        /** @description The release file for this platform */
        requestBody: {
            content: {
                "application/octet-stream": number[];
            };
        };
        responses: {
            /** @description The file is stored and verified; the install job started */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["InstallStarted"];
                };
            };
            /** @description The file does not match the manifest (`update.checksum_mismatch`, `update.size_mismatch`), or the version is unknown (`update.version_unknown`) */
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
            /** @description Not allowed, or a fresh authentication is needed (`auth.forbidden`, `auth.step_up_required`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description This installation cannot install now (`update.install_blocked`, parameter `reason`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The file is larger than the manifest says (`update.size_mismatch`) */
            413: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No update service (`update.unavailable`) */
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
    get_whats_new: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The notes and whether to show them */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["WhatsNew"];
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
            /** @description No update service (`update.unavailable`) */
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
    mark_whats_new_seen: {
        parameters: {
            query?: never;
            header?: never;
            path?: never;
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description Recorded */
            204: {
                headers: {
                    [name: string]: unknown;
                };
                content?: never;
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
            /** @description No update service (`update.unavailable`) */
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
    get_topology: {
        parameters: {
            query?: {
                /** @description Nodes of this site (identifier). */
                site?: string;
                /** @description Nodes in this VLAN: a VLAN id (1 to 4094) or a VLAN identifier. */
                vlan?: string;
                /** @description Nodes with an address in this prefix (identifier). */
                prefix?: string;
                /** @description Nodes with an address inside this network, such as `192.0.2.0/24`. */
                within?: string;
                /**
                 * @description Nodes of these kinds: `router`, `switch`, `access_point`, `hypervisor`, `vm`,
                 *     `container`, `host`, `device`; repeat the parameter or separate with commas.
                 */
                kind?: string[];
                /** @description Case-insensitive text over the label, MAC and IP addresses, vendor, model and SSIDs. */
                q?: string;
                /** @description The most nodes to return, 1 to 20,000; 5,000 when absent. */
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
            /** @description Nodes, edges and a summary */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyGraph"];
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
            /** @description The principal may not read observations */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The named VLAN or prefix does not exist (`ipam.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM or the topology is not configured (`ipam.unavailable`, `ipam.topology.unavailable`) */
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
    get_topology_node: {
        parameters: {
            query?: {
                /** @description Only this port: what is connected to it. */
                port?: string;
                /** @description Read at least at this store revision. */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description The node identifier, such as `m-00005e005301`. */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The node, its ports with what hangs on each, its neighbours and its intent */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["TopologyNodeView"];
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
            /** @description The principal may not read observations */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description No node has this identifier (`ipam.topology.not_found`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM or the topology is not configured (`ipam.unavailable`, `ipam.topology.unavailable`) */
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
    provision_vlan: {
        parameters: {
            query?: {
                /**
                 * @description Compute the preview without starting anything (API-09); the controller is read and
                 *     diffed, nothing is written.
                 */
                dry_run?: boolean;
                /** @description For a dry run: read at least at this store revision. */
                at_least?: number;
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
                "application/json": components["schemas"]["VlanProvisionRequest"];
            };
        };
        responses: {
            /** @description The preview of a dry run: the IPAM plan, the controller's read-back diff and the steps of the job */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VlanProvisionPreview"];
                };
            };
            /** @description The job of the provision */
            202: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["VlanProvisionSubmitted"];
                };
            };
            /** @description Invalid request (`ipam.vlan.invalid_request`, `ipam.validation`, `sys.invalid_request`, `sys.invalid_query`) */
            400: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description Not allowed, or writes through the connector are off (`connect.writes_disabled`) */
            403: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The VLAN does not exist (`ipam.not_found`) or the connector is not a network controller (`ipam.vlan.controller_unknown`) */
            404: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description A warning needs an acknowledgement (`ipam.plan.unacknowledged`), the VLAN id exists at the site (`ipam.vlan.duplicate`), the network overlaps (`ipam.prefix.overlap`), the connector is disabled (`ipam.vlan.controller_disabled`) or a guardrail refuses (`connect.guardrail.protected_vlan`) */
            409: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The idempotency key was used for another provision (`ipam.idempotency_mismatch`) */
            422: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description The network controller did not answer (`connect.unreachable` and other `connect.*` codes) */
            502: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/problem+json": components["schemas"]["ProblemDetails"];
                };
            };
            /** @description IPAM, the job engine or the network controllers are not configured (`ipam.unavailable`, `ipam.move.no_engine`, `ipam.vlan.controllers_unavailable`) */
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
    list_vlan_prefixes: {
        parameters: {
            query?: {
                /** @description Soft-deleted prefixes: `exclude` (the default) or `include`. */
                deleted?: string;
                /** @description Read at least at this store revision. */
                at_least?: number;
            };
            header?: never;
            path: {
                /** @description The VLAN. */
                id: string;
            };
            cookie?: never;
        };
        requestBody?: never;
        responses: {
            /** @description The prefixes linked to the VLAN, by VRF and network */
            200: {
                headers: {
                    [name: string]: unknown;
                };
                content: {
                    "application/json": components["schemas"]["Page_Prefix"];
                };
            };
            /** @description Invalid parameter (`sys.invalid_query`, `sys.invalid_request`) */
            400: {
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
            /** @description The VLAN does not exist (`ipam.not_found`) */
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
