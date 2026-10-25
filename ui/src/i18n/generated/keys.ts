// Message keys of ui/i18n/en.xlf. Regenerate with `npm run i18n`; do not edit.
export type MessageKey =
  | "access.col.actions"
  | "access.grant.text"
  | "access.grants.add"
  | "access.grants.add_confirm"
  | "access.grants.add_title"
  | "access.grants.col.delegable"
  | "access.grants.col.granted"
  | "access.grants.col.holder"
  | "access.grants.col.role"
  | "access.grants.col.scope"
  | "access.grants.created"
  | "access.grants.delegated"
  | "access.grants.error.scope"
  | "access.grants.error.subject"
  | "access.grants.field.delegable"
  | "access.grants.field.delegable_help"
  | "access.grants.field.role"
  | "access.grants.field.subject"
  | "access.grants.heading"
  | "access.grants.lede"
  | "access.grants.lede_user"
  | "access.grants.none"
  | "access.grants.revoke_body"
  | "access.grants.revoke_cascade"
  | "access.grants.revoke_named"
  | "access.grants.revoke_title"
  | "access.grants.revoked"
  | "access.lede"
  | "access.mfa.optional"
  | "access.mfa.optional_help"
  | "access.mfa.passkey"
  | "access.mfa.passkey_help"
  | "access.mfa.profile_help"
  | "access.mfa.totp_or_stronger"
  | "access.mfa.totp_or_stronger_help"
  | "access.picker.choose"
  | "access.picker.kind"
  | "access.picker.kind_everything"
  | "access.picker.kind_prefix"
  | "access.picker.kind_site"
  | "access.picker.kind_vrf"
  | "access.picker.object_prefix"
  | "access.picker.object_site"
  | "access.picker.object_vrf"
  | "access.picker.prefix_option"
  | "access.picker.subtree_prefix"
  | "access.picker.subtree_site"
  | "access.role.admin"
  | "access.role.admin_description"
  | "access.role.auditor"
  | "access.role.auditor_description"
  | "access.role.operator"
  | "access.role.operator_description"
  | "access.role.operator_grant"
  | "access.role.viewer"
  | "access.role.viewer_description"
  | "access.role.viewer_grant"
  | "access.roles.col.held"
  | "access.roles.col.may"
  | "access.roles.col.mfa"
  | "access.roles.col.role"
  | "access.roles.dialog_title"
  | "access.roles.edit"
  | "access.roles.edit_named"
  | "access.roles.follow_profile"
  | "access.roles.follows_profile"
  | "access.roles.global_only"
  | "access.roles.global_or_grant"
  | "access.roles.heading"
  | "access.roles.lede"
  | "access.roles.saved"
  | "access.roles.stored"
  | "access.roles.weaker"
  | "access.sa.add"
  | "access.sa.add_lede"
  | "access.sa.add_title"
  | "access.sa.created"
  | "access.sa.error.name"
  | "access.sa.field.display_name"
  | "access.sa.field.name"
  | "access.sa.field.name_help"
  | "access.sa.field.roles"
  | "access.sa.field.roles_help"
  | "access.sa.grants_only"
  | "access.sa.heading"
  | "access.sa.lede"
  | "access.sa.no_tokens"
  | "access.sa.none"
  | "access.sa.summary"
  | "access.sa.token_revoked"
  | "access.sa.tokens"
  | "access.sa.tokens_of"
  | "access.scope.everything"
  | "access.scope.object"
  | "access.scope.prefix"
  | "access.scope.prefix_subtree"
  | "access.scope.site"
  | "access.scope.site_subtree"
  | "access.scope.tenant"
  | "access.scope.vrf"
  | "access.subject.option"
  | "access.subject.service"
  | "access.title"
  | "access.token.add_grant"
  | "access.token.col.expires"
  | "access.token.col.last_used"
  | "access.token.col.name"
  | "access.token.col.reach"
  | "access.token.create"
  | "access.token.create_title"
  | "access.token.created_body"
  | "access.token.created_title"
  | "access.token.days"
  | "access.token.error.empty"
  | "access.token.error.name"
  | "access.token.error.scope"
  | "access.token.expired"
  | "access.token.grants"
  | "access.token.grants_help"
  | "access.token.kind"
  | "access.token.kind_personal"
  | "access.token.kind_personal_help"
  | "access.token.kind_scoped"
  | "access.token.kind_scoped_help"
  | "access.token.lifetime"
  | "access.token.max_days"
  | "access.token.max_none"
  | "access.token.name"
  | "access.token.name_help"
  | "access.token.no_expiry"
  | "access.token.personal"
  | "access.token.remove_grant"
  | "access.token.revoke_body"
  | "access.token.revoke_named"
  | "access.token.revoke_title"
  | "access.token.scopes"
  | "access.token.stored"
  | "access.token_scope.audit_read"
  | "access.token_scope.audit_read_help"
  | "access.token_scope.metrics"
  | "access.token_scope.metrics_help"
  | "access.user.kind"
  | "access.user.service"
  | "account.codes.lede"
  | "account.codes.title"
  | "account.copy_failed"
  | "account.methods.flag_mfa"
  | "account.methods.flag_password"
  | "account.methods.reauthenticate"
  | "account.methods.requires"
  | "account.methods.signed_in_with"
  | "account.methods.summary_label"
  | "account.nav.label"
  | "account.nav.methods"
  | "account.nav.sessions"
  | "account.nav.tokens"
  | "account.passkey.add"
  | "account.passkey.add_key"
  | "account.passkey.added"
  | "account.passkey.added_key"
  | "account.passkey.created"
  | "account.passkey.kind.device"
  | "account.passkey.kind.hardware"
  | "account.passkey.kind.synced"
  | "account.passkey.label"
  | "account.passkey.label_help"
  | "account.passkey.last_used"
  | "account.passkey.lede"
  | "account.passkey.never_used"
  | "account.passkey.none"
  | "account.passkey.remove_body"
  | "account.passkey.remove_named"
  | "account.passkey.remove_refused"
  | "account.passkey.remove_title"
  | "account.passkey.removed"
  | "account.passkey.title"
  | "account.passkey.waiting_key"
  | "account.passkey.waiting_passkey"
  | "account.password.changed"
  | "account.password.changed_others"
  | "account.password.check.breach_clean"
  | "account.password.check.breach_off"
  | "account.password.check.breach_unavailable"
  | "account.password.check.context"
  | "account.password.check.trivial"
  | "account.password.checks"
  | "account.password.confirm"
  | "account.password.current"
  | "account.password.current_help"
  | "account.password.lede"
  | "account.password.mismatch"
  | "account.password.new"
  | "account.password.rule.length"
  | "account.password.rule.passphrase"
  | "account.password.rule.pattern"
  | "account.password.rule.pin"
  | "account.password.rule.profile"
  | "account.password.show"
  | "account.password.state.bad"
  | "account.password.state.idle"
  | "account.password.state.off"
  | "account.password.state.ok"
  | "account.password.state.pending"
  | "account.password.submit"
  | "account.password.title"
  | "account.recovery.confirm_body"
  | "account.recovery.confirm_title"
  | "account.recovery.generate"
  | "account.recovery.lede"
  | "account.recovery.left"
  | "account.recovery.name"
  | "account.recovery.needs_factor"
  | "account.recovery.title"
  | "account.sessions.client"
  | "account.sessions.client_unknown"
  | "account.sessions.col.actions"
  | "account.sessions.col.address"
  | "account.sessions.col.client"
  | "account.sessions.col.expires"
  | "account.sessions.col.last_activity"
  | "account.sessions.col.signed_in"
  | "account.sessions.col.strength"
  | "account.sessions.confirm_body"
  | "account.sessions.confirm_button"
  | "account.sessions.confirm_title"
  | "account.sessions.lede"
  | "account.sessions.none_other"
  | "account.sessions.revoke_named"
  | "account.sessions.revoked"
  | "account.sessions.revoked_many"
  | "account.sessions.sign_out"
  | "account.sessions.sign_out_others"
  | "account.sessions.strength.hardware_key"
  | "account.sessions.strength.passkey"
  | "account.sessions.strength.password"
  | "account.sessions.strength.password_totp"
  | "account.sessions.strength.pin"
  | "account.sessions.this"
  | "account.sessions.title"
  | "account.title"
  | "account.tokens.col.created"
  | "account.tokens.col.expires"
  | "account.tokens.col.last_used"
  | "account.tokens.col.name"
  | "account.tokens.col.prefix"
  | "account.tokens.create"
  | "account.tokens.create_title"
  | "account.tokens.created_body"
  | "account.tokens.created_title"
  | "account.tokens.days"
  | "account.tokens.expired"
  | "account.tokens.lede"
  | "account.tokens.lifetime"
  | "account.tokens.max_days"
  | "account.tokens.max_none"
  | "account.tokens.name"
  | "account.tokens.name_help"
  | "account.tokens.no_expiry"
  | "account.tokens.none"
  | "account.tokens.revoke_body"
  | "account.tokens.revoke_named"
  | "account.tokens.revoke_title"
  | "account.tokens.revoked"
  | "account.tokens.stored"
  | "account.tokens.title"
  | "account.totp.code"
  | "account.totp.enabled"
  | "account.totp.expired"
  | "account.totp.key"
  | "account.totp.lede"
  | "account.totp.name"
  | "account.totp.open_link"
  | "account.totp.params"
  | "account.totp.qr_label"
  | "account.totp.remove_body"
  | "account.totp.remove_refused"
  | "account.totp.remove_title"
  | "account.totp.removed"
  | "account.totp.scan_or_key"
  | "account.totp.setup"
  | "account.totp.setup_title"
  | "account.totp.status_off"
  | "account.totp.status_on"
  | "account.totp.title"
  | "account.totp.verify"
  | "audit.chain.advice"
  | "audit.chain.broken"
  | "audit.chain.checked"
  | "audit.chain.checking"
  | "audit.chain.detail"
  | "audit.chain.empty"
  | "audit.chain.failed"
  | "audit.chain.head"
  | "audit.chain.intact"
  | "audit.chain.label"
  | "audit.chain.open_record"
  | "audit.chain.reason.other"
  | "audit.chain.reason.sys.audit.bad_hash"
  | "audit.chain.reason.sys.audit.broken_link"
  | "audit.chain.reason.sys.audit.gap"
  | "audit.chain.verified_before"
  | "audit.chain.verify"
  | "audit.chain.verifying"
  | "audit.changes.field"
  | "audit.changes.new"
  | "audit.changes.no_value"
  | "audit.changes.none"
  | "audit.changes.not_recorded"
  | "audit.changes.object"
  | "audit.changes.old"
  | "audit.changes.table"
  | "audit.changes.title"
  | "audit.col.action"
  | "audit.col.objects"
  | "audit.col.outcome"
  | "audit.col.principal"
  | "audit.col.seq"
  | "audit.col.source"
  | "audit.col.time"
  | "audit.context.key"
  | "audit.context.none"
  | "audit.context.title"
  | "audit.context.value"
  | "audit.empty.filtered"
  | "audit.empty.filtered_hint"
  | "audit.empty.none"
  | "audit.filter.action"
  | "audit.filter.action_invalid"
  | "audit.filter.action_placeholder"
  | "audit.filter.clear"
  | "audit.filter.from"
  | "audit.filter.object"
  | "audit.filter.object_invalid"
  | "audit.filter.object_placeholder"
  | "audit.filter.order"
  | "audit.filter.order_asc"
  | "audit.filter.order_desc"
  | "audit.filter.outcome"
  | "audit.filter.outcome_all"
  | "audit.filter.principal"
  | "audit.filter.principal_invalid"
  | "audit.filter.principal_placeholder"
  | "audit.filter.range_invalid"
  | "audit.filter.time_invalid"
  | "audit.filter.to"
  | "audit.filter.value_invalid"
  | "audit.filters.label"
  | "audit.grid.label"
  | "audit.hashes.first"
  | "audit.hashes.hash"
  | "audit.hashes.note"
  | "audit.hashes.prev"
  | "audit.hashes.title"
  | "audit.kind.address"
  | "audit.kind.api_token"
  | "audit.kind.connector"
  | "audit.kind.custom_field"
  | "audit.kind.dhcp_class"
  | "audit.kind.dhcp_filter"
  | "audit.kind.dhcp_option_def"
  | "audit.kind.dhcp_policy"
  | "audit.kind.dhcp_scope"
  | "audit.kind.dns_acl"
  | "audit.kind.dns_forwarder"
  | "audit.kind.dns_key"
  | "audit.kind.dns_list"
  | "audit.kind.dns_view"
  | "audit.kind.host"
  | "audit.kind.import"
  | "audit.kind.interface"
  | "audit.kind.job"
  | "audit.kind.node"
  | "audit.kind.observation"
  | "audit.kind.prefix"
  | "audit.kind.proposal"
  | "audit.kind.range"
  | "audit.kind.secret"
  | "audit.kind.session"
  | "audit.kind.settings"
  | "audit.kind.site"
  | "audit.kind.system"
  | "audit.kind.tenant"
  | "audit.kind.user"
  | "audit.kind.vlan"
  | "audit.kind.vrf"
  | "audit.kind.zone"
  | "audit.live.new"
  | "audit.live.new_many"
  | "audit.live.show"
  | "audit.live.show_latest"
  | "audit.outcome.denied"
  | "audit.outcome.failed"
  | "audit.outcome.success"
  | "audit.principal.kind.node"
  | "audit.principal.kind.system"
  | "audit.principal.kind.token"
  | "audit.principal.kind.user"
  | "audit.record.back"
  | "audit.record.component"
  | "audit.record.crumbs"
  | "audit.record.loading"
  | "audit.record.next"
  | "audit.record.not_found"
  | "audit.record.not_set"
  | "audit.record.object_log"
  | "audit.record.objects"
  | "audit.record.objects_none"
  | "audit.record.on_behalf_of"
  | "audit.record.open_newest"
  | "audit.record.overview"
  | "audit.record.owner"
  | "audit.record.previous"
  | "audit.record.principal_id"
  | "audit.record.principal_kind"
  | "audit.record.principal_log"
  | "audit.record.request"
  | "audit.record.revision"
  | "audit.record.session"
  | "audit.record.strength"
  | "audit.record.title"
  | "audit.row"
  | "audit.strength.hardware_key"
  | "audit.strength.passkey"
  | "audit.strength.password"
  | "audit.strength.password_totp"
  | "audit.strength.pin"
  | "audit.sub"
  | "audit.title"
  | "audit_export.add"
  | "audit_export.add_title"
  | "audit_export.alert_after_saved"
  | "audit_export.checkpoint"
  | "audit_export.col.actions"
  | "audit_export.col.delivered"
  | "audit_export.col.format"
  | "audit_export.col.lag"
  | "audit_export.col.name"
  | "audit_export.col.state"
  | "audit_export.col.target"
  | "audit_export.delivered"
  | "audit_export.edit_title"
  | "audit_export.error.alert_after"
  | "audit_export.error.client_key"
  | "audit_export.error.file"
  | "audit_export.error.host"
  | "audit_export.error.keep"
  | "audit_export.error.max_mib"
  | "audit_export.error.name"
  | "audit_export.error.port"
  | "audit_export.failing.title"
  | "audit_export.failing_since"
  | "audit_export.field.alert_after"
  | "audit_export.field.alert_after_help"
  | "audit_export.field.ca_pem"
  | "audit_export.field.ca_pem_help"
  | "audit_export.field.client_cert_pem"
  | "audit_export.field.client_cert_pem_help"
  | "audit_export.field.client_key"
  | "audit_export.field.client_key_help"
  | "audit_export.field.facility"
  | "audit_export.field.file"
  | "audit_export.field.file_help"
  | "audit_export.field.format"
  | "audit_export.field.host"
  | "audit_export.field.keep"
  | "audit_export.field.max_mib"
  | "audit_export.field.name"
  | "audit_export.field.port"
  | "audit_export.field.server_name"
  | "audit_export.field.server_name_help"
  | "audit_export.field.transport"
  | "audit_export.format.cef"
  | "audit_export.format.json"
  | "audit_export.format.rfc5424"
  | "audit_export.lede"
  | "audit_export.none"
  | "audit_export.pause"
  | "audit_export.paused"
  | "audit_export.policy.heading"
  | "audit_export.policy.met"
  | "audit_export.policy.unmet"
  | "audit_export.policy.value"
  | "audit_export.remove_body"
  | "audit_export.remove_last"
  | "audit_export.remove_named"
  | "audit_export.remove_title"
  | "audit_export.removed"
  | "audit_export.required.title"
  | "audit_export.resume"
  | "audit_export.resumed"
  | "audit_export.saved"
  | "audit_export.sinks.heading"
  | "audit_export.state.alarm"
  | "audit_export.state.behind"
  | "audit_export.state.disabled"
  | "audit_export.state.failing"
  | "audit_export.state.ok"
  | "audit_export.state.pending"
  | "audit_export.test"
  | "audit_export.test_failed"
  | "audit_export.test_ok"
  | "audit_export.title"
  | "audit_export.transport.file"
  | "audit_export.transport.file_help"
  | "audit_export.transport.tcp"
  | "audit_export.transport.tcp_help"
  | "audit_export.transport.tls"
  | "audit_export.transport.tls_help"
  | "audit_export.transport.udp"
  | "audit_export.transport.udp_help"
  | "audit_export.udp_warning"
  | "audit_export.verify.body"
  | "audit_export.verify.heading"
  | "audit_export.warning.failing"
  | "audit_export.warning.required"
  | "auth.signin.back_to_sign_in"
  | "auth.signin.break_glass_button"
  | "auth.signin.break_glass_lead"
  | "auth.signin.break_glass_link"
  | "auth.signin.break_glass_title"
  | "auth.signin.break_glass_warning"
  | "auth.signin.ceremony.cancelled"
  | "auth.signin.ceremony.exists"
  | "auth.signin.ceremony.failed"
  | "auth.signin.ceremony.insecure"
  | "auth.signin.ceremony.unsupported"
  | "auth.signin.insecure"
  | "auth.signin.lead"
  | "auth.signin.or"
  | "auth.signin.passkey"
  | "auth.signin.passkey_insecure"
  | "auth.signin.passkey_unsupported"
  | "auth.signin.password"
  | "auth.signin.product"
  | "auth.signin.recovery_code"
  | "auth.signin.retry_in"
  | "auth.signin.second_lead_recovery"
  | "auth.signin.second_lead_totp"
  | "auth.signin.second_title"
  | "auth.signin.secure"
  | "auth.signin.start_over"
  | "auth.signin.submit"
  | "auth.signin.throttle_explain"
  | "auth.signin.title"
  | "auth.signin.totp_code"
  | "auth.signin.use_passkey"
  | "auth.signin.use_password"
  | "auth.signin.use_recovery"
  | "auth.signin.use_totp"
  | "auth.signin.user_name"
  | "auth.signin.verify"
  | "auth.signin.waiting"
  | "auth.signin.waiting_key"
  | "auth.strength.hardware_key"
  | "auth.strength.passkey"
  | "auth.strength.password"
  | "auth.strength.password_totp"
  | "auth.strength.pin"
  | "backup.create.again"
  | "backup.create.body"
  | "backup.create.done"
  | "backup.create.error.mismatch"
  | "backup.create.error.short"
  | "backup.create.passphrase"
  | "backup.create.passphrase_help"
  | "backup.create.passphrase_only"
  | "backup.create.passphrase_optional"
  | "backup.create.title"
  | "backup.create.with_recipient"
  | "backup.job_link"
  | "backup.lede"
  | "backup.now"
  | "backup.restore.body"
  | "backup.restore.note"
  | "backup.restore.open"
  | "backup.restore.open_named"
  | "backup.restore.slots"
  | "backup.restore.title"
  | "backup.restored.body"
  | "backup.restored.nodes"
  | "backup.restored.title"
  | "backup.run.failed"
  | "backup.run.manual"
  | "backup.run.scheduled"
  | "backup.run.succeeded"
  | "backup.running"
  | "backup.runs.col.actions"
  | "backup.runs.col.file"
  | "backup.runs.col.finished"
  | "backup.runs.col.node"
  | "backup.runs.col.outcome"
  | "backup.runs.col.reason"
  | "backup.runs.col.size"
  | "backup.runs.heading"
  | "backup.runs.none"
  | "backup.schedule.enabled"
  | "backup.schedule.enabled_help"
  | "backup.schedule.error.interval"
  | "backup.schedule.error.keep"
  | "backup.schedule.error.recipient"
  | "backup.schedule.error.target_dir"
  | "backup.schedule.every"
  | "backup.schedule.heading"
  | "backup.schedule.include_config"
  | "backup.schedule.interval"
  | "backup.schedule.interval_help"
  | "backup.schedule.keep"
  | "backup.schedule.keep_help"
  | "backup.schedule.needs_recipient"
  | "backup.schedule.off"
  | "backup.schedule.recipient"
  | "backup.schedule.recipient_help"
  | "backup.schedule.saved"
  | "backup.schedule.target_dir"
  | "backup.schedule.target_dir_help"
  | "backup.slot.passphrase"
  | "backup.slot.recipient"
  | "backup.state.age_label"
  | "backup.state.heading"
  | "backup.state.last_failed"
  | "backup.state.last_good"
  | "backup.state.never"
  | "backup.state.next"
  | "backup.state.not_scheduled"
  | "backup.state.recipient"
  | "backup.state.recipient_no"
  | "backup.state.recipient_yes"
  | "backup.state.running"
  | "backup.state.running_no"
  | "backup.state.running_yes"
  | "backup.state.target"
  | "backup.step_up.body"
  | "backup.step_up.sign_in"
  | "backup.step_up.title"
  | "backup.title"
  | "backup.warning.failed"
  | "backup.warning.restored"
  | "backup.warning.stale"
  | "certificates.accept.label"
  | "certificates.accept.off"
  | "certificates.accept.on"
  | "certificates.accept.where"
  | "certificates.ca.heading"
  | "certificates.chain"
  | "certificates.chain_len"
  | "certificates.days"
  | "certificates.days_left"
  | "certificates.error"
  | "certificates.expiry.expired"
  | "certificates.expiry.not_yet_valid"
  | "certificates.expiry.soon"
  | "certificates.fingerprint"
  | "certificates.hsts"
  | "certificates.imported.cert_path"
  | "certificates.imported.heading"
  | "certificates.imported.interval"
  | "certificates.imported.interval.value"
  | "certificates.imported.key_path"
  | "certificates.issuer"
  | "certificates.lede"
  | "certificates.loaded_at"
  | "certificates.min_version"
  | "certificates.min_version.value"
  | "certificates.mode.heading"
  | "certificates.mode.imported"
  | "certificates.mode.imported.help"
  | "certificates.mode.internal_ca"
  | "certificates.mode.internal_ca.help"
  | "certificates.mode.label"
  | "certificates.mode.plain"
  | "certificates.mode.plain.help"
  | "certificates.mode.reverse_proxy"
  | "certificates.mode.reverse_proxy.help"
  | "certificates.names"
  | "certificates.names.none"
  | "certificates.none"
  | "certificates.off"
  | "certificates.on"
  | "certificates.pending.detected"
  | "certificates.pending.heading"
  | "certificates.pending.notice"
  | "certificates.plain.notice"
  | "certificates.proxy.heading"
  | "certificates.proxy.host"
  | "certificates.proxy.note"
  | "certificates.proxy.protocol"
  | "certificates.proxy.trusted"
  | "certificates.read_at"
  | "certificates.refresh"
  | "certificates.rule.hardened"
  | "certificates.rule.home"
  | "certificates.rule.lab"
  | "certificates.rule.standard"
  | "certificates.rule.unknown"
  | "certificates.served.heading"
  | "certificates.subject"
  | "certificates.title"
  | "certificates.unknown"
  | "certificates.valid_from"
  | "certificates.valid_until"
  | "cluster.action.add"
  | "cluster.action.check_digests"
  | "cluster.action.promote"
  | "cluster.action.promote_named"
  | "cluster.action.queue"
  | "cluster.action.remove"
  | "cluster.action.remove_named"
  | "cluster.action.step_down"
  | "cluster.add.intro"
  | "cluster.add.next"
  | "cluster.add.title"
  | "cluster.blocker.changing"
  | "cluster.blocker.even_voters"
  | "cluster.blocker.last_voter"
  | "cluster.blocker.no_successor"
  | "cluster.blocker.not_caught_up"
  | "cluster.blocker.not_learner"
  | "cluster.blocker.not_voter"
  | "cluster.blocker.single"
  | "cluster.caveat.even_after"
  | "cluster.caveat.forced"
  | "cluster.caveat.no_tolerance"
  | "cluster.caveat.reconnect"
  | "cluster.caveat.removes_leader"
  | "cluster.caveat.removes_self"
  | "cluster.caveat.replaces"
  | "cluster.caveat.revokes"
  | "cluster.changing"
  | "cluster.col.actions"
  | "cluster.col.address"
  | "cluster.col.compat"
  | "cluster.col.contact"
  | "cluster.col.format"
  | "cluster.col.health"
  | "cluster.col.joined"
  | "cluster.col.lag"
  | "cluster.col.name"
  | "cluster.col.role"
  | "cluster.col.version"
  | "cluster.compat.format_one"
  | "cluster.compat.format_range"
  | "cluster.compat.tooltip"
  | "cluster.digests.agree"
  | "cluster.digests.col.digest"
  | "cluster.digests.col.entries"
  | "cluster.digests.col.member"
  | "cluster.digests.col.revision"
  | "cluster.digests.col.state"
  | "cluster.digests.col.tables"
  | "cluster.digests.differ"
  | "cluster.digests.intro"
  | "cluster.digests.state.agrees"
  | "cluster.digests.state.differs"
  | "cluster.digests.state.missing"
  | "cluster.digests.title"
  | "cluster.done.open_job"
  | "cluster.done.promoted"
  | "cluster.done.removed"
  | "cluster.done.stepped_down"
  | "cluster.format.advice"
  | "cluster.format.binary"
  | "cluster.format.blocked"
  | "cluster.format.current"
  | "cluster.format.knows"
  | "cluster.format.not_reported"
  | "cluster.format.stored"
  | "cluster.format.target"
  | "cluster.format.title"
  | "cluster.format.waiting"
  | "cluster.health.catching_up"
  | "cluster.health.caught_up"
  | "cluster.health.leader"
  | "cluster.health.out_of_contact"
  | "cluster.health.unknown"
  | "cluster.job.edit"
  | "cluster.job.write_preview"
  | "cluster.member.leader_marker"
  | "cluster.member.unnamed"
  | "cluster.members.count"
  | "cluster.members.title"
  | "cluster.no_quorum.body"
  | "cluster.no_quorum.body_since"
  | "cluster.no_quorum.not_queueable"
  | "cluster.no_quorum.queue"
  | "cluster.no_quorum.queueable"
  | "cluster.no_quorum.queued"
  | "cluster.no_quorum.show_queue"
  | "cluster.no_quorum.title"
  | "cluster.partition.conflicts"
  | "cluster.partition.electing.body"
  | "cluster.partition.electing.title"
  | "cluster.partition.isolated.body"
  | "cluster.partition.isolated.title"
  | "cluster.partition.queue_link"
  | "cluster.partition.review"
  | "cluster.partition.stale"
  | "cluster.partition.stale_title"
  | "cluster.preview.blockers"
  | "cluster.preview.caveats"
  | "cluster.preview.change"
  | "cluster.preview.forceable"
  | "cluster.preview.same"
  | "cluster.preview.tolerated"
  | "cluster.preview.voters"
  | "cluster.promote.confirm"
  | "cluster.promote.force"
  | "cluster.promote.force_help"
  | "cluster.promote.intro"
  | "cluster.promote.replace"
  | "cluster.promote.replace_help"
  | "cluster.promote.replace_none"
  | "cluster.promote.title"
  | "cluster.queue.action"
  | "cluster.queue.cancel_body"
  | "cluster.queue.cancel_confirm"
  | "cluster.queue.cancel_failed"
  | "cluster.queue.cancel_named"
  | "cluster.queue.cancel_title"
  | "cluster.queue.cancelled"
  | "cluster.queue.change_state.applied"
  | "cluster.queue.change_state.conflict"
  | "cluster.queue.change_state.expired"
  | "cluster.queue.changes.empty"
  | "cluster.queue.changes.intro"
  | "cluster.queue.changes.title"
  | "cluster.queue.col.actions"
  | "cluster.queue.col.change"
  | "cluster.queue.col.expires"
  | "cluster.queue.col.queued"
  | "cluster.queue.col.request"
  | "cluster.queue.col.result"
  | "cluster.queue.col.state"
  | "cluster.queue.conflict.expired"
  | "cluster.queue.conflict.other"
  | "cluster.queue.conflict.stale"
  | "cluster.queue.count"
  | "cluster.queue.discard"
  | "cluster.queue.discard_body"
  | "cluster.queue.discard_failed"
  | "cluster.queue.discard_named"
  | "cluster.queue.discard_title"
  | "cluster.queue.discarded"
  | "cluster.queue.dismiss"
  | "cluster.queue.dismiss_named"
  | "cluster.queue.dismissed"
  | "cluster.queue.keep"
  | "cluster.queue.kind"
  | "cluster.queue.local.empty"
  | "cluster.queue.local.intro"
  | "cluster.queue.local.title"
  | "cluster.queue.reapplied"
  | "cluster.queue.reapply"
  | "cluster.queue.reapply_confirm"
  | "cluster.queue.reapply_intro"
  | "cluster.queue.reapply_named"
  | "cluster.queue.reapply_title"
  | "cluster.queue.state.applying"
  | "cluster.queue.state.expired"
  | "cluster.queue.state.queued"
  | "cluster.queue.title"
  | "cluster.queue.unavailable"
  | "cluster.queue.what_unknown"
  | "cluster.quorum.electing"
  | "cluster.quorum.healthy"
  | "cluster.quorum.isolated"
  | "cluster.quorum.single"
  | "cluster.remove.confirm"
  | "cluster.remove.intro"
  | "cluster.remove.title"
  | "cluster.role.learner"
  | "cluster.role.voter"
  | "cluster.step_down.confirm"
  | "cluster.step_down.intro"
  | "cluster.step_down.successor"
  | "cluster.step_down.title"
  | "cluster.summary.label"
  | "cluster.summary.leader"
  | "cluster.summary.no_leader"
  | "cluster.summary.node"
  | "cluster.summary.quorum"
  | "cluster.summary.since"
  | "cluster.summary.term"
  | "cluster.summary.voters"
  | "cluster.summary.voters_value"
  | "cluster.title"
  | "cluster.tolerance"
  | "cluster.warning.migration_blocked"
  | "common.action.add"
  | "common.action.back"
  | "common.action.cancel"
  | "common.action.close"
  | "common.action.continue"
  | "common.action.copied"
  | "common.action.copy"
  | "common.action.create"
  | "common.action.delete"
  | "common.action.dismiss"
  | "common.action.download"
  | "common.action.edit"
  | "common.action.hide"
  | "common.action.print"
  | "common.action.remove"
  | "common.action.retry"
  | "common.action.revoke"
  | "common.action.save"
  | "common.action.show"
  | "common.ca_root.download"
  | "common.ca_root.help"
  | "common.count.items"
  | "common.greeting"
  | "common.loading"
  | "common.never"
  | "common.no"
  | "common.none"
  | "common.optional"
  | "common.recommended"
  | "common.required"
  | "common.unknown"
  | "common.yes"
  | "connect.job.edit"
  | "connect.job.poll_preview"
  | "connect.job.run"
  | "connect.job.write_preview"
  | "connectors.action.check"
  | "connectors.action.create"
  | "connectors.action.delete"
  | "connectors.action.disable"
  | "connectors.action.edit"
  | "connectors.action.enable"
  | "connectors.action.open"
  | "connectors.action.run"
  | "connectors.action.toggle"
  | "connectors.capability.actuator"
  | "connectors.capability.inventory"
  | "connectors.capability.migration"
  | "connectors.capability.network_controller"
  | "connectors.capability.webhook"
  | "connectors.col.capabilities"
  | "connectors.col.health"
  | "connectors.col.last_run"
  | "connectors.col.name"
  | "connectors.col.plugin"
  | "connectors.col.poll"
  | "connectors.col.process"
  | "connectors.col.writes"
  | "connectors.delete.body"
  | "connectors.delete.confirm"
  | "connectors.delete.title"
  | "connectors.detail.all_jobs"
  | "connectors.detail.back"
  | "connectors.detail.changed"
  | "connectors.detail.check_failed"
  | "connectors.detail.checked"
  | "connectors.detail.config"
  | "connectors.detail.created"
  | "connectors.detail.detail"
  | "connectors.detail.disabled"
  | "connectors.detail.error"
  | "connectors.detail.failed_runs"
  | "connectors.detail.failures"
  | "connectors.detail.health"
  | "connectors.detail.job"
  | "connectors.detail.last_error"
  | "connectors.detail.last_run"
  | "connectors.detail.last_success"
  | "connectors.detail.latency"
  | "connectors.detail.ms"
  | "connectors.detail.no"
  | "connectors.detail.no_check"
  | "connectors.detail.no_runs"
  | "connectors.detail.observations"
  | "connectors.detail.observations_link"
  | "connectors.detail.outcome"
  | "connectors.detail.pages"
  | "connectors.detail.process"
  | "connectors.detail.remote"
  | "connectors.detail.remote_version"
  | "connectors.detail.restarts"
  | "connectors.detail.runs"
  | "connectors.detail.started"
  | "connectors.detail.state"
  | "connectors.detail.trigger"
  | "connectors.detail.updated"
  | "connectors.detail.version"
  | "connectors.detail.warnings"
  | "connectors.detail.yes"
  | "connectors.empty.body"
  | "connectors.empty.title"
  | "connectors.form.choose"
  | "connectors.form.create"
  | "connectors.form.default"
  | "connectors.form.default_secs"
  | "connectors.form.enabled"
  | "connectors.form.example"
  | "connectors.form.guardrails"
  | "connectors.form.interval_range"
  | "connectors.form.item_add"
  | "connectors.form.item_add_to"
  | "connectors.form.item_label"
  | "connectors.form.item_remove"
  | "connectors.form.items_empty"
  | "connectors.form.name"
  | "connectors.form.name_help"
  | "connectors.form.name_long"
  | "connectors.form.name_required"
  | "connectors.form.no_plugins"
  | "connectors.form.no_settings"
  | "connectors.form.on"
  | "connectors.form.plugin"
  | "connectors.form.plugin_fixed"
  | "connectors.form.poll"
  | "connectors.form.save"
  | "connectors.form.secret_missing"
  | "connectors.form.secret_none"
  | "connectors.form.secret_other"
  | "connectors.form.secret_purpose"
  | "connectors.form.secret_tagged"
  | "connectors.form.secret_unlisted"
  | "connectors.form.secrets"
  | "connectors.form.secrets_admin"
  | "connectors.form.secrets_help"
  | "connectors.form.settings"
  | "connectors.form.stale"
  | "connectors.form.targets"
  | "connectors.form.timeout"
  | "connectors.form.title_create"
  | "connectors.form.title_edit"
  | "connectors.form.unsupported"
  | "connectors.form.writes"
  | "connectors.form.writes_help"
  | "connectors.form.writes_read_only"
  | "connectors.form.writes_warning"
  | "connectors.health.degraded"
  | "connectors.health.failing"
  | "connectors.health.healthy"
  | "connectors.health.off"
  | "connectors.instances"
  | "connectors.plugins.capabilities"
  | "connectors.plugins.homepage"
  | "connectors.plugins.license"
  | "connectors.plugins.none"
  | "connectors.plugins.platforms"
  | "connectors.plugins.reload"
  | "connectors.plugins.secrets"
  | "connectors.plugins.source.bundled"
  | "connectors.plugins.source.installed"
  | "connectors.plugins.title"
  | "connectors.plugins.unusable"
  | "connectors.problem.enum"
  | "connectors.problem.format"
  | "connectors.problem.items"
  | "connectors.problem.items_max"
  | "connectors.problem.items_min"
  | "connectors.problem.length"
  | "connectors.problem.length_max"
  | "connectors.problem.length_min"
  | "connectors.problem.pattern"
  | "connectors.problem.range"
  | "connectors.problem.range_max"
  | "connectors.problem.range_min"
  | "connectors.problem.required"
  | "connectors.problem.type"
  | "connectors.problem.unique"
  | "connectors.problem.unknown"
  | "connectors.process.backoff"
  | "connectors.process.circuit_open"
  | "connectors.process.failed"
  | "connectors.process.running"
  | "connectors.process.starting"
  | "connectors.process.stopped"
  | "connectors.process.until"
  | "connectors.remote.degraded"
  | "connectors.remote.healthy"
  | "connectors.remote.unreachable"
  | "connectors.run.failed"
  | "connectors.run.never"
  | "connectors.run.succeeded"
  | "connectors.seconds"
  | "connectors.seconds_default"
  | "connectors.sub"
  | "connectors.toast.change_failed"
  | "connectors.toast.check_failed"
  | "connectors.toast.checked"
  | "connectors.toast.delete_failed"
  | "connectors.toast.deleted"
  | "connectors.toast.disabled"
  | "connectors.toast.enabled"
  | "connectors.toast.open_job"
  | "connectors.toast.run"
  | "connectors.toast.run_failed"
  | "connectors.trigger.manual"
  | "connectors.trigger.schedule"
  | "connectors.writes.off"
  | "connectors.writes.on"
  | "dashboard.action.claim"
  | "dashboard.action.claim_where"
  | "dashboard.action.import"
  | "dashboard.action.prefix"
  | "dashboard.alarms.none"
  | "dashboard.alarms.title"
  | "dashboard.audit.all"
  | "dashboard.audit.none"
  | "dashboard.audit.title"
  | "dashboard.modules.name.dhcp"
  | "dashboard.modules.name.discovery"
  | "dashboard.modules.name.dns"
  | "dashboard.modules.name.ipam"
  | "dashboard.modules.none"
  | "dashboard.modules.restart_body"
  | "dashboard.modules.restart_title"
  | "dashboard.palette_hint"
  | "dashboard.tile.addresses"
  | "dashboard.tile.addresses_of"
  | "dashboard.tile.alarms"
  | "dashboard.tile.alarms_hint"
  | "dashboard.tile.connectors"
  | "dashboard.tile.connectors_hint"
  | "dashboard.tile.connectors_link"
  | "dashboard.tile.nodes"
  | "dashboard.tile.nodes_hint"
  | "dashboard.tile.nodes_link"
  | "dashboard.tile.nodes_none"
  | "dashboard.tile.proposals"
  | "dashboard.tile.proposals_hint"
  | "dashboard.tile.proposals_link"
  | "dashboard.tile.waiting_for_you"
  | "dashboard.update.action"
  | "dashboard.update.body"
  | "dashboard.update.open"
  | "dashboard.update.security"
  | "dashboard.update.title"
  | "dashboard.use.empty"
  | "dashboard.use.more"
  | "dashboard.use.networks"
  | "dashboard.use.of"
  | "dashboard.use.title"
  | "dashboard.use.vrf"
  | "dashboard.waiting.all"
  | "dashboard.waiting.none"
  | "dashboard.waiting.step"
  | "dashboard.waiting.title"
  | "dhcp.action.ddns_off"
  | "dhcp.action.ddns_on"
  | "dhcp.action.ddns_on_zone"
  | "dhcp.action.lease"
  | "dhcp.action.none"
  | "dhcp.action.options"
  | "dhcp.action.range"
  | "dhcp.arch.empty"
  | "dhcp.arch.label"
  | "dhcp.arch.name.0"
  | "dhcp.arch.name.10"
  | "dhcp.arch.name.11"
  | "dhcp.arch.name.15"
  | "dhcp.arch.name.16"
  | "dhcp.arch.name.19"
  | "dhcp.arch.name.6"
  | "dhcp.arch.name.7"
  | "dhcp.arch.name.9"
  | "dhcp.arch.none"
  | "dhcp.arch.option"
  | "dhcp.arch.other"
  | "dhcp.arch.value_label"
  | "dhcp.boot.add_button"
  | "dhcp.boot.add_done"
  | "dhcp.boot.add_file"
  | "dhcp.boot.add_file_help"
  | "dhcp.boot.add_kind"
  | "dhcp.boot.add_matches"
  | "dhcp.boot.add_order_first"
  | "dhcp.boot.add_order_last"
  | "dhcp.boot.add_order_tie"
  | "dhcp.boot.add_partial_class"
  | "dhcp.boot.add_partial_policy"
  | "dhcp.boot.add_submit"
  | "dhcp.boot.add_title"
  | "dhcp.boot.check.file_empty"
  | "dhcp.boot.check.long"
  | "dhcp.boot.col.file"
  | "dhcp.boot.field.file"
  | "dhcp.boot.field.next_server"
  | "dhcp.boot.field.pxe_config"
  | "dhcp.boot.field.pxe_prefix"
  | "dhcp.boot.field.pxe_reboot"
  | "dhcp.boot.field.tftp_name"
  | "dhcp.boot.form_help"
  | "dhcp.boot.form_title"
  | "dhcp.boot.hint.file"
  | "dhcp.boot.hint.next_server"
  | "dhcp.boot.hint.pxe_config"
  | "dhcp.boot.hint.pxe_prefix"
  | "dhcp.boot.hint.pxe_reboot"
  | "dhcp.boot.hint.tftp_name"
  | "dhcp.boot.inherited"
  | "dhcp.boot.inherited_none"
  | "dhcp.boot.kind.bios"
  | "dhcp.boot.kind.http"
  | "dhcp.boot.kind.http_x64"
  | "dhcp.boot.kind.ipxe"
  | "dhcp.boot.kind.uefi_arm64"
  | "dhcp.boot.kind.uefi_x64"
  | "dhcp.boot.policies_empty"
  | "dhcp.boot.policies_help"
  | "dhcp.boot.policies_link"
  | "dhcp.boot.policies_note"
  | "dhcp.boot.policies_title"
  | "dhcp.boot.save"
  | "dhcp.boot.saved"
  | "dhcp.boot.unchanged"
  | "dhcp.catalog.managed"
  | "dhcp.check.def_code"
  | "dhcp.check.exclusion_first"
  | "dhcp.check.exclusion_last"
  | "dhcp.check.exclusion_order"
  | "dhcp.check.exclusion_outside"
  | "dhcp.check.hex"
  | "dhcp.check.history_days"
  | "dhcp.check.lease_number"
  | "dhcp.check.lease_order"
  | "dhcp.check.lease_year"
  | "dhcp.check.mac"
  | "dhcp.check.mac_pattern"
  | "dhcp.check.match_empty"
  | "dhcp.check.match_hex"
  | "dhcp.check.match_long"
  | "dhcp.check.match_mac"
  | "dhcp.check.match_number"
  | "dhcp.check.name"
  | "dhcp.check.order"
  | "dhcp.check.prefix"
  | "dhcp.check.range_address"
  | "dhcp.check.range_order"
  | "dhcp.check.range_outside"
  | "dhcp.check.server_id"
  | "dhcp.check.server_id_clear"
  | "dhcp.check.space"
  | "dhcp.check.term_class"
  | "dhcp.class.create"
  | "dhcp.class.create_title"
  | "dhcp.class.created"
  | "dhcp.class.delete_body"
  | "dhcp.class.delete_confirm"
  | "dhcp.class.delete_title"
  | "dhcp.class.deleted"
  | "dhcp.class.edit_title"
  | "dhcp.class.field.matches"
  | "dhcp.class.field.matches_help"
  | "dhcp.class.field.name"
  | "dhcp.class.save"
  | "dhcp.class.saved"
  | "dhcp.classes.empty"
  | "dhcp.classes.empty_body"
  | "dhcp.classes.sub"
  | "dhcp.classes.title"
  | "dhcp.col.action"
  | "dhcp.col.address"
  | "dhcp.col.classes"
  | "dhcp.col.client_id"
  | "dhcp.col.client_mac"
  | "dhcp.col.code"
  | "dhcp.col.condition"
  | "dhcp.col.description"
  | "dhcp.col.enabled"
  | "dhcp.col.ends"
  | "dhcp.col.event"
  | "dhcp.col.filter_kind"
  | "dhcp.col.first"
  | "dhcp.col.host_name"
  | "dhcp.col.interface"
  | "dhcp.col.last"
  | "dhcp.col.lease"
  | "dhcp.col.leased"
  | "dhcp.col.leases"
  | "dhcp.col.mac"
  | "dhcp.col.matches"
  | "dhcp.col.name"
  | "dhcp.col.network"
  | "dhcp.col.node"
  | "dhcp.col.note"
  | "dhcp.col.order"
  | "dhcp.col.pools"
  | "dhcp.col.range"
  | "dhcp.col.relay"
  | "dhcp.col.reserved"
  | "dhcp.col.scope"
  | "dhcp.col.scopes"
  | "dhcp.col.server_managed"
  | "dhcp.col.size"
  | "dhcp.col.space"
  | "dhcp.col.state"
  | "dhcp.col.state_after"
  | "dhcp.col.time"
  | "dhcp.col.type"
  | "dhcp.col.used_by"
  | "dhcp.col.utilization"
  | "dhcp.col.vendor_class"
  | "dhcp.coming.body"
  | "dhcp.coming.scopes"
  | "dhcp.coming.title"
  | "dhcp.ddns.check.ttl"
  | "dhcp.ddns.conflict.protect"
  | "dhcp.ddns.conflict.replace"
  | "dhcp.ddns.field.client_a"
  | "dhcp.ddns.field.client_a_help"
  | "dhcp.ddns.field.conflict"
  | "dhcp.ddns.field.enabled"
  | "dhcp.ddns.field.foreign"
  | "dhcp.ddns.field.foreign_help"
  | "dhcp.ddns.field.legacy"
  | "dhcp.ddns.field.legacy_help"
  | "dhcp.ddns.field.reverse"
  | "dhcp.ddns.field.reverse_help"
  | "dhcp.ddns.field.ttl"
  | "dhcp.ddns.field.ttl_help"
  | "dhcp.ddns.field.zone"
  | "dhcp.ddns.follows"
  | "dhcp.ddns.hardened_note"
  | "dhcp.ddns.help"
  | "dhcp.ddns.inherit"
  | "dhcp.ddns.inherit_help"
  | "dhcp.ddns.legend"
  | "dhcp.ddns.needs_dns"
  | "dhcp.ddns.profile_open"
  | "dhcp.ddns.profile_strict"
  | "dhcp.ddns.saved"
  | "dhcp.ddns.server_now"
  | "dhcp.ddns.title"
  | "dhcp.ddns.words.client_a"
  | "dhcp.ddns.words.foreign"
  | "dhcp.ddns.words.legacy_off"
  | "dhcp.ddns.words.legacy_on"
  | "dhcp.ddns.words.off"
  | "dhcp.ddns.words.on"
  | "dhcp.ddns.words.protect"
  | "dhcp.ddns.words.replace"
  | "dhcp.ddns.words.reverse_off"
  | "dhcp.ddns.words.reverse_on"
  | "dhcp.ddns.words.ttl"
  | "dhcp.ddns.words.ttl_third"
  | "dhcp.ddns.words.zone"
  | "dhcp.ddns.words.zone_domain"
  | "dhcp.ddns.zone_none"
  | "dhcp.ddns.zone_state.off"
  | "dhcp.ddns.zone_state.on"
  | "dhcp.ddns.zone_state.profile_off"
  | "dhcp.ddns.zone_state.profile_on"
  | "dhcp.ddns.zone_unavailable"
  | "dhcp.ddns.zone_unknown"
  | "dhcp.def.create"
  | "dhcp.def.create_title"
  | "dhcp.def.created"
  | "dhcp.def.delete_body"
  | "dhcp.def.delete_confirm"
  | "dhcp.def.delete_title"
  | "dhcp.def.deleted"
  | "dhcp.def.field.array"
  | "dhcp.def.field.code"
  | "dhcp.def.field.code_help"
  | "dhcp.def.field.kind"
  | "dhcp.def.field.name"
  | "dhcp.def.field.space"
  | "dhcp.def.field.space_help"
  | "dhcp.def.field.vendor_class"
  | "dhcp.def.field.vendor_class_help"
  | "dhcp.def.help"
  | "dhcp.defs.empty"
  | "dhcp.do.delete"
  | "dhcp.do.edit"
  | "dhcp.do.history"
  | "dhcp.do.open"
  | "dhcp.do.refresh"
  | "dhcp.effective.architecture"
  | "dhcp.effective.classes"
  | "dhcp.effective.client_id"
  | "dhcp.effective.col.level"
  | "dhcp.effective.col.why"
  | "dhcp.effective.empty"
  | "dhcp.effective.help_facts"
  | "dhcp.effective.host_name"
  | "dhcp.effective.mac"
  | "dhcp.effective.no_classes"
  | "dhcp.effective.no_policies"
  | "dhcp.effective.note_live"
  | "dhcp.effective.policies"
  | "dhcp.effective.reservation"
  | "dhcp.effective.show"
  | "dhcp.effective.title"
  | "dhcp.effective.user_class"
  | "dhcp.effective.vendor_class"
  | "dhcp.effective.why.host"
  | "dhcp.effective.why.policy"
  | "dhcp.effective.why.pool"
  | "dhcp.effective.why.scope"
  | "dhcp.effective.why.server"
  | "dhcp.effective.why.shared_network"
  | "dhcp.event.conflict"
  | "dhcp.event.declined"
  | "dhcp.event.expired"
  | "dhcp.event.granted"
  | "dhcp.event.rebound"
  | "dhcp.event.reclaimed"
  | "dhcp.event.released"
  | "dhcp.event.renewed"
  | "dhcp.example.addr"
  | "dhcp.example.mac"
  | "dhcp.example.mac_pattern"
  | "dhcp.exclusion.create"
  | "dhcp.exclusion.create_title"
  | "dhcp.exclusion.created"
  | "dhcp.exclusion.delete_body"
  | "dhcp.exclusion.delete_confirm"
  | "dhcp.exclusion.delete_title"
  | "dhcp.exclusion.deleted"
  | "dhcp.exclusion.field.first"
  | "dhcp.exclusion.field.last"
  | "dhcp.exclusion.help"
  | "dhcp.exclusions.empty"
  | "dhcp.exclusions.empty_body"
  | "dhcp.exclusions.title"
  | "dhcp.field.description"
  | "dhcp.field.name_help"
  | "dhcp.filter.create"
  | "dhcp.filter.create_title"
  | "dhcp.filter.created"
  | "dhcp.filter.delete_body"
  | "dhcp.filter.delete_confirm"
  | "dhcp.filter.delete_title"
  | "dhcp.filter.deleted"
  | "dhcp.filter.edit_title"
  | "dhcp.filter.field.kind"
  | "dhcp.filter.field.mac"
  | "dhcp.filter.field.mac_help"
  | "dhcp.filter.field.note"
  | "dhcp.filter.kind.allow"
  | "dhcp.filter.kind.deny"
  | "dhcp.filter.save"
  | "dhcp.filter.saved"
  | "dhcp.filters.empty"
  | "dhcp.filters.empty_body"
  | "dhcp.filters.note"
  | "dhcp.filters.sub"
  | "dhcp.filters.title"
  | "dhcp.history.empty"
  | "dhcp.history.empty_body"
  | "dhcp.history.empty_filtered"
  | "dhcp.history.empty_filtered_body"
  | "dhcp.history.filters"
  | "dhcp.history.lease_link"
  | "dhcp.history.more"
  | "dhcp.history.sub"
  | "dhcp.history.title"
  | "dhcp.join.and"
  | "dhcp.join.or"
  | "dhcp.lease.default"
  | "dhcp.lease.history_link"
  | "dhcp.lease.host_missing"
  | "dhcp.lease.inherit"
  | "dhcp.lease.legend"
  | "dhcp.lease.max"
  | "dhcp.lease.min"
  | "dhcp.lease.open_host"
  | "dhcp.lease.reason"
  | "dhcp.lease.reason_help"
  | "dhcp.lease.release"
  | "dhcp.lease.release_body"
  | "dhcp.lease.release_confirm"
  | "dhcp.lease.release_title"
  | "dhcp.lease.released"
  | "dhcp.lease.reserve"
  | "dhcp.lease.reserved"
  | "dhcp.lease.server_now"
  | "dhcp.lease.unit"
  | "dhcp.lease.words"
  | "dhcp.leases.empty"
  | "dhcp.leases.empty_body"
  | "dhcp.leases.empty_filtered"
  | "dhcp.leases.empty_filtered_body"
  | "dhcp.leases.filters"
  | "dhcp.leases.more"
  | "dhcp.leases.state.abandoned"
  | "dhcp.leases.state.active"
  | "dhcp.leases.state.backup"
  | "dhcp.leases.state.expired"
  | "dhcp.leases.state.free"
  | "dhcp.leases.state.released"
  | "dhcp.leases.state.reset"
  | "dhcp.leases.sub"
  | "dhcp.leases.title"
  | "dhcp.level.host"
  | "dhcp.level.policy"
  | "dhcp.level.pool"
  | "dhcp.level.scope"
  | "dhcp.level.server"
  | "dhcp.level.shared_network"
  | "dhcp.lfilter.addr"
  | "dhcp.lfilter.addr_exact"
  | "dhcp.lfilter.addr_placeholder"
  | "dhcp.lfilter.from"
  | "dhcp.lfilter.kind"
  | "dhcp.lfilter.kind_any"
  | "dhcp.lfilter.mac"
  | "dhcp.lfilter.mac_invalid"
  | "dhcp.lfilter.name"
  | "dhcp.lfilter.name_placeholder"
  | "dhcp.lfilter.reset"
  | "dhcp.lfilter.scope"
  | "dhcp.lfilter.scope_any"
  | "dhcp.lfilter.state"
  | "dhcp.lfilter.state_any"
  | "dhcp.lfilter.to"
  | "dhcp.live.bars_label"
  | "dhcp.live.folded"
  | "dhcp.live.hint"
  | "dhcp.live.label"
  | "dhcp.live.new"
  | "dhcp.live.new_capped"
  | "dhcp.live.new_label"
  | "dhcp.live.new_link"
  | "dhcp.live.new_paused"
  | "dhcp.live.new_reset"
  | "dhcp.live.new_reset_hint"
  | "dhcp.live.new_since"
  | "dhcp.live.scope_more"
  | "dhcp.live.scope_open"
  | "dhcp.live.scope_pick"
  | "dhcp.live.strip_label"
  | "dhcp.match.add"
  | "dhcp.match.architecture"
  | "dhcp.match.architecture_named"
  | "dhcp.match.circuit_id"
  | "dhcp.match.client_id"
  | "dhcp.match.example.architecture"
  | "dhcp.match.example.circuit_id"
  | "dhcp.match.example.client_id"
  | "dhcp.match.example.host_name"
  | "dhcp.match.example.mac"
  | "dhcp.match.example.remote_id"
  | "dhcp.match.example.user_class"
  | "dhcp.match.example.vendor_class"
  | "dhcp.match.host_name"
  | "dhcp.match.host_name_prefix"
  | "dhcp.match.kind.architecture"
  | "dhcp.match.kind.circuit_id"
  | "dhcp.match.kind.client_id"
  | "dhcp.match.kind.host_name"
  | "dhcp.match.kind.mac"
  | "dhcp.match.kind.remote_id"
  | "dhcp.match.kind.user_class"
  | "dhcp.match.kind.vendor_class"
  | "dhcp.match.kind_label"
  | "dhcp.match.mac"
  | "dhcp.match.prefix"
  | "dhcp.match.remote_id"
  | "dhcp.match.remove"
  | "dhcp.match.row"
  | "dhcp.match.user_class"
  | "dhcp.match.value_label"
  | "dhcp.match.vendor_class"
  | "dhcp.match.vendor_class_prefix"
  | "dhcp.nav.classes"
  | "dhcp.nav.filters"
  | "dhcp.nav.history"
  | "dhcp.nav.label"
  | "dhcp.nav.leases"
  | "dhcp.nav.options"
  | "dhcp.nav.policies"
  | "dhcp.nav.scopes"
  | "dhcp.nav.shared_networks"
  | "dhcp.network.create"
  | "dhcp.network.create_title"
  | "dhcp.network.created"
  | "dhcp.network.delete_body"
  | "dhcp.network.delete_confirm"
  | "dhcp.network.delete_title"
  | "dhcp.network.deleted"
  | "dhcp.network.edit_title"
  | "dhcp.network.empty"
  | "dhcp.network.empty_body"
  | "dhcp.network.field.interface"
  | "dhcp.network.field.interface_help"
  | "dhcp.network.field.name"
  | "dhcp.network.save"
  | "dhcp.network.saved"
  | "dhcp.network.sub"
  | "dhcp.options.catalog"
  | "dhcp.options.catalog_help"
  | "dhcp.options.defs"
  | "dhcp.options.defs_help"
  | "dhcp.options.server"
  | "dhcp.options.server_help"
  | "dhcp.options.sub"
  | "dhcp.options.title"
  | "dhcp.optset.add"
  | "dhcp.optset.add_code"
  | "dhcp.optset.check.bool"
  | "dhcp.optset.check.code"
  | "dhcp.optset.check.count"
  | "dhcp.optset.check.empty"
  | "dhcp.optset.check.hex"
  | "dhcp.optset.check.ipv4"
  | "dhcp.optset.check.ipv6"
  | "dhcp.optset.check.managed"
  | "dhcp.optset.check.name"
  | "dhcp.optset.check.number"
  | "dhcp.optset.check.prefix"
  | "dhcp.optset.check.range"
  | "dhcp.optset.check.raw_hex"
  | "dhcp.optset.check.route"
  | "dhcp.optset.col.actions"
  | "dhcp.optset.col.code"
  | "dhcp.optset.col.name"
  | "dhcp.optset.col.value"
  | "dhcp.optset.empty"
  | "dhcp.optset.flag"
  | "dhcp.optset.kind.binary"
  | "dhcp.optset.kind.bool"
  | "dhcp.optset.kind.classless_routes"
  | "dhcp.optset.kind.empty"
  | "dhcp.optset.kind.fqdn"
  | "dhcp.optset.kind.i32"
  | "dhcp.optset.kind.ipv4_address"
  | "dhcp.optset.kind.ipv6_address"
  | "dhcp.optset.kind.ipv6_prefix"
  | "dhcp.optset.kind.string"
  | "dhcp.optset.kind.u16"
  | "dhcp.optset.kind.u32"
  | "dhcp.optset.kind.u8"
  | "dhcp.optset.kind_list"
  | "dhcp.optset.raw"
  | "dhcp.optset.remove"
  | "dhcp.optset.revert"
  | "dhcp.optset.routes_help"
  | "dhcp.optset.save"
  | "dhcp.optset.saved"
  | "dhcp.optset.unknown"
  | "dhcp.optset.value_of"
  | "dhcp.policies.empty"
  | "dhcp.policies.empty_body"
  | "dhcp.policies.note_live"
  | "dhcp.policies.sub"
  | "dhcp.policies.title"
  | "dhcp.policy.create"
  | "dhcp.policy.create_title"
  | "dhcp.policy.created"
  | "dhcp.policy.ddns.help"
  | "dhcp.policy.ddns.legend"
  | "dhcp.policy.ddns.on"
  | "dhcp.policy.delete_body"
  | "dhcp.policy.delete_confirm"
  | "dhcp.policy.delete_title"
  | "dhcp.policy.deleted"
  | "dhcp.policy.edit_title"
  | "dhcp.policy.field.action"
  | "dhcp.policy.field.condition"
  | "dhcp.policy.field.enabled"
  | "dhcp.policy.field.join"
  | "dhcp.policy.field.name"
  | "dhcp.policy.field.order"
  | "dhcp.policy.field.order_help"
  | "dhcp.policy.field.range_first"
  | "dhcp.policy.field.range_last"
  | "dhcp.policy.field.scope"
  | "dhcp.policy.field.scope_fixed"
  | "dhcp.policy.lease_inherit_help"
  | "dhcp.policy.options.help"
  | "dhcp.policy.options.label"
  | "dhcp.policy.options.new"
  | "dhcp.policy.options.title"
  | "dhcp.policy.save"
  | "dhcp.policy.saved"
  | "dhcp.policy.scope_server"
  | "dhcp.pool.clear"
  | "dhcp.pool.clear_body"
  | "dhcp.pool.clear_title"
  | "dhcp.pool.cleared"
  | "dhcp.pool.edit_title"
  | "dhcp.pool.field.classes"
  | "dhcp.pool.field.classes_help"
  | "dhcp.pool.lease_inherit_help"
  | "dhcp.pool.lease_range"
  | "dhcp.pool.lease_scope"
  | "dhcp.pool.save"
  | "dhcp.pool.saved"
  | "dhcp.pool.settings"
  | "dhcp.pools.empty"
  | "dhcp.pools.empty_body"
  | "dhcp.pools.ipam_link"
  | "dhcp.pools.note"
  | "dhcp.pools.title"
  | "dhcp.reservations.col_identity"
  | "dhcp.reservations.col_lease"
  | "dhcp.reservations.col_served"
  | "dhcp.reservations.empty"
  | "dhcp.reservations.help"
  | "dhcp.reservations.identity_client_id"
  | "dhcp.reservations.identity_mac"
  | "dhcp.reservations.identity_none"
  | "dhcp.reservations.ipv6_later"
  | "dhcp.reservations.lease_ends"
  | "dhcp.reservations.lease_failed"
  | "dhcp.reservations.lease_none"
  | "dhcp.reservations.lease_other"
  | "dhcp.reservations.scope_none"
  | "dhcp.reservations.scope_setup"
  | "dhcp.reservations.state_not_serving"
  | "dhcp.reservations.state_scope_disabled"
  | "dhcp.reservations.state_served"
  | "dhcp.reservations.title"
  | "dhcp.reserve.check.client_id"
  | "dhcp.reserve.check.host_name"
  | "dhcp.reserve.check.identity"
  | "dhcp.reserve.check.interface_name"
  | "dhcp.reserve.check.ip"
  | "dhcp.reserve.check.mac"
  | "dhcp.reserve.field.address"
  | "dhcp.reserve.field.address_help"
  | "dhcp.reserve.field.client_id"
  | "dhcp.reserve.field.client_id_help"
  | "dhcp.reserve.field.host"
  | "dhcp.reserve.field.interface"
  | "dhcp.reserve.field.mac"
  | "dhcp.reserve.field.mac_help"
  | "dhcp.reserve.field.new_host"
  | "dhcp.reserve.field.new_interface"
  | "dhcp.reserve.field.status"
  | "dhcp.reserve.host_new"
  | "dhcp.reserve.host_option"
  | "dhcp.reserve.in_pool"
  | "dhcp.reserve.in_pool_lease"
  | "dhcp.reserve.interface_new"
  | "dhcp.reserve.loading"
  | "dhcp.reserve.mode.dynamic"
  | "dhcp.reserve.mode.reserved"
  | "dhcp.reserve.mode.static"
  | "dhcp.reserve.mode.unmanaged"
  | "dhcp.reserve.no_scope"
  | "dhcp.reserve.open_host"
  | "dhcp.reserve.outside"
  | "dhcp.reserve.preview"
  | "dhcp.reserve.save"
  | "dhcp.reserve.saved"
  | "dhcp.reserve.saved_unchanged"
  | "dhcp.reserve.scope_disabled"
  | "dhcp.reserve.scope_link"
  | "dhcp.reserve.scope_not_serving"
  | "dhcp.reserve.scope_served"
  | "dhcp.reserve.stale"
  | "dhcp.reserve.status.active"
  | "dhcp.reserve.status.planned"
  | "dhcp.reserve.title"
  | "dhcp.reserve.use_free"
  | "dhcp.reserve.will.address_bound"
  | "dhcp.reserve.will.address_kept"
  | "dhcp.reserve.will.address_new"
  | "dhcp.reserve.will.address_status"
  | "dhcp.reserve.will.host_kept"
  | "dhcp.reserve.will.host_mode"
  | "dhcp.reserve.will.host_new"
  | "dhcp.reserve.will.interface_client_id"
  | "dhcp.reserve.will.interface_client_id_cleared"
  | "dhcp.reserve.will.interface_mac"
  | "dhcp.reserve.will.interface_mac_kept"
  | "dhcp.reserve.will.interface_mac_replaced"
  | "dhcp.reserve.will.interface_new"
  | "dhcp.reserve.will.interface_new_mac"
  | "dhcp.reserve.will.keyed_client_id"
  | "dhcp.reserve.will.keyed_mac"
  | "dhcp.reserve.will.lease_other"
  | "dhcp.reserve.will.not_serving"
  | "dhcp.reserve.will.nothing"
  | "dhcp.reserve.will.scope_disabled"
  | "dhcp.reserve.will.scope_served"
  | "dhcp.scope.create"
  | "dhcp.scope.create_title"
  | "dhcp.scope.created"
  | "dhcp.scope.ddns_line_off"
  | "dhcp.scope.ddns_line_on"
  | "dhcp.scope.ddns_link"
  | "dhcp.scope.delete_body"
  | "dhcp.scope.delete_confirm"
  | "dhcp.scope.delete_title"
  | "dhcp.scope.deleted"
  | "dhcp.scope.disabled"
  | "dhcp.scope.enabled"
  | "dhcp.scope.field.authoritative"
  | "dhcp.scope.field.authoritative_help"
  | "dhcp.scope.field.classes"
  | "dhcp.scope.field.classes_help"
  | "dhcp.scope.field.enabled"
  | "dhcp.scope.field.enabled_help"
  | "dhcp.scope.field.prefix"
  | "dhcp.scope.field.prefix_help"
  | "dhcp.scope.field.prefix_pick"
  | "dhcp.scope.field.restricted"
  | "dhcp.scope.field.restricted_help"
  | "dhcp.scope.field.server_id"
  | "dhcp.scope.field.server_id_help"
  | "dhcp.scope.field.shared_network"
  | "dhcp.scope.in_ipam"
  | "dhcp.scope.no_classes"
  | "dhcp.scope.no_networks"
  | "dhcp.scope.options_help"
  | "dhcp.scope.options_title"
  | "dhcp.scope.save"
  | "dhcp.scope.saved"
  | "dhcp.scope.settings"
  | "dhcp.scope.shared_none"
  | "dhcp.scope.tab.boot"
  | "dhcp.scope.tab.ddns"
  | "dhcp.scope.tab.exclusions"
  | "dhcp.scope.tab.options"
  | "dhcp.scope.tab.pools"
  | "dhcp.scope.tab.settings"
  | "dhcp.scope.tabs"
  | "dhcp.scope.title"
  | "dhcp.scope.unchanged"
  | "dhcp.scopes.empty"
  | "dhcp.scopes.empty_body"
  | "dhcp.scopes.sub"
  | "dhcp.scopes.title"
  | "dhcp.settings.authoritative"
  | "dhcp.settings.authoritative_help"
  | "dhcp.settings.conflict"
  | "dhcp.settings.conflict_follow"
  | "dhcp.settings.conflict_help"
  | "dhcp.settings.effective"
  | "dhcp.settings.effective_days"
  | "dhcp.settings.history_days"
  | "dhcp.settings.history_days_help"
  | "dhcp.settings.history_follow"
  | "dhcp.settings.lease"
  | "dhcp.settings.lease_help"
  | "dhcp.settings.lede"
  | "dhcp.settings.off"
  | "dhcp.settings.on"
  | "dhcp.settings.save"
  | "dhcp.settings.saved"
  | "dhcp.settings.server"
  | "dhcp.settings.title"
  | "dhcp.shared_networks.title"
  | "dhcp.state.not_built_body"
  | "dhcp.state.not_built_title"
  | "dhcp.state.off_body"
  | "dhcp.state.off_link"
  | "dhcp.state.off_title"
  | "dhcp.strip.accepting"
  | "dhcp.strip.commit"
  | "dhcp.strip.label"
  | "dhcp.strip.listeners"
  | "dhcp.strip.not_dhcp_body"
  | "dhcp.strip.not_dhcp_title"
  | "dhcp.strip.not_serving"
  | "dhcp.strip.probe_off"
  | "dhcp.strip.probe_on"
  | "dhcp.strip.refusing"
  | "dhcp.strip.revision"
  | "dhcp.strip.scopes"
  | "dhcp.strip.serving"
  | "dhcp.term.add"
  | "dhcp.term.class"
  | "dhcp.term.class_label"
  | "dhcp.term.class_pick"
  | "dhcp.term.kind.class"
  | "dhcp.term.kind.match"
  | "dhcp.term.kind.not_class"
  | "dhcp.term.kind.not_match"
  | "dhcp.term.kind_label"
  | "dhcp.term.not_class"
  | "dhcp.term.not_match"
  | "dhcp.term.remove"
  | "dhcp.term.row"
  | "dhcp.title"
  | "dhcp.tri.inherit"
  | "dhcp.unit.days"
  | "dhcp.unit.hours"
  | "dhcp.unit.minutes"
  | "dhcp.util.abandoned"
  | "dhcp.util.at"
  | "dhcp.util.free"
  | "dhcp.util.label"
  | "dhcp.util.leased"
  | "dhcp.util.percent"
  | "dhcp.util.pool_size"
  | "dhcp.util.reserved"
  | "dhcp.util.title"
  | "discovery.action.approve"
  | "discovery.action.dismiss"
  | "discovery.action.open"
  | "discovery.action.reconcile"
  | "discovery.action.reject"
  | "discovery.approve.confirm"
  | "discovery.approve.title"
  | "discovery.batch.approve"
  | "discovery.batch.approve_body"
  | "discovery.batch.approve_confirm"
  | "discovery.batch.approve_title"
  | "discovery.batch.done_approved"
  | "discovery.batch.done_rejected"
  | "discovery.batch.done_skipped"
  | "discovery.batch.keep"
  | "discovery.batch.kind.address_mismatch"
  | "discovery.batch.kind.conflict"
  | "discovery.batch.kind.discovered_host"
  | "discovery.batch.kind.orphaned_intent"
  | "discovery.batch.kind.outside_prefixes"
  | "discovery.batch.kind.prefix_vlan_mismatch"
  | "discovery.batch.kind.vlan_discovered"
  | "discovery.batch.loaded_only"
  | "discovery.batch.reject"
  | "discovery.batch.reject_body"
  | "discovery.batch.reject_title"
  | "discovery.batch.skipped_body"
  | "discovery.batch.skipped_title"
  | "discovery.col.created"
  | "discovery.col.first_seen"
  | "discovery.col.kind"
  | "discovery.col.last_seen"
  | "discovery.col.observed"
  | "discovery.col.prefix"
  | "discovery.col.severity"
  | "discovery.col.sightings"
  | "discovery.col.source"
  | "discovery.col.sources"
  | "discovery.col.state"
  | "discovery.col.subject"
  | "discovery.col.subject_key"
  | "discovery.col.summary"
  | "discovery.col.type"
  | "discovery.col.updated"
  | "discovery.count"
  | "discovery.count_open"
  | "discovery.empty.body"
  | "discovery.empty.filtered"
  | "discovery.empty.title"
  | "discovery.fact.address_mac"
  | "discovery.fact.attachment"
  | "discovery.fact.attachment_vlan"
  | "discovery.fact.current"
  | "discovery.fact.expired"
  | "discovery.fact.link"
  | "discovery.fact.name"
  | "discovery.fact.network"
  | "discovery.fact.no_ports"
  | "discovery.fact.os"
  | "discovery.fact.parent"
  | "discovery.fact.port"
  | "discovery.fact.ports"
  | "discovery.fact.ssid"
  | "discovery.fact.tls"
  | "discovery.fact.vendor"
  | "discovery.fact_type.address"
  | "discovery.fact_type.attachment"
  | "discovery.fact_type.host"
  | "discovery.fact_type.link"
  | "discovery.fact_type.name"
  | "discovery.fact_type.network"
  | "discovery.fact_type.os"
  | "discovery.fact_type.services"
  | "discovery.fact_type.vendor"
  | "discovery.filter.all"
  | "discovery.filter.label"
  | "discovery.filter.placeholder"
  | "discovery.filter.prefix"
  | "discovery.filter.remove"
  | "discovery.filter.remove_prefix"
  | "discovery.filter.state"
  | "discovery.grid.label"
  | "discovery.kind.address_mismatch"
  | "discovery.kind.conflict"
  | "discovery.kind.discovered_host"
  | "discovery.kind.orphaned_intent"
  | "discovery.kind.outside_prefixes"
  | "discovery.kind.prefix_vlan_mismatch"
  | "discovery.kind.vlan_discovered"
  | "discovery.lookup.label"
  | "discovery.lookup.placeholder"
  | "discovery.lookup.submit"
  | "discovery.method.arp"
  | "discovery.method.arp_sweep"
  | "discovery.method.dhcp_snoop"
  | "discovery.method.icmp"
  | "discovery.method.lldp"
  | "discovery.method.llmnr"
  | "discovery.method.mdns"
  | "discovery.method.nd"
  | "discovery.method.os_fingerprint"
  | "discovery.method.reverse_dns"
  | "discovery.method.snmp"
  | "discovery.method.tcp_connect"
  | "discovery.method.tcp_syn"
  | "discovery.nav.label"
  | "discovery.nav.observations"
  | "discovery.nav.proposals"
  | "discovery.observations.all"
  | "discovery.observations.current"
  | "discovery.observations.empty"
  | "discovery.observations.empty_body"
  | "discovery.observations.expired"
  | "discovery.observations.filter_label"
  | "discovery.observations.filter_placeholder"
  | "discovery.observations.grid_label"
  | "discovery.observations.sub"
  | "discovery.panel.adopted_by"
  | "discovery.panel.adoption_failed"
  | "discovery.panel.change"
  | "discovery.panel.change_conflict"
  | "discovery.panel.change_count"
  | "discovery.panel.change_none"
  | "discovery.panel.conflict_hint"
  | "discovery.panel.decided_by"
  | "discovery.panel.decision"
  | "discovery.panel.evidence"
  | "discovery.panel.evidence_count"
  | "discovery.panel.first_seen"
  | "discovery.panel.intent"
  | "discovery.panel.ip"
  | "discovery.panel.label"
  | "discovery.panel.last_seen"
  | "discovery.panel.mac"
  | "discovery.panel.name"
  | "discovery.panel.network"
  | "discovery.panel.newer"
  | "discovery.panel.no_evidence"
  | "discovery.panel.nothing_hint"
  | "discovery.panel.opened"
  | "discovery.panel.prefix"
  | "discovery.panel.reason"
  | "discovery.panel.results"
  | "discovery.panel.sightings"
  | "discovery.panel.subject"
  | "discovery.panel.superseded_by"
  | "discovery.reconcile.failed"
  | "discovery.reject.body"
  | "discovery.reject.body_conflict"
  | "discovery.reject.confirm"
  | "discovery.reject.confirm_conflict"
  | "discovery.reject.reason"
  | "discovery.reject.reason_hint"
  | "discovery.reject.reason_too_long"
  | "discovery.reject.title"
  | "discovery.reject.title_conflict"
  | "discovery.report.adopted"
  | "discovery.report.adoption_failures"
  | "discovery.report.at"
  | "discovery.report.expired"
  | "discovery.report.moves_confirmed"
  | "discovery.report.nothing"
  | "discovery.report.opened"
  | "discovery.report.refreshed"
  | "discovery.report.sightings"
  | "discovery.report.superseded"
  | "discovery.report.suppressed"
  | "discovery.report.title"
  | "discovery.report.unchanged"
  | "discovery.rule.address_mismatch"
  | "discovery.rule.address_unrecorded"
  | "discovery.rule.conflict_address_taken"
  | "discovery.rule.conflict_networks"
  | "discovery.rule.conflict_shared_address"
  | "discovery.rule.discovered_address"
  | "discovery.rule.discovered_mac"
  | "discovery.rule.orphaned_address"
  | "discovery.rule.outside_prefixes"
  | "discovery.rule.prefix_vlan_differs"
  | "discovery.rule.prefix_vlan_unset"
  | "discovery.rule.vlan_discovered"
  | "discovery.severity.critical"
  | "discovery.severity.info"
  | "discovery.severity.warning"
  | "discovery.source.dhcp"
  | "discovery.source.dns"
  | "discovery.source.inventory"
  | "discovery.source.network_controller"
  | "discovery.source.probe"
  | "discovery.source_short.dhcp_lease"
  | "discovery.source_short.dns_record"
  | "discovery.source_short.inventory"
  | "discovery.source_short.network_controller"
  | "discovery.source_short.probe"
  | "discovery.state.accepted"
  | "discovery.state.expired"
  | "discovery.state.open"
  | "discovery.state.rejected"
  | "discovery.state.superseded"
  | "discovery.subject.attachments"
  | "discovery.subject.current"
  | "discovery.subject.fact_count"
  | "discovery.subject.facts"
  | "discovery.subject.intent"
  | "discovery.subject.ips"
  | "discovery.subject.kind_ip"
  | "discovery.subject.kind_mac"
  | "discovery.subject.kind_name"
  | "discovery.subject.macs"
  | "discovery.subject.names"
  | "discovery.subject.no_intent"
  | "discovery.subject.no_proposals"
  | "discovery.subject.not_current"
  | "discovery.subject.os"
  | "discovery.subject.parents"
  | "discovery.subject.platforms"
  | "discovery.subject.ports"
  | "discovery.subject.proposals"
  | "discovery.subject.sightings"
  | "discovery.subject.sources"
  | "discovery.subject.summary"
  | "discovery.subject.tags"
  | "discovery.subject.tls"
  | "discovery.subject.unknown"
  | "discovery.subject.vendors"
  | "discovery.subject.vlan"
  | "discovery.toast.approved"
  | "discovery.toast.dismissed"
  | "discovery.toast.rejected"
  | "dns.acl.col.entries"
  | "dns.acl.col.used_by"
  | "dns.acl.create"
  | "dns.acl.create_title"
  | "dns.acl.created"
  | "dns.acl.delete_body"
  | "dns.acl.delete_confirm"
  | "dns.acl.delete_title"
  | "dns.acl.delete_used"
  | "dns.acl.deleted"
  | "dns.acl.edit_title"
  | "dns.acl.entry_invalid"
  | "dns.acl.field.entries"
  | "dns.acl.field.entries_help"
  | "dns.acl.field.name"
  | "dns.acl.name_invalid"
  | "dns.acl.save"
  | "dns.acl.saved"
  | "dns.acls.empty"
  | "dns.acls.sub"
  | "dns.acls.title"
  | "dns.anchor.add"
  | "dns.anchor.add_title"
  | "dns.anchor.added"
  | "dns.anchor.check.dnskey"
  | "dns.anchor.check.ds"
  | "dns.anchor.check.zone"
  | "dns.anchor.col.algorithm"
  | "dns.anchor.col.form"
  | "dns.anchor.col.seen"
  | "dns.anchor.col.source"
  | "dns.anchor.col.state"
  | "dns.anchor.col.tag"
  | "dns.anchor.field.dnskey"
  | "dns.anchor.field.dnskey_help"
  | "dns.anchor.field.ds"
  | "dns.anchor.field.ds_help"
  | "dns.anchor.field.form"
  | "dns.anchor.field.form_dnskey"
  | "dns.anchor.field.form_ds"
  | "dns.anchor.field.replace_root"
  | "dns.anchor.field.replace_root_help"
  | "dns.anchor.field.zone"
  | "dns.anchor.field.zone_help"
  | "dns.anchor.form.dnskey"
  | "dns.anchor.form.ds"
  | "dns.anchor.keys_of"
  | "dns.anchor.last_query"
  | "dns.anchor.lede"
  | "dns.anchor.never"
  | "dns.anchor.never_seen"
  | "dns.anchor.next_query"
  | "dns.anchor.pending"
  | "dns.anchor.refresh"
  | "dns.anchor.refresh_failed"
  | "dns.anchor.refresh_sent"
  | "dns.anchor.remove"
  | "dns.anchor.remove_body"
  | "dns.anchor.remove_confirm"
  | "dns.anchor.remove_root_body"
  | "dns.anchor.remove_title"
  | "dns.anchor.removed"
  | "dns.anchor.root"
  | "dns.anchor.source.operator"
  | "dns.anchor.source.rfc5011"
  | "dns.anchor.source.shipped"
  | "dns.anchor.state.add_pend"
  | "dns.anchor.state.missing"
  | "dns.anchor.state.removed"
  | "dns.anchor.state.revoked"
  | "dns.anchor.state.start"
  | "dns.anchor.state.valid"
  | "dns.anchor.state_since"
  | "dns.batch.add_to"
  | "dns.batch.applied"
  | "dns.batch.apply"
  | "dns.batch.back"
  | "dns.batch.col.after"
  | "dns.batch.col.before"
  | "dns.batch.col.change"
  | "dns.batch.count"
  | "dns.batch.diff_summary"
  | "dns.batch.diff_title"
  | "dns.batch.discard"
  | "dns.batch.drop"
  | "dns.batch.hint"
  | "dns.batch.kind.add"
  | "dns.batch.kind.change"
  | "dns.batch.kind.delete"
  | "dns.batch.list_label"
  | "dns.batch.mode"
  | "dns.batch.pending_tag"
  | "dns.batch.review"
  | "dns.blocking.allow"
  | "dns.blocking.allow.added"
  | "dns.blocking.allow.already"
  | "dns.blocking.allow.job"
  | "dns.blocking.allow_label"
  | "dns.blocking.client.withheld"
  | "dns.blocking.client.withheld_hint"
  | "dns.blocking.clients.empty"
  | "dns.blocking.clients.note_hidden"
  | "dns.blocking.clients.note_pseudonym"
  | "dns.blocking.clients.table"
  | "dns.blocking.clients.title"
  | "dns.blocking.col.action"
  | "dns.blocking.col.blocked"
  | "dns.blocking.col.client"
  | "dns.blocking.col.ipam"
  | "dns.blocking.col.list"
  | "dns.blocking.col.name"
  | "dns.blocking.col.queries"
  | "dns.blocking.col.share"
  | "dns.blocking.col.time"
  | "dns.blocking.hours.bar"
  | "dns.blocking.hours.blocked"
  | "dns.blocking.hours.label"
  | "dns.blocking.hours.queries"
  | "dns.blocking.hours.title"
  | "dns.blocking.list_deleted"
  | "dns.blocking.lists.empty"
  | "dns.blocking.lists.manage"
  | "dns.blocking.lists.table"
  | "dns.blocking.lists.title"
  | "dns.blocking.loading"
  | "dns.blocking.log_off.body"
  | "dns.blocking.log_off.link"
  | "dns.blocking.log_off.title"
  | "dns.blocking.next"
  | "dns.blocking.pause.btn.15"
  | "dns.blocking.pause.btn.5"
  | "dns.blocking.pause.btn.60"
  | "dns.blocking.pause.btn.open"
  | "dns.blocking.pause.for"
  | "dns.blocking.pause.hint"
  | "dns.blocking.pause.label"
  | "dns.blocking.pause.left"
  | "dns.blocking.pause.on"
  | "dns.blocking.pause.open"
  | "dns.blocking.pause.title"
  | "dns.blocking.pause.until"
  | "dns.blocking.period"
  | "dns.blocking.recent.empty"
  | "dns.blocking.recent.table"
  | "dns.blocking.recent.title"
  | "dns.blocking.refresh"
  | "dns.blocking.resume"
  | "dns.blocking.sample"
  | "dns.blocking.short_log"
  | "dns.blocking.sub"
  | "dns.blocking.tile.blocked"
  | "dns.blocking.tile.blocked_hint"
  | "dns.blocking.tile.cached"
  | "dns.blocking.tile.cached_hint"
  | "dns.blocking.tile.clients"
  | "dns.blocking.tile.clients_hint"
  | "dns.blocking.tile.queries"
  | "dns.blocking.tile.queries_hint"
  | "dns.blocking.title"
  | "dns.blocking.top.empty"
  | "dns.blocking.top_blocked.table"
  | "dns.blocking.top_blocked.title"
  | "dns.blocking.top_names.table"
  | "dns.blocking.top_names.title"
  | "dns.blocking.truncated"
  | "dns.blocking.window.24h"
  | "dns.blocking.window.7d"
  | "dns.blocking.window.label"
  | "dns.cache.capped"
  | "dns.cache.col.data"
  | "dns.cache.col.hits"
  | "dns.cache.col.name"
  | "dns.cache.col.stale"
  | "dns.cache.col.state"
  | "dns.cache.col.ttl"
  | "dns.cache.col.type"
  | "dns.cache.col.view"
  | "dns.cache.data_less"
  | "dns.cache.data_more"
  | "dns.cache.ede"
  | "dns.cache.ede_hint"
  | "dns.cache.empty"
  | "dns.cache.empty_suffix"
  | "dns.cache.flush"
  | "dns.cache.flush_body"
  | "dns.cache.flush_cancel"
  | "dns.cache.flush_confirm"
  | "dns.cache.flush_failed"
  | "dns.cache.flush_title"
  | "dns.cache.flushed"
  | "dns.cache.lede"
  | "dns.cache.more"
  | "dns.cache.next"
  | "dns.cache.no_node"
  | "dns.cache.not_dns_body"
  | "dns.cache.not_dns_title"
  | "dns.cache.open_hint"
  | "dns.cache.page"
  | "dns.cache.previous"
  | "dns.cache.reload"
  | "dns.cache.root"
  | "dns.cache.rows_shown"
  | "dns.cache.same_as_parent"
  | "dns.cache.show"
  | "dns.cache.signature"
  | "dns.cache.signature_expiry"
  | "dns.cache.signature_hint"
  | "dns.cache.stale"
  | "dns.cache.stale_hint"
  | "dns.cache.sub"
  | "dns.cache.suffix"
  | "dns.cache.suffix_invalid"
  | "dns.cache.suffix_placeholder"
  | "dns.cache.title"
  | "dns.cache.tree_label"
  | "dns.cache.ttl_h"
  | "dns.cache.ttl_min"
  | "dns.cache.ttl_none"
  | "dns.cache.ttl_s"
  | "dns.cache.view_default"
  | "dns.check.caa"
  | "dns.check.empty"
  | "dns.check.ipv4"
  | "dns.check.ipv6"
  | "dns.check.mx"
  | "dns.check.name"
  | "dns.check.number"
  | "dns.check.outside"
  | "dns.check.srv"
  | "dns.check.target"
  | "dns.check.ttl"
  | "dns.check.txt"
  | "dns.check.type"
  | "dns.col.data"
  | "dns.col.description"
  | "dns.col.kind"
  | "dns.col.name"
  | "dns.col.origin"
  | "dns.col.origins"
  | "dns.col.rrsets"
  | "dns.col.serial"
  | "dns.col.ttl"
  | "dns.col.type"
  | "dns.col.updated"
  | "dns.col.zone"
  | "dns.coming.body"
  | "dns.coming.title"
  | "dns.coming.zones"
  | "dns.dnssec.algorithm.ecdsa_p256_sha256"
  | "dns.dnssec.algorithm.ed25519"
  | "dns.dnssec.algorithm_label"
  | "dns.dnssec.csk"
  | "dns.dnssec.ds"
  | "dns.dnssec.ds_copied"
  | "dns.dnssec.ds_copy"
  | "dns.dnssec.ds_copy_blocked"
  | "dns.dnssec.ds_help"
  | "dns.dnssec.ds_none"
  | "dns.dnssec.expires"
  | "dns.dnssec.finding.clock_skew"
  | "dns.dnssec.finding.expired"
  | "dns.dnssec.finding.expiring"
  | "dns.dnssec.finding.other"
  | "dns.dnssec.finding.resign_overdue"
  | "dns.dnssec.key.activated"
  | "dns.dnssec.key.published"
  | "dns.dnssec.key.retired"
  | "dns.dnssec.key.role"
  | "dns.dnssec.key.state"
  | "dns.dnssec.key.tag"
  | "dns.dnssec.keys"
  | "dns.dnssec.keys_none"
  | "dns.dnssec.last_signed"
  | "dns.dnssec.mode.imported"
  | "dns.dnssec.mode.off"
  | "dns.dnssec.mode.online"
  | "dns.dnssec.mode_help.imported"
  | "dns.dnssec.mode_help.off"
  | "dns.dnssec.mode_help.online"
  | "dns.dnssec.mode_label"
  | "dns.dnssec.next_resign"
  | "dns.dnssec.nsec3"
  | "dns.dnssec.parent_ds"
  | "dns.dnssec.parent_ds_undo"
  | "dns.dnssec.policy"
  | "dns.dnssec.role.csk"
  | "dns.dnssec.role.ksk"
  | "dns.dnssec.role.zsk"
  | "dns.dnssec.roll.csk"
  | "dns.dnssec.roll.ksk"
  | "dns.dnssec.roll.zsk"
  | "dns.dnssec.rollover"
  | "dns.dnssec.rollover_failed"
  | "dns.dnssec.rollover_help"
  | "dns.dnssec.rollover_open_job"
  | "dns.dnssec.rollover_running"
  | "dns.dnssec.rollover_started"
  | "dns.dnssec.save"
  | "dns.dnssec.saved"
  | "dns.dnssec.signed_serial"
  | "dns.dnssec.state.active"
  | "dns.dnssec.state.generated"
  | "dns.dnssec.state.published"
  | "dns.dnssec.state.removed"
  | "dns.dnssec.state.retired"
  | "dns.dnssec.status"
  | "dns.do.add_records"
  | "dns.do.delete"
  | "dns.do.delete_rrset"
  | "dns.do.edit"
  | "dns.do.export"
  | "dns.do.import"
  | "dns.do.open"
  | "dns.do.remove_record"
  | "dns.do.take_over"
  | "dns.export.failed"
  | "dns.fwd.all_views"
  | "dns.fwd.check.address"
  | "dns.fwd.check.duplicate"
  | "dns.fwd.check.none"
  | "dns.fwd.check.path"
  | "dns.fwd.check.path_transport"
  | "dns.fwd.check.port"
  | "dns.fwd.check.suffix"
  | "dns.fwd.check.taken"
  | "dns.fwd.check.tls_name"
  | "dns.fwd.check.tls_required"
  | "dns.fwd.check.too_many"
  | "dns.fwd.check.view"
  | "dns.fwd.col.suffix"
  | "dns.fwd.col.tls_name"
  | "dns.fwd.col.transport"
  | "dns.fwd.col.upstreams"
  | "dns.fwd.col.view"
  | "dns.fwd.create"
  | "dns.fwd.create_title"
  | "dns.fwd.created"
  | "dns.fwd.default"
  | "dns.fwd.delete_body"
  | "dns.fwd.delete_confirm"
  | "dns.fwd.delete_root"
  | "dns.fwd.delete_title"
  | "dns.fwd.deleted"
  | "dns.fwd.edit_title"
  | "dns.fwd.empty"
  | "dns.fwd.empty_body"
  | "dns.fwd.field.all_views"
  | "dns.fwd.field.all_views_help"
  | "dns.fwd.field.mode"
  | "dns.fwd.field.suffix"
  | "dns.fwd.field.suffix_help"
  | "dns.fwd.field.suffix_placeholder"
  | "dns.fwd.field.tls_name"
  | "dns.fwd.field.tls_name_help"
  | "dns.fwd.field.transport"
  | "dns.fwd.field.upstreams"
  | "dns.fwd.field.upstreams_help_doh"
  | "dns.fwd.field.upstreams_help_dot"
  | "dns.fwd.field.upstreams_help_plain"
  | "dns.fwd.field.validate"
  | "dns.fwd.field.validate_help"
  | "dns.fwd.field.validate_off"
  | "dns.fwd.known"
  | "dns.fwd.mode.forward"
  | "dns.fwd.mode.recurse"
  | "dns.fwd.mode.recurse_help"
  | "dns.fwd.mode.recurse_long"
  | "dns.fwd.mode.recurse_upstreams"
  | "dns.fwd.no_default_body"
  | "dns.fwd.no_default_link"
  | "dns.fwd.no_default_title"
  | "dns.fwd.preset.dot"
  | "dns.fwd.preset.dot_title"
  | "dns.fwd.preset.privacy"
  | "dns.fwd.problems_title"
  | "dns.fwd.recursion.hardened"
  | "dns.fwd.recursion.known"
  | "dns.fwd.recursion.lab"
  | "dns.fwd.recursion.title"
  | "dns.fwd.recursion.views"
  | "dns.fwd.recursion.views_link"
  | "dns.fwd.resolution.choice.default"
  | "dns.fwd.resolution.col.resolution"
  | "dns.fwd.resolution.col.view"
  | "dns.fwd.resolution.default_view"
  | "dns.fwd.resolution.failed"
  | "dns.fwd.resolution.lede"
  | "dns.fwd.resolution.mode.forward"
  | "dns.fwd.resolution.mode.recurse"
  | "dns.fwd.resolution.mode.refuse"
  | "dns.fwd.resolution.of"
  | "dns.fwd.resolution.root_rule"
  | "dns.fwd.resolution.saved"
  | "dns.fwd.resolution.title"
  | "dns.fwd.save"
  | "dns.fwd.saved"
  | "dns.fwd.sub"
  | "dns.fwd.title"
  | "dns.fwd.transport.doh"
  | "dns.fwd.transport.dot"
  | "dns.fwd.transport.plain"
  | "dns.fwd.unvalidated"
  | "dns.fwd.use_dot"
  | "dns.history.action"
  | "dns.history.changes"
  | "dns.history.empty"
  | "dns.history.no_audit"
  | "dns.history.outcome.denied"
  | "dns.history.outcome.failed"
  | "dns.history.outcome.success"
  | "dns.history.result"
  | "dns.history.revision"
  | "dns.history.serial"
  | "dns.history.serial_title"
  | "dns.history.updated"
  | "dns.history.when"
  | "dns.import.apply.again"
  | "dns.import.apply.done"
  | "dns.import.apply.failed"
  | "dns.import.apply.open_job"
  | "dns.import.apply.open_zone"
  | "dns.import.apply.progress"
  | "dns.import.apply.rolled_back"
  | "dns.import.apply.running"
  | "dns.import.apply.serial"
  | "dns.import.fact.added"
  | "dns.import.fact.removed"
  | "dns.import.fact.replaced"
  | "dns.import.losses.line"
  | "dns.import.losses.none"
  | "dns.import.losses.title"
  | "dns.import.losses.what"
  | "dns.import.parse_error"
  | "dns.import.preview.apply"
  | "dns.import.preview.back"
  | "dns.import.preview.title"
  | "dns.import.step.apply"
  | "dns.import.step.done"
  | "dns.import.step.preview"
  | "dns.import.step.upload"
  | "dns.import.steps"
  | "dns.import.title"
  | "dns.import.types.caption"
  | "dns.import.types.records"
  | "dns.import.upload.body"
  | "dns.import.upload.choose"
  | "dns.import.upload.drop"
  | "dns.import.upload.lines"
  | "dns.import.upload.paste"
  | "dns.import.upload.preview"
  | "dns.import.upload.replace"
  | "dns.import.upload.replace_help"
  | "dns.import.upload.title"
  | "dns.import.upload.too_large"
  | "dns.infra.capability.down"
  | "dns.infra.capability.edns"
  | "dns.infra.capability.lame"
  | "dns.infra.capability.lower_case"
  | "dns.infra.capability.no_edns"
  | "dns.infra.capability.tcp_only"
  | "dns.infra.col.address"
  | "dns.infra.col.capabilities"
  | "dns.infra.col.failures"
  | "dns.infra.col.origin"
  | "dns.infra.col.p99"
  | "dns.infra.col.server"
  | "dns.infra.col.srtt"
  | "dns.infra.ds.bogus"
  | "dns.infra.ds.insecure"
  | "dns.infra.ds.secure"
  | "dns.infra.ds.unknown"
  | "dns.infra.empty"
  | "dns.infra.empty_suffix"
  | "dns.infra.flush_all"
  | "dns.infra.flush_body_all"
  | "dns.infra.flush_body_suffix"
  | "dns.infra.flush_confirm"
  | "dns.infra.flush_failed"
  | "dns.infra.flush_suffix"
  | "dns.infra.flush_title_all"
  | "dns.infra.flush_title_suffix"
  | "dns.infra.flushed_all"
  | "dns.infra.flushed_suffix"
  | "dns.infra.lede"
  | "dns.infra.ms"
  | "dns.infra.no_addresses"
  | "dns.infra.off"
  | "dns.infra.origin.authoritative"
  | "dns.infra.origin.glue"
  | "dns.infra.origin.hints"
  | "dns.infra.origin.sibling_glue"
  | "dns.infra.servers_of"
  | "dns.infra.show"
  | "dns.infra.srtt_none"
  | "dns.infra.suffix"
  | "dns.infra.title"
  | "dns.job.dnssec_rollover"
  | "dns.key.col.algorithm"
  | "dns.key.col.created"
  | "dns.key.col.name"
  | "dns.key.copied"
  | "dns.key.copy_blocked"
  | "dns.key.create_action"
  | "dns.key.create_title"
  | "dns.key.created_body"
  | "dns.key.created_title"
  | "dns.key.delete_body"
  | "dns.key.delete_confirm"
  | "dns.key.delete_title"
  | "dns.key.deleted"
  | "dns.key.generate"
  | "dns.key.import"
  | "dns.key.mode"
  | "dns.key.mode_generate"
  | "dns.key.mode_import"
  | "dns.key.name_help"
  | "dns.key.secret"
  | "dns.key.secret_help"
  | "dns.key.secret_invalid"
  | "dns.key.stored"
  | "dns.keys.empty"
  | "dns.keys.sub"
  | "dns.keys.title"
  | "dns.kind.forward"
  | "dns.kind.primary"
  | "dns.kind.rpz"
  | "dns.kind.secondary"
  | "dns.kind.stub"
  | "dns.list.action.nodata"
  | "dns.list.action.nxdomain"
  | "dns.list.action.redirect"
  | "dns.list.check.file"
  | "dns.list.check.interval"
  | "dns.list.check.name"
  | "dns.list.check.redirect"
  | "dns.list.check.url"
  | "dns.list.col.action"
  | "dns.list.col.entries"
  | "dns.list.col.etag"
  | "dns.list.col.fetched"
  | "dns.list.col.format"
  | "dns.list.col.interval"
  | "dns.list.col.last_error"
  | "dns.list.col.source"
  | "dns.list.create"
  | "dns.list.create_title"
  | "dns.list.created"
  | "dns.list.delete_body"
  | "dns.list.delete_confirm"
  | "dns.list.delete_title"
  | "dns.list.deleted"
  | "dns.list.disabled"
  | "dns.list.edit_title"
  | "dns.list.every"
  | "dns.list.fetch"
  | "dns.list.fetch_failed"
  | "dns.list.fetch_started"
  | "dns.list.field.action"
  | "dns.list.field.enabled"
  | "dns.list.field.file"
  | "dns.list.field.file_help"
  | "dns.list.field.format"
  | "dns.list.field.interval"
  | "dns.list.field.interval_help"
  | "dns.list.field.name"
  | "dns.list.field.redirect"
  | "dns.list.field.redirect_help"
  | "dns.list.field.source"
  | "dns.list.field.url"
  | "dns.list.field.url_help"
  | "dns.list.file_chosen"
  | "dns.list.format.domains"
  | "dns.list.format.domains_help"
  | "dns.list.format.hosts"
  | "dns.list.format.hosts_help"
  | "dns.list.job"
  | "dns.list.no_version"
  | "dns.list.open_job"
  | "dns.list.save"
  | "dns.list.saved"
  | "dns.list.source.upload"
  | "dns.list.source.url"
  | "dns.list.upload"
  | "dns.list.upload_hint"
  | "dns.list.upload_title"
  | "dns.list.uploaded"
  | "dns.lists.empty"
  | "dns.lists.empty_body"
  | "dns.lists.sub"
  | "dns.lists.title"
  | "dns.log.blocked"
  | "dns.log.cached"
  | "dns.log.client_mode.address"
  | "dns.log.client_mode.hidden"
  | "dns.log.client_mode.pseudonym"
  | "dns.log.client_none"
  | "dns.log.col.client"
  | "dns.log.col.ede"
  | "dns.log.col.flags"
  | "dns.log.col.latency"
  | "dns.log.col.name"
  | "dns.log.col.rcode"
  | "dns.log.col.resolution"
  | "dns.log.col.subqueries"
  | "dns.log.col.time"
  | "dns.log.col.transport"
  | "dns.log.col.type"
  | "dns.log.col.validation"
  | "dns.log.ede"
  | "dns.log.empty"
  | "dns.log.empty_filtered"
  | "dns.log.empty_validation"
  | "dns.log.figures"
  | "dns.log.filter.apply"
  | "dns.log.filter.client"
  | "dns.log.filter.client_invalid"
  | "dns.log.filter.client_placeholder"
  | "dns.log.filter.from"
  | "dns.log.filter.qname"
  | "dns.log.filter.qname_invalid"
  | "dns.log.filter.qname_placeholder"
  | "dns.log.filter.rcode"
  | "dns.log.filter.rcode_any"
  | "dns.log.filter.reset"
  | "dns.log.filter.until"
  | "dns.log.filter.until_invalid"
  | "dns.log.filter.validation"
  | "dns.log.filter.validation_any"
  | "dns.log.filter.validation_help"
  | "dns.log.latency"
  | "dns.log.newer"
  | "dns.log.no_node"
  | "dns.log.node"
  | "dns.log.node_label"
  | "dns.log.not_dns_body"
  | "dns.log.not_dns_title"
  | "dns.log.off_body"
  | "dns.log.off_link"
  | "dns.log.off_title"
  | "dns.log.older"
  | "dns.log.page"
  | "dns.log.partial"
  | "dns.log.pseudonym_hint"
  | "dns.log.refresh"
  | "dns.log.resolution.cache"
  | "dns.log.resolution.denial"
  | "dns.log.resolution.forward"
  | "dns.log.resolution.local"
  | "dns.log.resolution.policy"
  | "dns.log.resolution.recurse"
  | "dns.log.resolution.refused"
  | "dns.log.resolution.stale"
  | "dns.log.resolution.zone"
  | "dns.log.start"
  | "dns.log.started_toast"
  | "dns.log.stop"
  | "dns.log.stopped_body"
  | "dns.log.stopped_title"
  | "dns.log.stopped_toast"
  | "dns.log.sub"
  | "dns.log.switch_failed"
  | "dns.log.table"
  | "dns.log.title"
  | "dns.log.transport.doh"
  | "dns.log.transport.dot"
  | "dns.log.transport.tcp"
  | "dns.log.transport.udp"
  | "dns.log.validation.bogus"
  | "dns.log.validation.indeterminate"
  | "dns.log.validation.insecure"
  | "dns.log.validation.secure"
  | "dns.log.validation.unvalidated"
  | "dns.loss.directive"
  | "dns.loss.origin"
  | "dns.loss.outside"
  | "dns.loss.soa"
  | "dns.loss.unsupported_type"
  | "dns.nav.acls"
  | "dns.nav.blocking"
  | "dns.nav.cache"
  | "dns.nav.forwarders"
  | "dns.nav.keys"
  | "dns.nav.label"
  | "dns.nav.lists"
  | "dns.nav.log"
  | "dns.nav.recursion"
  | "dns.nav.views"
  | "dns.nav.zones"
  | "dns.node.col.address"
  | "dns.node.col.key"
  | "dns.node.col.transport"
  | "dns.node.col.workers"
  | "dns.node.doc"
  | "dns.node.forwarders_hint"
  | "dns.node.forwarders_link"
  | "dns.node.group.cache"
  | "dns.node.group.listeners"
  | "dns.node.group.log"
  | "dns.node.group.role"
  | "dns.node.group.tcp"
  | "dns.node.lede"
  | "dns.node.log_off"
  | "dns.node.no"
  | "dns.node.no_node"
  | "dns.node.no_role_body"
  | "dns.node.no_role_title"
  | "dns.node.not_served"
  | "dns.node.off_body"
  | "dns.node.problems"
  | "dns.node.refresh"
  | "dns.node.row.cache_bytes"
  | "dns.node.row.cache_entries"
  | "dns.node.row.cache_hit_ratio"
  | "dns.node.row.cache_hits"
  | "dns.node.row.cache_misses"
  | "dns.node.row.cache_stale"
  | "dns.node.row.lag"
  | "dns.node.row.log_client"
  | "dns.node.row.log_days"
  | "dns.node.row.log_dropped"
  | "dns.node.row.log_format"
  | "dns.node.row.log_sample"
  | "dns.node.row.log_size_mb"
  | "dns.node.row.log_state"
  | "dns.node.row.log_write_errors"
  | "dns.node.row.log_written"
  | "dns.node.row.rrsets"
  | "dns.node.row.serving"
  | "dns.node.row.socket_mode"
  | "dns.node.row.started"
  | "dns.node.row.tcp_open"
  | "dns.node.row.tcp_refused"
  | "dns.node.row.workers"
  | "dns.node.row.zones"
  | "dns.node.served"
  | "dns.node.title"
  | "dns.node.tls"
  | "dns.node.unknown"
  | "dns.node.yes"
  | "dns.nta.add"
  | "dns.nta.add_lede"
  | "dns.nta.add_title"
  | "dns.nta.check.lifetime"
  | "dns.nta.check.reason"
  | "dns.nta.check.reason_long"
  | "dns.nta.check.root"
  | "dns.nta.check.zone"
  | "dns.nta.col.actions"
  | "dns.nta.col.created"
  | "dns.nta.col.expires"
  | "dns.nta.col.reason"
  | "dns.nta.col.zone"
  | "dns.nta.created"
  | "dns.nta.delete"
  | "dns.nta.delete_body"
  | "dns.nta.delete_confirm"
  | "dns.nta.delete_title"
  | "dns.nta.deleted"
  | "dns.nta.expired"
  | "dns.nta.field.lifetime"
  | "dns.nta.field.lifetime_help"
  | "dns.nta.field.reason"
  | "dns.nta.field.reason_help"
  | "dns.nta.field.zone"
  | "dns.nta.lede"
  | "dns.nta.none"
  | "dns.op.add"
  | "dns.op.delete"
  | "dns.op.remove"
  | "dns.op.set"
  | "dns.origin.ad"
  | "dns.origin.dhcp"
  | "dns.origin.dnssec"
  | "dns.origin.dynamic"
  | "dns.origin.ipam"
  | "dns.origin.manual"
  | "dns.origin.transfer"
  | "dns.record.line_error"
  | "dns.records.any_origin"
  | "dns.records.any_type"
  | "dns.records.empty"
  | "dns.records.filter_label"
  | "dns.records.filter_placeholder"
  | "dns.records.label"
  | "dns.records.origin_filter"
  | "dns.records.type_filter"
  | "dns.recursion.counter.answered"
  | "dns.recursion.counter.budget"
  | "dns.recursion.counter.failure_cache_hits"
  | "dns.recursion.counter.local"
  | "dns.recursion.counter.servfail"
  | "dns.recursion.counter.subqueries"
  | "dns.recursion.counter.timeout"
  | "dns.recursion.counter.unwanted"
  | "dns.recursion.counters.title"
  | "dns.recursion.facts.title"
  | "dns.recursion.hints.date"
  | "dns.recursion.hints.shipped"
  | "dns.recursion.infra.names"
  | "dns.recursion.infra.of"
  | "dns.recursion.infra.servers"
  | "dns.recursion.infra.title"
  | "dns.recursion.infra.zones"
  | "dns.recursion.ms"
  | "dns.recursion.ntas.title"
  | "dns.recursion.prime.button"
  | "dns.recursion.prime.failed"
  | "dns.recursion.prime.sent"
  | "dns.recursion.priming.duration"
  | "dns.recursion.priming.expires"
  | "dns.recursion.priming.failed"
  | "dns.recursion.priming.last"
  | "dns.recursion.priming.never"
  | "dns.recursion.priming.ok"
  | "dns.recursion.problem.priming_failed"
  | "dns.recursion.problems.title"
  | "dns.recursion.root_hints"
  | "dns.recursion.roots.col.address"
  | "dns.recursion.roots.col.name"
  | "dns.recursion.roots.col.srtt"
  | "dns.recursion.roots.srtt_none"
  | "dns.recursion.roots.title"
  | "dns.recursion.status.loading"
  | "dns.recursion.status.no_node"
  | "dns.recursion.status.off.body"
  | "dns.recursion.status.off.title"
  | "dns.recursion.status.running"
  | "dns.recursion.status.title"
  | "dns.recursion.sub"
  | "dns.recursion.title"
  | "dns.recursion.trust_anchors.none"
  | "dns.recursion.trust_anchors.title"
  | "dns.recursion.validation.keys"
  | "dns.recursion.validation.no_keys"
  | "dns.recursion.validation.title"
  | "dns.resolution.default"
  | "dns.resolution.forward"
  | "dns.resolution.recurse"
  | "dns.resolution.refuse"
  | "dns.rrset.add_action"
  | "dns.rrset.add_records_title"
  | "dns.rrset.add_submit"
  | "dns.rrset.add_title"
  | "dns.rrset.delete_body"
  | "dns.rrset.delete_confirm"
  | "dns.rrset.delete_title"
  | "dns.rrset.edit_data"
  | "dns.rrset.edit_hint"
  | "dns.rrset.edit_ttl"
  | "dns.rrset.failed"
  | "dns.rrset.field.data"
  | "dns.rrset.field.data_help"
  | "dns.rrset.field.name"
  | "dns.rrset.field.name_help"
  | "dns.rrset.field.ttl"
  | "dns.rrset.field.type"
  | "dns.rrset.saved"
  | "dns.sec.bogus"
  | "dns.sec.indeterminate"
  | "dns.sec.insecure"
  | "dns.sec.secure"
  | "dns.sec.unvalidated"
  | "dns.serial.counter"
  | "dns.serial.counter_help"
  | "dns.serial.date_counter"
  | "dns.serial.date_counter_help"
  | "dns.serial.unixtime"
  | "dns.serial.unixtime_help"
  | "dns.settings.expire"
  | "dns.settings.minimum"
  | "dns.settings.ns"
  | "dns.settings.ns_required"
  | "dns.settings.refresh"
  | "dns.settings.retry"
  | "dns.settings.rname_help"
  | "dns.settings.save"
  | "dns.settings.saved"
  | "dns.settings.serial"
  | "dns.settings.soa"
  | "dns.settings.soa_body"
  | "dns.settings.source_invalid"
  | "dns.settings.source_primaries"
  | "dns.settings.source_primaries_body"
  | "dns.settings.source_stub"
  | "dns.settings.source_stub_body"
  | "dns.settings.ttl"
  | "dns.state.not_built_body"
  | "dns.state.not_built_title"
  | "dns.state.off_body"
  | "dns.state.off_link"
  | "dns.state.off_title"
  | "dns.takeover.body"
  | "dns.takeover.confirm"
  | "dns.takeover.tag"
  | "dns.takeover.title"
  | "dns.title"
  | "dns.transfer.address"
  | "dns.transfer.allow"
  | "dns.transfer.allow_add"
  | "dns.transfer.allow_help"
  | "dns.transfer.allow_none"
  | "dns.transfer.allow_remove"
  | "dns.transfer.body"
  | "dns.transfer.catalog"
  | "dns.transfer.catalog_help_other"
  | "dns.transfer.catalog_help_primary"
  | "dns.transfer.catalog_help_secondary"
  | "dns.transfer.check.address"
  | "dns.transfer.check.key"
  | "dns.transfer.check.port"
  | "dns.transfer.check.tls_name"
  | "dns.transfer.error.failed"
  | "dns.transfer.error.refused"
  | "dns.transfer.error.tsig"
  | "dns.transfer.expires"
  | "dns.transfer.from_primary"
  | "dns.transfer.key"
  | "dns.transfer.last_error"
  | "dns.transfer.last_success"
  | "dns.transfer.next_refresh"
  | "dns.transfer.not_queued"
  | "dns.transfer.notify"
  | "dns.transfer.notify_add"
  | "dns.transfer.notify_none"
  | "dns.transfer.notify_remove"
  | "dns.transfer.now"
  | "dns.transfer.port"
  | "dns.transfer.primary"
  | "dns.transfer.primary_add"
  | "dns.transfer.primary_remove"
  | "dns.transfer.queued"
  | "dns.transfer.records_readonly"
  | "dns.transfer.require_tsig"
  | "dns.transfer.require_tsig_help"
  | "dns.transfer.serial"
  | "dns.transfer.state"
  | "dns.transfer.state_idle"
  | "dns.transfer.state_running"
  | "dns.transfer.status"
  | "dns.transfer.title"
  | "dns.transfer.tls_name"
  | "dns.transfer.unavailable"
  | "dns.transfer.xot"
  | "dns.transfer.xot_help"
  | "dns.transfer.xot_short"
  | "dns.update.allow"
  | "dns.update.allow_add"
  | "dns.update.allow_help"
  | "dns.update.allow_none"
  | "dns.update.allow_remove"
  | "dns.update.body"
  | "dns.update.default_hardened"
  | "dns.update.default_home"
  | "dns.update.default_lab"
  | "dns.update.default_standard"
  | "dns.update.may_replace_ipam"
  | "dns.update.may_replace_ipam_help"
  | "dns.update.require_tsig"
  | "dns.update.require_tsig_hardened"
  | "dns.update.require_tsig_help"
  | "dns.update.require_tsig_lab"
  | "dns.update.title"
  | "dns.upstream.chosen"
  | "dns.upstream.chosen_long"
  | "dns.upstream.col.answered"
  | "dns.upstream.col.error"
  | "dns.upstream.col.ewma"
  | "dns.upstream.col.failed"
  | "dns.upstream.col.last"
  | "dns.upstream.col.p50"
  | "dns.upstream.col.p99"
  | "dns.upstream.col.rule"
  | "dns.upstream.col.state"
  | "dns.upstream.col.upstream"
  | "dns.upstream.counts"
  | "dns.upstream.last_error"
  | "dns.upstream.ms"
  | "dns.upstream.rule.default"
  | "dns.upstream.rule.stub"
  | "dns.upstream.section.doc"
  | "dns.upstream.section.empty"
  | "dns.upstream.section.link"
  | "dns.upstream.section.title"
  | "dns.upstream.state.degraded"
  | "dns.upstream.state.down"
  | "dns.upstream.state.unknown"
  | "dns.upstream.state.up"
  | "dns.upstream.times"
  | "dns.view.action.down"
  | "dns.view.action.up"
  | "dns.view.check.address"
  | "dns.view.check.description"
  | "dns.view.check.name"
  | "dns.view.check.name_long"
  | "dns.view.check.name_required"
  | "dns.view.check.no_acl"
  | "dns.view.check.no_scope"
  | "dns.view.check.no_zone"
  | "dns.view.check.prefix"
  | "dns.view.check.rule_empty"
  | "dns.view.check.rule_too_many"
  | "dns.view.check.scope_twice"
  | "dns.view.check.scope_weight"
  | "dns.view.check.scope_zone"
  | "dns.view.check.taken"
  | "dns.view.check.time"
  | "dns.view.check.too_many_rules"
  | "dns.view.check.too_many_scopes"
  | "dns.view.check.type"
  | "dns.view.col.name"
  | "dns.view.col.order"
  | "dns.view.col.recursion"
  | "dns.view.col.rules"
  | "dns.view.col.scopes"
  | "dns.view.create"
  | "dns.view.create_title"
  | "dns.view.created"
  | "dns.view.default.body"
  | "dns.view.default.title"
  | "dns.view.default_scopes"
  | "dns.view.delete_body"
  | "dns.view.delete_confirm"
  | "dns.view.delete_title"
  | "dns.view.deleted"
  | "dns.view.drag"
  | "dns.view.edit_title"
  | "dns.view.empty"
  | "dns.view.empty_body"
  | "dns.view.every_query"
  | "dns.view.field.name"
  | "dns.view.field.order"
  | "dns.view.field.order_at"
  | "dns.view.field.order_help"
  | "dns.view.field.order_last"
  | "dns.view.field.recursion"
  | "dns.view.field.recursion_help"
  | "dns.view.field.rules"
  | "dns.view.field.rules_help"
  | "dns.view.field.rules_none"
  | "dns.view.field.scope"
  | "dns.view.field.scopes"
  | "dns.view.field.scopes_help"
  | "dns.view.field.weight"
  | "dns.view.field.zone"
  | "dns.view.in_use"
  | "dns.view.move_down"
  | "dns.view.move_up"
  | "dns.view.moved"
  | "dns.view.recursion.default"
  | "dns.view.recursion.missing"
  | "dns.view.rule.add"
  | "dns.view.rule.from"
  | "dns.view.rule.help.client_subnet"
  | "dns.view.rule.help.interface"
  | "dns.view.rule.help.qname"
  | "dns.view.rule.help.qtype"
  | "dns.view.rule.help.time_of_day"
  | "dns.view.rule.help.transport"
  | "dns.view.rule.kind.client_subnet"
  | "dns.view.rule.kind.interface"
  | "dns.view.rule.kind.qname"
  | "dns.view.rule.kind.qtype"
  | "dns.view.rule.kind.time_of_day"
  | "dns.view.rule.kind.transport"
  | "dns.view.rule.kind_label"
  | "dns.view.rule.remove"
  | "dns.view.rule.to"
  | "dns.view.rule.words.client_subnet"
  | "dns.view.rule.words.interface"
  | "dns.view.rule.words.qname"
  | "dns.view.rule.words.qtype"
  | "dns.view.rule.words.time_of_day"
  | "dns.view.rule.words.transport"
  | "dns.view.save"
  | "dns.view.saved"
  | "dns.view.scope.add"
  | "dns.view.scope.no_zones"
  | "dns.view.scope.remove"
  | "dns.view.scope_chip"
  | "dns.view.share"
  | "dns.view.sub"
  | "dns.view.title"
  | "dns.view.transport.doh"
  | "dns.view.transport.dot"
  | "dns.view.transport.tcp"
  | "dns.view.transport.udp"
  | "dns.zone.create.action"
  | "dns.zone.create.done"
  | "dns.zone.create.primaries_required"
  | "dns.zone.create.reverse_notice"
  | "dns.zone.create.submit"
  | "dns.zone.create.title"
  | "dns.zone.delete.body"
  | "dns.zone.delete.confirm"
  | "dns.zone.delete.done"
  | "dns.zone.delete.title"
  | "dns.zone.field.description"
  | "dns.zone.field.kind"
  | "dns.zone.field.mname"
  | "dns.zone.field.name"
  | "dns.zone.field.name_help"
  | "dns.zone.field.name_servers"
  | "dns.zone.field.name_servers_help"
  | "dns.zone.field.primaries"
  | "dns.zone.field.primaries_help"
  | "dns.zone.field.rname"
  | "dns.zone.field.serial"
  | "dns.zone.field.ttl"
  | "dns.zone.not_served"
  | "dns.zone.not_served_hint"
  | "dns.zone.reverse"
  | "dns.zone.serial"
  | "dns.zone.stub"
  | "dns.zone.stub_hint"
  | "dns.zone.tab.dnssec"
  | "dns.zone.tab.history"
  | "dns.zone.tab.records"
  | "dns.zone.tab.settings"
  | "dns.zone.tabs"
  | "dns.zones.empty"
  | "dns.zones.empty_body"
  | "dns.zones.filter_label"
  | "dns.zones.filter_placeholder"
  | "dns.zones.sub"
  | "dns.zones.title"
  | "errors.audit.export.client_key"
  | "errors.audit.export.conflict"
  | "errors.audit.export.duplicate"
  | "errors.audit.export.file"
  | "errors.audit.export.host"
  | "errors.audit.export.invalid"
  | "errors.audit.export.name"
  | "errors.audit.export.not_found"
  | "errors.audit.export.pem"
  | "errors.audit.export.port"
  | "errors.audit.export.range"
  | "errors.audit.export.required"
  | "errors.audit.export.test_target"
  | "errors.audit.export.tls_unused"
  | "errors.audit.export.too_many"
  | "errors.audit.export.unknown_sink"
  | "errors.auth.break_glass.hardware_key_only"
  | "errors.auth.challenge_invalid"
  | "errors.auth.conflict"
  | "errors.auth.forbidden"
  | "errors.auth.invalid_credentials"
  | "errors.auth.password.breached"
  | "errors.auth.password.context_specific"
  | "errors.auth.password.incorrect"
  | "errors.auth.password.invalid_characters"
  | "errors.auth.password.pattern_mismatch"
  | "errors.auth.password.pin_digits_only"
  | "errors.auth.password.policy"
  | "errors.auth.password.too_long"
  | "errors.auth.password.too_short"
  | "errors.auth.password.trivial"
  | "errors.auth.session_expired"
  | "errors.auth.setup.closed"
  | "errors.auth.setup.invalid_host_name"
  | "errors.auth.setup.token_invalid"
  | "errors.auth.step_up_required"
  | "errors.auth.throttled"
  | "errors.auth.token.lifetime_exceeded"
  | "errors.auth.totp.already_enrolled"
  | "errors.auth.totp.code_mismatch"
  | "errors.auth.totp.not_enrolled"
  | "errors.auth.unauthenticated"
  | "errors.auth.webauthn.attestation_required"
  | "errors.auth.webauthn.backup_eligible_refused"
  | "errors.auth.webauthn.credential_exists"
  | "errors.auth.webauthn.origin_mismatch"
  | "errors.auth.webauthn.rp_id_mismatch"
  | "errors.auth.webauthn.user_verification"
  | "errors.client.aborted"
  | "errors.client.bad_response"
  | "errors.client.network"
  | "errors.cluster.enrolment.lifetime"
  | "errors.cluster.enrolment.not_found"
  | "errors.cluster.enrolment.random"
  | "errors.cluster.enrolment.roles"
  | "errors.cluster.member.changing"
  | "errors.cluster.member.even_voters"
  | "errors.cluster.member.last_voter"
  | "errors.cluster.member.no_successor"
  | "errors.cluster.member.not_caught_up"
  | "errors.cluster.member.not_found"
  | "errors.cluster.member.not_learner"
  | "errors.cluster.no_quorum"
  | "errors.cluster.node.conflict"
  | "errors.cluster.node.name"
  | "errors.cluster.node.name_taken"
  | "errors.cluster.node.not_found"
  | "errors.cluster.single"
  | "errors.connect.guardrail.management_client"
  | "errors.connect.guardrail.management_port"
  | "errors.connect.guardrail.protected_client"
  | "errors.connect.guardrail.protected_network"
  | "errors.connect.guardrail.protected_port"
  | "errors.connect.guardrail.protected_vlan"
  | "errors.connect.guardrail.uplink"
  | "errors.connect.instance.call_timeout"
  | "errors.connect.instance.conflict"
  | "errors.connect.instance.disabled"
  | "errors.connect.instance.name"
  | "errors.connect.instance.name_taken"
  | "errors.connect.instance.not_found"
  | "errors.connect.instance.nothing_to_run"
  | "errors.connect.instance.poll_interval"
  | "errors.connect.plugin.exited"
  | "errors.connect.plugin.unavailable"
  | "errors.connect.plugin.unknown"
  | "errors.connect.plugin.unusable"
  | "errors.connect.run.failed"
  | "errors.connect.secret.missing"
  | "errors.connect.secret.not_found"
  | "errors.connect.secret.not_operator"
  | "errors.connect.secret.undeclared"
  | "errors.connect.settings.invalid"
  | "errors.connect.timeout"
  | "errors.connect.unreachable"
  | "errors.connect.verify_mismatch"
  | "errors.connect.writes_disabled"
  | "errors.dhcp.class.in_use"
  | "errors.dhcp.class.invalid"
  | "errors.dhcp.class.not_found"
  | "errors.dhcp.ddns.invalid"
  | "errors.dhcp.exclusion.invalid"
  | "errors.dhcp.exclusion.not_found"
  | "errors.dhcp.export.format"
  | "errors.dhcp.filter.exists"
  | "errors.dhcp.filter.invalid"
  | "errors.dhcp.filter.not_found"
  | "errors.dhcp.lease.not_found"
  | "errors.dhcp.lease.state"
  | "errors.dhcp.lease_times.invalid"
  | "errors.dhcp.module.disabled"
  | "errors.dhcp.node.not_dhcp"
  | "errors.dhcp.option.code_reserved"
  | "errors.dhcp.option.invalid"
  | "errors.dhcp.option.unknown"
  | "errors.dhcp.option_def.exists"
  | "errors.dhcp.option_def.in_use"
  | "errors.dhcp.option_def.not_found"
  | "errors.dhcp.policy.invalid"
  | "errors.dhcp.policy.not_found"
  | "errors.dhcp.pool.not_found"
  | "errors.dhcp.pool.not_pool"
  | "errors.dhcp.pool.outside"
  | "errors.dhcp.reservation.conflict"
  | "errors.dhcp.reservation.no_identity"
  | "errors.dhcp.scope.attached"
  | "errors.dhcp.scope.exists"
  | "errors.dhcp.scope.invalid"
  | "errors.dhcp.scope.not_found"
  | "errors.dhcp.scope.not_network"
  | "errors.dhcp.settings.invalid"
  | "errors.dhcp.shared_network.in_use"
  | "errors.dhcp.shared_network.invalid"
  | "errors.dhcp.shared_network.not_found"
  | "errors.dhcp.store_refused"
  | "errors.dns.acl.in_use"
  | "errors.dns.acl.not_found"
  | "errors.dns.blocking.log_off"
  | "errors.dns.default_zone.invalid"
  | "errors.dns.forwarder.invalid"
  | "errors.dns.forwarder.not_found"
  | "errors.dns.key.exists"
  | "errors.dns.key.not_found"
  | "errors.dns.list.invalid"
  | "errors.dns.list.not_found"
  | "errors.dns.module.disabled"
  | "errors.dns.node.not_dns"
  | "errors.dns.nta.invalid"
  | "errors.dns.nta.not_found"
  | "errors.dns.record.conflict"
  | "errors.dns.record.invalid"
  | "errors.dns.record.origin"
  | "errors.dns.recursion.disabled"
  | "errors.dns.transfer.refused"
  | "errors.dns.trust_anchor.invalid"
  | "errors.dns.trust_anchor.not_found"
  | "errors.dns.trust_anchor.root_protected"
  | "errors.dns.update.refused"
  | "errors.dns.view.in_use"
  | "errors.dns.view.invalid"
  | "errors.dns.view.not_found"
  | "errors.dns.zone.exists"
  | "errors.dns.zone.invalid"
  | "errors.dns.zone.not_found"
  | "errors.dns.zone.secondary"
  | "errors.dns.zonefile.invalid"
  | "errors.generic.client"
  | "errors.generic.field"
  | "errors.generic.not_implemented"
  | "errors.generic.server"
  | "errors.generic.unexpected"
  | "errors.i18n.pack.argument"
  | "errors.i18n.pack.bidi"
  | "errors.i18n.pack.control"
  | "errors.i18n.pack.default_language"
  | "errors.i18n.pack.duplicate"
  | "errors.i18n.pack.empty"
  | "errors.i18n.pack.icu"
  | "errors.i18n.pack.invalid"
  | "errors.i18n.pack.key"
  | "errors.i18n.pack.markup"
  | "errors.i18n.pack.metadata"
  | "errors.i18n.pack.no_candidate"
  | "errors.i18n.pack.not_found"
  | "errors.i18n.pack.not_previewed"
  | "errors.i18n.pack.root"
  | "errors.i18n.pack.src_lang"
  | "errors.i18n.pack.structure"
  | "errors.i18n.pack.tag"
  | "errors.i18n.pack.too_large"
  | "errors.i18n.pack.too_many_units"
  | "errors.i18n.pack.trg_lang"
  | "errors.i18n.pack.version"
  | "errors.i18n.pack.xml"
  | "errors.i18n.unavailable"
  | "errors.i18n.upload.empty"
  | "errors.i18n.upload.malformed"
  | "errors.import.apply.failed"
  | "errors.import.conflict.kept"
  | "errors.import.credentials.vault_required"
  | "errors.import.expired"
  | "errors.import.mapping.invalid"
  | "errors.import.not_found"
  | "errors.import.plan.blocked"
  | "errors.import.preview.stale"
  | "errors.import.state.conflict"
  | "errors.import.unavailable"
  | "errors.import.upload.empty"
  | "errors.import.upload.lost"
  | "errors.import.upload.malformed"
  | "errors.import.upload.too_large"
  | "errors.import.upload.unreadable"
  | "errors.import.upload.unsupported"
  | "errors.ipam.address.duplicate"
  | "errors.ipam.address.full"
  | "errors.ipam.address.in_dhcp_pool"
  | "errors.ipam.address.in_range"
  | "errors.ipam.address.in_supernet"
  | "errors.ipam.address.network_or_broadcast"
  | "errors.ipam.address.no_prefix"
  | "errors.ipam.adoption.invalid"
  | "errors.ipam.bulk.too_large"
  | "errors.ipam.bulk.wrong_collection"
  | "errors.ipam.contended"
  | "errors.ipam.host.lock_manual_only"
  | "errors.ipam.host.locked"
  | "errors.ipam.host.reservation_identifier"
  | "errors.ipam.id_taken"
  | "errors.ipam.idempotency_mismatch"
  | "errors.ipam.immutable"
  | "errors.ipam.in_use"
  | "errors.ipam.interface.duplicate_mac"
  | "errors.ipam.invalid_cursor"
  | "errors.ipam.invalid_filter"
  | "errors.ipam.job.failed"
  | "errors.ipam.move.controller_unavailable"
  | "errors.ipam.move.host_part_taken"
  | "errors.ipam.move.l2_changed"
  | "errors.ipam.move.l2_refused"
  | "errors.ipam.move.plan_changed"
  | "errors.ipam.move.unmanaged"
  | "errors.ipam.name_taken"
  | "errors.ipam.not_deleted"
  | "errors.ipam.not_found"
  | "errors.ipam.object_deleted"
  | "errors.ipam.parent_status"
  | "errors.ipam.plan.stale"
  | "errors.ipam.plan.unacknowledged"
  | "errors.ipam.prefix.becomes_supernet"
  | "errors.ipam.prefix.full"
  | "errors.ipam.prefix.has_children"
  | "errors.ipam.prefix.has_ranges"
  | "errors.ipam.prefix.host_bits"
  | "errors.ipam.prefix.nibble_boundary"
  | "errors.ipam.prefix.overlap"
  | "errors.ipam.prefix.overlaps_range"
  | "errors.ipam.prefix.resize_orphans"
  | "errors.ipam.proposal.batch_empty"
  | "errors.ipam.proposal.batch_too_large"
  | "errors.ipam.proposal.not_found"
  | "errors.ipam.proposal.not_open"
  | "errors.ipam.proposal.nothing_to_apply"
  | "errors.ipam.proposal.revision_mismatch"
  | "errors.ipam.range.covers_reservation"
  | "errors.ipam.range.not_in_network"
  | "errors.ipam.range.outside_prefix"
  | "errors.ipam.range.overlap"
  | "errors.ipam.reconciler.unavailable"
  | "errors.ipam.reference_missing"
  | "errors.ipam.revision_mismatch"
  | "errors.ipam.site.cycle"
  | "errors.ipam.status.transition"
  | "errors.ipam.topology.not_found"
  | "errors.ipam.topology.unavailable"
  | "errors.ipam.unavailable"
  | "errors.ipam.validation"
  | "errors.ipam.vlan.controller_changed"
  | "errors.ipam.vlan.controller_disabled"
  | "errors.ipam.vlan.controller_unknown"
  | "errors.ipam.vlan.controllers_unavailable"
  | "errors.ipam.vlan.duplicate"
  | "errors.ipam.vlan.invalid_request"
  | "errors.modules.conflict"
  | "errors.modules.pinned"
  | "errors.modules.store"
  | "errors.modules.unavailable"
  | "errors.node.config.invalid"
  | "errors.node.config.not_a_probe"
  | "errors.node.config.revision_mismatch"
  | "errors.node.config.secret"
  | "errors.node.config.vault_unavailable"
  | "errors.node.roles.controller"
  | "errors.node.roles.empty"
  | "errors.node.roles.last_controller"
  | "errors.node.roles.pinned"
  | "errors.node.roles.revision_mismatch"
  | "errors.node.roles.store"
  | "errors.node.roles.unsupported"
  | "errors.queue.changed"
  | "errors.queue.full"
  | "errors.queue.io"
  | "errors.queue.not_a_person"
  | "errors.queue.not_found"
  | "errors.queue.not_isolated"
  | "errors.queue.not_queueable"
  | "errors.queue.too_large"
  | "errors.queue.unavailable"
  | "errors.remote.address_unknown"
  | "errors.remote.interface_unknown"
  | "errors.scan.job.invalid"
  | "errors.scan.job.no_probe"
  | "errors.scan.job.not_found"
  | "errors.scan.job.target"
  | "errors.scan.stopped"
  | "errors.settings.pin_coupling"
  | "errors.sys.csrf_rejected"
  | "errors.sys.internal"
  | "errors.sys.invalid_request"
  | "errors.sys.not_implemented"
  | "errors.sys.not_ready"
  | "errors.sys.rate_limited"
  | "errors.sys.shutting_down"
  | "errors.sys.store.no_quorum"
  | "errors.sys.store.precondition_failed"
  | "errors.update.check_failed"
  | "errors.update.check_off"
  | "errors.update.check_refused"
  | "errors.update.check_timeout"
  | "errors.update.check_unavailable"
  | "errors.update.checksum_mismatch"
  | "errors.update.fetch_failed"
  | "errors.update.install_blocked"
  | "errors.update.io"
  | "errors.update.job"
  | "errors.update.job_failed"
  | "errors.update.manifest.invalid"
  | "errors.update.manifest.json"
  | "errors.update.manifest.project"
  | "errors.update.manifest.schema"
  | "errors.update.manifest.too_large"
  | "errors.update.not_executable"
  | "errors.update.not_newer"
  | "errors.update.signature_unverified"
  | "errors.update.size_mismatch"
  | "errors.update.source_mismatch"
  | "errors.update.store"
  | "errors.update.unavailable"
  | "errors.update.upload_failed"
  | "errors.update.version_mismatch"
  | "errors.update.version_unknown"
  | "errors.upgrade.attempt_unreadable"
  | "errors.upgrade.copy_target"
  | "errors.upgrade.crashed"
  | "errors.upgrade.format_mismatch"
  | "errors.upgrade.format_newer"
  | "errors.upgrade.in_use"
  | "errors.upgrade.io"
  | "errors.upgrade.marker_invalid"
  | "errors.upgrade.migration_failed"
  | "errors.upgrade.migration_missing"
  | "errors.upgrade.no_store"
  | "errors.upgrade.not_confirmed"
  | "errors.upgrade.not_ready"
  | "errors.upgrade.open_failed"
  | "errors.upgrade.refused"
  | "errors.upgrade.store"
  | "errors.users.last_administrator"
  | "errors.users.name_taken"
  | "errors.users.not_found"
  | "errors.vault.host_credentials.conflict"
  | "errors.vault.host_credentials.secret_missing"
  | "errors.vault.pin_coupling"
  | "errors.vault.reveal.host_required"
  | "errors.vault.reveal.not_bound"
  | "errors.vault.reveal.rate_limited"
  | "errors.vault.secret.conflict"
  | "errors.vault.secret.in_use"
  | "errors.vault.secret.invalid"
  | "errors.vault.secret.not_found"
  | "errors.vault.secret.not_revealable"
  | "errors.vault.secret.not_text"
  | "errors.vault.secret.too_large"
  | "grid.actionbar.label"
  | "grid.actionbar.selected"
  | "grid.actions"
  | "grid.columns.button"
  | "grid.columns.move_down"
  | "grid.columns.move_up"
  | "grid.columns.reset"
  | "grid.columns.title"
  | "grid.deleted.exclude"
  | "grid.deleted.include"
  | "grid.deleted.label"
  | "grid.deleted.only"
  | "grid.density.comfortable"
  | "grid.density.compact"
  | "grid.density.dense"
  | "grid.density.label"
  | "grid.empty.filtered"
  | "grid.empty.title"
  | "grid.filter.invalid"
  | "grid.loading"
  | "grid.loading_more"
  | "grid.more"
  | "grid.row_actions"
  | "grid.rows"
  | "grid.saving"
  | "grid.select_all"
  | "grid.select_row"
  | "grid.selected"
  | "grid.selection.clear"
  | "guardrails.add"
  | "guardrails.col.actions"
  | "guardrails.col.kind"
  | "guardrails.col.path"
  | "guardrails.dialog.body"
  | "guardrails.dialog.submit"
  | "guardrails.dialog.title"
  | "guardrails.error.duplicate"
  | "guardrails.error.invalid"
  | "guardrails.error.mac"
  | "guardrails.error.parallel"
  | "guardrails.error.port"
  | "guardrails.error.reference"
  | "guardrails.error.vid"
  | "guardrails.field.device"
  | "guardrails.field.kind"
  | "guardrails.field.mac"
  | "guardrails.field.network"
  | "guardrails.field.port"
  | "guardrails.field.vid"
  | "guardrails.help.device"
  | "guardrails.help.mac"
  | "guardrails.help.network"
  | "guardrails.help.port"
  | "guardrails.help.vid"
  | "guardrails.kind.client"
  | "guardrails.kind.network"
  | "guardrails.kind.port"
  | "guardrails.kind.vlan"
  | "guardrails.lede"
  | "guardrails.note"
  | "guardrails.parallel.help"
  | "guardrails.parallel.label"
  | "guardrails.parallel.limits"
  | "guardrails.path.port"
  | "guardrails.path.vlan"
  | "guardrails.paths.heading"
  | "guardrails.paths.none"
  | "guardrails.reloaded"
  | "guardrails.remove"
  | "guardrails.remove_label"
  | "guardrails.saved"
  | "guardrails.title"
  | "hosts.addresses.none"
  | "hosts.addresses.title"
  | "hosts.bulk.lock_title"
  | "hosts.bulk.mode_title"
  | "hosts.bulk.unlock_title"
  | "hosts.col.addresses"
  | "hosts.col.client_id"
  | "hosts.col.duid"
  | "hosts.col.interface"
  | "hosts.connect.failed"
  | "hosts.connect.hint"
  | "hosts.connect.rdp"
  | "hosts.connect.rdp_port"
  | "hosts.connect.ssh"
  | "hosts.connect.ssh_port"
  | "hosts.connect.target"
  | "hosts.connect.title"
  | "hosts.connect.user"
  | "hosts.connect.user_placeholder"
  | "hosts.credentials.audit_hint"
  | "hosts.credentials.bind"
  | "hosts.credentials.bind_title"
  | "hosts.credentials.bound"
  | "hosts.credentials.col.actions"
  | "hosts.credentials.col.name"
  | "hosts.credentials.col.revealed"
  | "hosts.credentials.col.role"
  | "hosts.credentials.col.user"
  | "hosts.credentials.copy"
  | "hosts.credentials.empty"
  | "hosts.credentials.field.role"
  | "hosts.credentials.field.secret"
  | "hosts.credentials.manage"
  | "hosts.credentials.never_revealed"
  | "hosts.credentials.none_free"
  | "hosts.credentials.option"
  | "hosts.credentials.revealed_by"
  | "hosts.credentials.role.admin"
  | "hosts.credentials.role.other"
  | "hosts.credentials.role.rdp"
  | "hosts.credentials.role.ssh"
  | "hosts.credentials.role.web"
  | "hosts.credentials.title"
  | "hosts.credentials.unbind"
  | "hosts.credentials.unbind_body"
  | "hosts.credentials.unbind_failed"
  | "hosts.credentials.unbind_label"
  | "hosts.credentials.unbind_title"
  | "hosts.credentials.unbound"
  | "hosts.crumbs"
  | "hosts.dns.col.address"
  | "hosts.dns.col.forward"
  | "hosts.dns.col.reverse"
  | "hosts.dns.no_records"
  | "hosts.dns.no_zone"
  | "hosts.dns.origin.ad"
  | "hosts.dns.origin.dhcp"
  | "hosts.dns.origin.dnssec"
  | "hosts.dns.origin.dynamic"
  | "hosts.dns.origin.ipam"
  | "hosts.dns.origin.manual"
  | "hosts.dns.origin.transfer"
  | "hosts.dns.title"
  | "hosts.do.create"
  | "hosts.do.lock"
  | "hosts.do.set_mode"
  | "hosts.do.toggle_lock"
  | "hosts.do.unlock"
  | "hosts.empty"
  | "hosts.facts.title"
  | "hosts.filter.label"
  | "hosts.filter.locked"
  | "hosts.filter.placeholder"
  | "hosts.form.create"
  | "hosts.form.create_title"
  | "hosts.form.created"
  | "hosts.form.default_tenant"
  | "hosts.form.duid_invalid"
  | "hosts.form.edit_title"
  | "hosts.form.first_interface"
  | "hosts.form.hex_invalid"
  | "hosts.form.iface_create"
  | "hosts.form.iface_create_title"
  | "hosts.form.iface_edit_title"
  | "hosts.form.iface_name_required"
  | "hosts.form.iface_saved"
  | "hosts.form.lock"
  | "hosts.form.mac_invalid"
  | "hosts.form.name_invalid"
  | "hosts.form.none"
  | "hosts.form.save"
  | "hosts.form.saved"
  | "hosts.in_several"
  | "hosts.interfaces.add"
  | "hosts.interfaces.empty"
  | "hosts.interfaces.title"
  | "hosts.jobs.all"
  | "hosts.jobs.none"
  | "hosts.jobs.title"
  | "hosts.lock_failed"
  | "hosts.locked"
  | "hosts.mac.none"
  | "hosts.mac.several"
  | "hosts.mode.change"
  | "hosts.mode.change_title"
  | "hosts.mode.changed"
  | "hosts.mode.current"
  | "hosts.mode.locked_note"
  | "hosts.mode.title"
  | "hosts.not_found"
  | "hosts.observations.empty"
  | "hosts.observations.open"
  | "hosts.observations.title"
  | "hosts.undo"
  | "hosts.unlocked"
  | "hosts.warn.both"
  | "hosts.warn.duid"
  | "hosts.warn.identifier_title"
  | "hosts.warn.mac"
  | "import.action.create"
  | "import.action.kept"
  | "import.action.unchanged"
  | "import.action.update"
  | "import.changes.first_rows"
  | "import.changes.group"
  | "import.changes.title"
  | "import.columns.column"
  | "import.columns.credential_option"
  | "import.columns.header"
  | "import.columns.interface"
  | "import.columns.interface_placeholder"
  | "import.columns.label"
  | "import.columns.samples"
  | "import.columns.shapes"
  | "import.columns.suggested"
  | "import.columns.target"
  | "import.columns.target_of"
  | "import.columns.vault"
  | "import.conflict.fail"
  | "import.conflict.skip"
  | "import.conflict.update"
  | "import.credentials.not_allowed"
  | "import.credentials.pin_enrol"
  | "import.credentials.reason.forbidden"
  | "import.credentials.reason.pin_coupling"
  | "import.credentials.reason.step_up_required"
  | "import.credentials.reason.unauthenticated"
  | "import.credentials.reason.vault_unavailable"
  | "import.credentials.statement"
  | "import.credentials.title"
  | "import.discard"
  | "import.export.addresses"
  | "import.export.body"
  | "import.export.hosts"
  | "import.export.prefixes"
  | "import.export.title"
  | "import.issue.header_row"
  | "import.issue.network_cidr"
  | "import.issue.no_address"
  | "import.kind.host"
  | "import.kind.index"
  | "import.kind.list"
  | "import.kind.network"
  | "import.kind.skip"
  | "import.loss.address.duplicate"
  | "import.loss.address.is_broadcast"
  | "import.loss.address.is_network"
  | "import.loss.address.missing"
  | "import.loss.address.no_prefix"
  | "import.loss.address.range_too_large"
  | "import.loss.address.unparsable"
  | "import.loss.column.unmapped"
  | "import.loss.conflict.kept"
  | "import.loss.counts"
  | "import.loss.credential.duplicate"
  | "import.loss.credential.no_host"
  | "import.loss.credential.numeric"
  | "import.loss.credential.skipped"
  | "import.loss.credential.suspicious"
  | "import.loss.custom.undefined"
  | "import.loss.detail"
  | "import.loss.download"
  | "import.loss.host.conflict"
  | "import.loss.host.locked"
  | "import.loss.name.invalid"
  | "import.loss.name.missing"
  | "import.loss.name.normalized"
  | "import.loss.none"
  | "import.loss.prefix.host_bits"
  | "import.loss.prefix.in_network"
  | "import.loss.prefix.proposed"
  | "import.loss.prefix.unlisted"
  | "import.loss.prefix.unparsable"
  | "import.loss.severity"
  | "import.loss.sheet.empty"
  | "import.loss.sheet.skipped"
  | "import.loss.title"
  | "import.loss.value.invalid"
  | "import.loss.what"
  | "import.loss.where"
  | "import.loss.whole"
  | "import.mapping.files"
  | "import.mapping.preview"
  | "import.mapping.tab"
  | "import.mapping.text"
  | "import.mask.addresses"
  | "import.mask.index"
  | "import.mask.name"
  | "import.mask.row_count"
  | "import.mask.user"
  | "import.options.conflict"
  | "import.options.credentials"
  | "import.options.credentials_help"
  | "import.options.credentials_import"
  | "import.options.tenant"
  | "import.options.tenant_default"
  | "import.options.title"
  | "import.options.vrf"
  | "import.options.vrf_default"
  | "import.preview.apply"
  | "import.preview.back"
  | "import.preview.blocked"
  | "import.preview.counts"
  | "import.preview.credentials_kind"
  | "import.preview.kind"
  | "import.preview.rows_free"
  | "import.preview.rows_imported"
  | "import.preview.rows_skipped"
  | "import.preview.rows_total"
  | "import.preview.steps"
  | "import.preview.summary"
  | "import.preview.supernet_step"
  | "import.preview.warnings"
  | "import.proposals.body"
  | "import.proposals.holds"
  | "import.proposals.title"
  | "import.result.again"
  | "import.result.back"
  | "import.result.count"
  | "import.result.created"
  | "import.result.done"
  | "import.result.failed"
  | "import.result.more"
  | "import.result.progress"
  | "import.result.rolled_back"
  | "import.result.running"
  | "import.result.show_all"
  | "import.rows.count"
  | "import.rows.items"
  | "import.rows.more"
  | "import.rows.none"
  | "import.rows.nothing"
  | "import.rows.status"
  | "import.rows.status_free"
  | "import.rows.status_imported"
  | "import.rows.status_skipped"
  | "import.rows.title"
  | "import.rows.where"
  | "import.severity.error"
  | "import.severity.info"
  | "import.severity.warning"
  | "import.shape.address"
  | "import.shape.cidr"
  | "import.shape.count"
  | "import.shape.duid"
  | "import.shape.empty"
  | "import.shape.mac"
  | "import.shape.number"
  | "import.shape.range"
  | "import.shape.text"
  | "import.sheet.cidr"
  | "import.sheet.header_row"
  | "import.sheet.kind"
  | "import.sheet.listed"
  | "import.sheet.no_header"
  | "import.sheet.roles_from"
  | "import.sheet.summary"
  | "import.sheets.errors"
  | "import.sheets.free"
  | "import.sheets.imported"
  | "import.sheets.kind"
  | "import.sheets.notes"
  | "import.sheets.rows"
  | "import.sheets.sheet"
  | "import.sheets.skipped"
  | "import.sheets.title"
  | "import.sheets.warnings"
  | "import.step.apply"
  | "import.step.done"
  | "import.step.mapping"
  | "import.step.preview"
  | "import.step.upload"
  | "import.steps"
  | "import.sub"
  | "import.target.address"
  | "import.target.alarm_crit"
  | "import.target.alarm_warn"
  | "import.target.alloc"
  | "import.target.client_id"
  | "import.target.description"
  | "import.target.dns_name"
  | "import.target.duid"
  | "import.target.host"
  | "import.target.ignore"
  | "import.target.interface"
  | "import.target.interfaces"
  | "import.target.lock"
  | "import.target.login"
  | "import.target.mac"
  | "import.target.mask"
  | "import.target.mode"
  | "import.target.password"
  | "import.target.prefix"
  | "import.target.role"
  | "import.target.site"
  | "import.target.status"
  | "import.target.tags"
  | "import.target.tenant"
  | "import.target.vlan"
  | "import.target.vlan_name"
  | "import.target.vrf"
  | "import.title"
  | "import.upload.body"
  | "import.upload.choose"
  | "import.upload.drop"
  | "import.upload.files"
  | "import.upload.remove"
  | "import.upload.size"
  | "import.upload.start"
  | "import.upload.title"
  | "import.upload.too_large"
  | "import.upload.unsupported"
  | "ipam.action.create"
  | "ipam.action.delete"
  | "ipam.action.lock"
  | "ipam.action.remove"
  | "ipam.action.restore"
  | "ipam.action.unlock"
  | "ipam.action.update"
  | "ipam.address.claim_failed"
  | "ipam.address.claimed"
  | "ipam.address.facts"
  | "ipam.address.in_several"
  | "ipam.address.interface"
  | "ipam.address.not_found"
  | "ipam.address.renamed"
  | "ipam.address.unassigned"
  | "ipam.addresses.claim"
  | "ipam.addresses.dns_hint"
  | "ipam.addresses.empty"
  | "ipam.addresses.filter_label"
  | "ipam.addresses.filter_placeholder"
  | "ipam.addresses.filter_terms"
  | "ipam.addresses.free"
  | "ipam.addresses.grid"
  | "ipam.addresses.none"
  | "ipam.addresses.show_free"
  | "ipam.adoption.clear"
  | "ipam.adoption.cleared"
  | "ipam.adoption.edit"
  | "ipam.adoption.error.sightings"
  | "ipam.adoption.error.vendor_length"
  | "ipam.adoption.error.vendors_count"
  | "ipam.adoption.host_mode"
  | "ipam.adoption.host_mode_help"
  | "ipam.adoption.host_mode_on"
  | "ipam.adoption.min_sightings"
  | "ipam.adoption.min_sightings_help"
  | "ipam.adoption.mode.adopt_all"
  | "ipam.adoption.mode.adopt_hosts"
  | "ipam.adoption.mode.manual"
  | "ipam.adoption.mode_hint.adopt_all"
  | "ipam.adoption.mode_hint.adopt_hosts"
  | "ipam.adoption.mode_hint.manual"
  | "ipam.adoption.mode_label"
  | "ipam.adoption.never"
  | "ipam.adoption.only_pools"
  | "ipam.adoption.only_pools_on"
  | "ipam.adoption.proposals"
  | "ipam.adoption.save"
  | "ipam.adoption.saved"
  | "ipam.adoption.set"
  | "ipam.adoption.sightings_on"
  | "ipam.adoption.source_default"
  | "ipam.adoption.source_inherited"
  | "ipam.adoption.source_own"
  | "ipam.adoption.stale"
  | "ipam.adoption.title"
  | "ipam.adoption.updated_by"
  | "ipam.adoption.vendors"
  | "ipam.adoption.vendors_help"
  | "ipam.adoption.vendors_on"
  | "ipam.alarm.critical"
  | "ipam.alarm.normal"
  | "ipam.alarm.warning"
  | "ipam.cfdef.applies_required"
  | "ipam.cfdef.applies_to"
  | "ipam.cfdef.create"
  | "ipam.cfdef.create_title"
  | "ipam.cfdef.delete_title"
  | "ipam.cfdef.deleted"
  | "ipam.cfdef.edit_title"
  | "ipam.cfdef.empty"
  | "ipam.cfdef.key"
  | "ipam.cfdef.key_help"
  | "ipam.cfdef.key_invalid"
  | "ipam.cfdef.no"
  | "ipam.cfdef.options"
  | "ipam.cfdef.options_help"
  | "ipam.cfdef.options_required"
  | "ipam.cfdef.required"
  | "ipam.cfdef.required_col"
  | "ipam.cfdef.type"
  | "ipam.cfdef.yes"
  | "ipam.col.address"
  | "ipam.col.created"
  | "ipam.col.description"
  | "ipam.col.dns_name"
  | "ipam.col.host"
  | "ipam.col.lease"
  | "ipam.col.mac"
  | "ipam.col.mode"
  | "ipam.col.name"
  | "ipam.col.prefix"
  | "ipam.col.range"
  | "ipam.col.role"
  | "ipam.col.site"
  | "ipam.col.status"
  | "ipam.col.tag"
  | "ipam.col.tags"
  | "ipam.col.tenant"
  | "ipam.col.updated"
  | "ipam.col.utilization"
  | "ipam.col.vid"
  | "ipam.col.vlan"
  | "ipam.col.vni"
  | "ipam.col.vrf"
  | "ipam.command.focus_tree"
  | "ipam.custom_kind.boolean"
  | "ipam.custom_kind.date"
  | "ipam.custom_kind.integer"
  | "ipam.custom_kind.select"
  | "ipam.custom_kind.text"
  | "ipam.custom_kind.url"
  | "ipam.delete.cascade"
  | "ipam.delete.done"
  | "ipam.delete.title"
  | "ipam.delete.undo"
  | "ipam.delete.undo_failed"
  | "ipam.do.delete"
  | "ipam.do.edit"
  | "ipam.do.export_csv"
  | "ipam.do.history"
  | "ipam.do.move"
  | "ipam.do.next_free_address"
  | "ipam.do.next_free_prefix"
  | "ipam.do.open"
  | "ipam.do.reserve"
  | "ipam.do.restore"
  | "ipam.field.alarm_both"
  | "ipam.field.alarm_crit"
  | "ipam.field.alarm_help"
  | "ipam.field.alarm_order"
  | "ipam.field.alarm_range"
  | "ipam.field.alarm_warn"
  | "ipam.field.choose"
  | "ipam.field.cidr"
  | "ipam.field.cidr_help"
  | "ipam.field.cidr_invalid"
  | "ipam.field.cidr_required"
  | "ipam.field.custom"
  | "ipam.field.dns_help"
  | "ipam.field.dns_invalid"
  | "ipam.field.first"
  | "ipam.field.inside_prefix"
  | "ipam.field.integer_invalid"
  | "ipam.field.ip"
  | "ipam.field.ip_invalid"
  | "ipam.field.ip_renumber_help"
  | "ipam.field.ip_required"
  | "ipam.field.last"
  | "ipam.field.last_before_first"
  | "ipam.field.lease_help"
  | "ipam.field.lease_number"
  | "ipam.field.lease_range"
  | "ipam.field.lease_unit"
  | "ipam.field.none"
  | "ipam.field.option_invalid"
  | "ipam.field.required"
  | "ipam.field.tag_invalid"
  | "ipam.field.tag_remove"
  | "ipam.field.tags_help"
  | "ipam.field.unit_days"
  | "ipam.field.unit_hours"
  | "ipam.field.unit_minutes"
  | "ipam.field.url_invalid"
  | "ipam.flag.deleted"
  | "ipam.flag.locked"
  | "ipam.flag.locked_hint"
  | "ipam.form.create_kind"
  | "ipam.form.create_title"
  | "ipam.form.created"
  | "ipam.form.edit_title"
  | "ipam.form.role_auto"
  | "ipam.form.role_help"
  | "ipam.form.save_changes"
  | "ipam.form.save_title"
  | "ipam.form.saved"
  | "ipam.form.use_network"
  | "ipam.history.empty"
  | "ipam.history.label"
  | "ipam.history.more"
  | "ipam.history.title"
  | "ipam.kind.address"
  | "ipam.kind.custom_field"
  | "ipam.kind.host"
  | "ipam.kind.interface"
  | "ipam.kind.prefix"
  | "ipam.kind.range"
  | "ipam.kind.site"
  | "ipam.kind.tenant"
  | "ipam.kind.vlan"
  | "ipam.kind.vrf"
  | "ipam.kind_title.address"
  | "ipam.kind_title.custom_field"
  | "ipam.kind_title.host"
  | "ipam.kind_title.interface"
  | "ipam.kind_title.prefix"
  | "ipam.kind_title.range"
  | "ipam.kind_title.site"
  | "ipam.kind_title.tenant"
  | "ipam.kind_title.vlan"
  | "ipam.kind_title.vrf"
  | "ipam.meter.title"
  | "ipam.meter.value"
  | "ipam.mode.dynamic"
  | "ipam.mode.reserved"
  | "ipam.mode.static"
  | "ipam.mode.unmanaged"
  | "ipam.mode_hint.dynamic"
  | "ipam.mode_hint.reserved"
  | "ipam.mode_hint.static"
  | "ipam.mode_hint.unmanaged"
  | "ipam.move.choose_body"
  | "ipam.move.choose_title"
  | "ipam.move.dragging"
  | "ipam.move.no_target"
  | "ipam.move.step.cleanup"
  | "ipam.move.step.controller_client"
  | "ipam.move.step.controller_port"
  | "ipam.move.step.dhcp"
  | "ipam.move.step.intent"
  | "ipam.move.task.device"
  | "ipam.move.task.dhcp"
  | "ipam.move.task.dns"
  | "ipam.move.task.generic"
  | "ipam.move.task.l2"
  | "ipam.move.task.l2_client"
  | "ipam.move.task.l2_network"
  | "ipam.move.task.l2_port"
  | "ipam.move.task.l2_port_vlan"
  | "ipam.move.task.l2_refused"
  | "ipam.move.task.l2_shared_port"
  | "ipam.move.task.l2_ssid"
  | "ipam.move.task.l2_vlan"
  | "ipam.move.task.observe"
  | "ipam.move.title"
  | "ipam.nav.addresses"
  | "ipam.nav.custom_fields"
  | "ipam.nav.hosts"
  | "ipam.nav.import"
  | "ipam.nav.label"
  | "ipam.nav.networks"
  | "ipam.nav.reconcile"
  | "ipam.nav.sites"
  | "ipam.nav.tags"
  | "ipam.nav.tenancy"
  | "ipam.nav.vlans"
  | "ipam.next_free.address"
  | "ipam.next_free.address_title"
  | "ipam.next_free.create"
  | "ipam.next_free.find_address"
  | "ipam.next_free.find_prefix"
  | "ipam.next_free.from"
  | "ipam.next_free.length"
  | "ipam.next_free.length_help"
  | "ipam.next_free.length_invalid"
  | "ipam.next_free.length_required"
  | "ipam.next_free.prefix"
  | "ipam.next_free.prefix_title"
  | "ipam.next_free.suggest"
  | "ipam.next_free.whole_network"
  | "ipam.overview.empty_hint"
  | "ipam.overview.grid"
  | "ipam.overview.label"
  | "ipam.overview.sub"
  | "ipam.plan.ack"
  | "ipam.plan.ack_needed"
  | "ipam.plan.change.create"
  | "ipam.plan.change.delete"
  | "ipam.plan.change.lock"
  | "ipam.plan.change.remove"
  | "ipam.plan.change.restore"
  | "ipam.plan.change.unlock"
  | "ipam.plan.change.update"
  | "ipam.plan.changes"
  | "ipam.plan.col.action"
  | "ipam.plan.col.fields"
  | "ipam.plan.col.object"
  | "ipam.plan.derived"
  | "ipam.plan.heading"
  | "ipam.plan.nothing"
  | "ipam.plan.open_job"
  | "ipam.plan.previewing"
  | "ipam.plan.stale"
  | "ipam.plan.summary_line"
  | "ipam.prefix.alarm"
  | "ipam.prefix.alarm_value"
  | "ipam.prefix.alloc"
  | "ipam.prefix.alloc_highest"
  | "ipam.prefix.alloc_lowest"
  | "ipam.prefix.children_grid"
  | "ipam.prefix.crumbs"
  | "ipam.prefix.dns_reverse"
  | "ipam.prefix.dns_reverse_default"
  | "ipam.prefix.dns_reverse_help"
  | "ipam.prefix.dns_reverse_managed"
  | "ipam.prefix.dns_reverse_off"
  | "ipam.prefix.in_several"
  | "ipam.prefix.no_children"
  | "ipam.prefix.not_found"
  | "ipam.prefix.ranges_grid"
  | "ipam.prefix.tab.addresses"
  | "ipam.prefix.tab.adoption"
  | "ipam.prefix.tab.children"
  | "ipam.prefix.tab.history"
  | "ipam.prefix.tab.ranges"
  | "ipam.prefix.tabs"
  | "ipam.prefix.usage"
  | "ipam.prefix_role.network"
  | "ipam.prefix_role.supernet"
  | "ipam.range.add"
  | "ipam.range.empty"
  | "ipam.range_role.dhcp_pool"
  | "ipam.range_role.infrastructure"
  | "ipam.range_role.reserved"
  | "ipam.reconcile.col.address"
  | "ipam.reconcile.col.details"
  | "ipam.reconcile.col.winner"
  | "ipam.reconcile.count"
  | "ipam.reconcile.dns_forward"
  | "ipam.reconcile.dns_ptr"
  | "ipam.reconcile.empty"
  | "ipam.reconcile.filter.all_kinds"
  | "ipam.reconcile.filter.all_prefixes"
  | "ipam.reconcile.filter.host"
  | "ipam.reconcile.filter.host_apply"
  | "ipam.reconcile.filter.host_chip"
  | "ipam.reconcile.filter.host_placeholder"
  | "ipam.reconcile.filter.host_unknown"
  | "ipam.reconcile.filter.kind"
  | "ipam.reconcile.filter.label"
  | "ipam.reconcile.filter.prefix"
  | "ipam.reconcile.filter.remove_host"
  | "ipam.reconcile.host_open"
  | "ipam.reconcile.host_unavailable"
  | "ipam.reconcile.kind.conflict"
  | "ipam.reconcile.kind.ghost"
  | "ipam.reconcile.kind.orphan"
  | "ipam.reconcile.kind.ptr_mismatch"
  | "ipam.reconcile.kind.rogue"
  | "ipam.reconcile.kind_help.conflict"
  | "ipam.reconcile.kind_help.ghost"
  | "ipam.reconcile.kind_help.orphan"
  | "ipam.reconcile.kind_help.ptr_mismatch"
  | "ipam.reconcile.kind_help.rogue"
  | "ipam.reconcile.last_seen"
  | "ipam.reconcile.more"
  | "ipam.reconcile.no_winner"
  | "ipam.reconcile.os"
  | "ipam.reconcile.os_guess"
  | "ipam.reconcile.os_source"
  | "ipam.reconcile.proposal"
  | "ipam.reconcile.retry"
  | "ipam.reconcile.rule.forward_record"
  | "ipam.reconcile.rule.intent_managed"
  | "ipam.reconcile.rule.lease_dynamic"
  | "ipam.reconcile.rule.manual_record"
  | "ipam.reconcile.rule.never_automatic"
  | "ipam.reconcile.rule.newest_sighting"
  | "ipam.reconcile.rule.orphan_rule"
  | "ipam.reconcile.sub"
  | "ipam.reconcile.title"
  | "ipam.reconcile.truth.dns"
  | "ipam.reconcile.truth.intent"
  | "ipam.reconcile.truth.lease"
  | "ipam.reconcile.truth.scan"
  | "ipam.reconcile.vendors"
  | "ipam.reconcile.winner"
  | "ipam.reconcile.wins"
  | "ipam.restore.done"
  | "ipam.restore.title"
  | "ipam.scope.label"
  | "ipam.scope.option"
  | "ipam.site.ad_site"
  | "ipam.site.ad_site_help"
  | "ipam.site.create"
  | "ipam.site.create_title"
  | "ipam.site.edit_title"
  | "ipam.site.empty"
  | "ipam.site.filter_label"
  | "ipam.site.filter_placeholder"
  | "ipam.site.parent"
  | "ipam.status.active"
  | "ipam.status.deprecated"
  | "ipam.status.planned"
  | "ipam.status.reserved"
  | "ipam.tags.by_kind"
  | "ipam.tags.count"
  | "ipam.tags.empty"
  | "ipam.tags.show"
  | "ipam.tags.sub"
  | "ipam.tenancy.created"
  | "ipam.tenancy.filter_placeholder"
  | "ipam.tenancy.name_required"
  | "ipam.tenancy.none"
  | "ipam.tenancy.save"
  | "ipam.tenancy.saved"
  | "ipam.tenant.create"
  | "ipam.tenant.create_title"
  | "ipam.tenant.default_zone"
  | "ipam.tenant.default_zone_help"
  | "ipam.tenant.default_zone_none"
  | "ipam.tenant.edit_title"
  | "ipam.tenant.empty"
  | "ipam.tenant.filter_label"
  | "ipam.tenant.title"
  | "ipam.tree.add"
  | "ipam.tree.drag_hint"
  | "ipam.tree.drop_hint"
  | "ipam.tree.drop_refused"
  | "ipam.tree.empty"
  | "ipam.tree.filter"
  | "ipam.tree.key_grid"
  | "ipam.tree.key_tree"
  | "ipam.tree.label"
  | "ipam.tree.supernet"
  | "ipam.vlan.create"
  | "ipam.vlan.create_title"
  | "ipam.vlan.edit_title"
  | "ipam.vlan.empty"
  | "ipam.vlan.filter_label"
  | "ipam.vlan.filter_placeholder"
  | "ipam.vlan.job.title"
  | "ipam.vlan.prefixes.empty"
  | "ipam.vlan.prefixes.intro"
  | "ipam.vlan.prefixes.list_label"
  | "ipam.vlan.prefixes.loading"
  | "ipam.vlan.prefixes.row_action"
  | "ipam.vlan.prefixes.title"
  | "ipam.vlan.provision.action"
  | "ipam.vlan.provision.connector"
  | "ipam.vlan.provision.connector_any"
  | "ipam.vlan.provision.connector_help"
  | "ipam.vlan.provision.controller_auto"
  | "ipam.vlan.provision.controller_auto_help"
  | "ipam.vlan.provision.controller_label"
  | "ipam.vlan.provision.controller_manual"
  | "ipam.vlan.provision.controller_manual_help"
  | "ipam.vlan.provision.controller_none"
  | "ipam.vlan.provision.dhcp_off"
  | "ipam.vlan.provision.dhcp_relay"
  | "ipam.vlan.provision.dhcp_relay_help"
  | "ipam.vlan.provision.diff.absent"
  | "ipam.vlan.provision.diff.now"
  | "ipam.vlan.provision.diff.planned"
  | "ipam.vlan.provision.diff.removed"
  | "ipam.vlan.provision.diff.setting"
  | "ipam.vlan.provision.diff_heading"
  | "ipam.vlan.provision.diff_none"
  | "ipam.vlan.provision.hint.by_hand"
  | "ipam.vlan.provision.intro_existing"
  | "ipam.vlan.provision.intro_new"
  | "ipam.vlan.provision.mode.automatic"
  | "ipam.vlan.provision.mode.manual"
  | "ipam.vlan.provision.mode.unchanged"
  | "ipam.vlan.provision.mode_hint.automatic"
  | "ipam.vlan.provision.mode_hint.manual"
  | "ipam.vlan.provision.mode_hint.unchanged"
  | "ipam.vlan.provision.network_legend"
  | "ipam.vlan.provision.network_name"
  | "ipam.vlan.provision.network_name_help"
  | "ipam.vlan.provision.network_name_long"
  | "ipam.vlan.provision.network_name_placeholder"
  | "ipam.vlan.provision.notes_heading"
  | "ipam.vlan.provision.preview"
  | "ipam.vlan.provision.preview_intro"
  | "ipam.vlan.provision.read_at"
  | "ipam.vlan.provision.read_only"
  | "ipam.vlan.provision.reason.controller_ambiguous"
  | "ipam.vlan.provision.reason.controller_read_only"
  | "ipam.vlan.provision.reason.manual_requested"
  | "ipam.vlan.provision.reason.no_controller"
  | "ipam.vlan.provision.reason.unknown"
  | "ipam.vlan.provision.relay_invalid"
  | "ipam.vlan.provision.relay_too_many"
  | "ipam.vlan.provision.row_action"
  | "ipam.vlan.provision.start"
  | "ipam.vlan.provision.started"
  | "ipam.vlan.provision.step.activate"
  | "ipam.vlan.provision.step.intent_both"
  | "ipam.vlan.provision.step.intent_prefix"
  | "ipam.vlan.provision.step.intent_vlan"
  | "ipam.vlan.provision.step.manual"
  | "ipam.vlan.provision.step.network"
  | "ipam.vlan.provision.step.network_check"
  | "ipam.vlan.provision.steps_heading"
  | "ipam.vlan.provision.title_existing"
  | "ipam.vlan.provision.title_new"
  | "ipam.vlan.provision.vlan_existing"
  | "ipam.vlan.provision.vlan_new"
  | "ipam.vlan.provision.vrf_default"
  | "ipam.vlan.provision.warning.controller_ambiguous"
  | "ipam.vlan.provision.warning.controller_read_only"
  | "ipam.vlan.provision.warning.network_changes"
  | "ipam.vlan.provision.will_exist"
  | "ipam.vlan.provision.with_prefix"
  | "ipam.vlan.provision.with_prefix_help"
  | "ipam.vlan.step.activate"
  | "ipam.vlan.step.controller"
  | "ipam.vlan.step.intent"
  | "ipam.vlan.task.network"
  | "ipam.vlan.vid_invalid"
  | "ipam.vlan.vni_help"
  | "ipam.vlan.vni_invalid"
  | "ipam.vrf.create"
  | "ipam.vrf.create_title"
  | "ipam.vrf.default_tenant"
  | "ipam.vrf.edit_title"
  | "ipam.vrf.empty"
  | "ipam.vrf.filter_label"
  | "ipam.vrf.rd"
  | "ipam.vrf.rd_help"
  | "ipam.vrf.title"
  | "jobs.action.cancel"
  | "jobs.action.complete"
  | "jobs.action.fail"
  | "jobs.action.finish_cancel"
  | "jobs.action.finish_rollback"
  | "jobs.action.resume"
  | "jobs.action.roll_back"
  | "jobs.action.start"
  | "jobs.action.wait"
  | "jobs.cancel.body_active"
  | "jobs.cancel.body_queued"
  | "jobs.cancel.button"
  | "jobs.cancel.confirm"
  | "jobs.cancel.done"
  | "jobs.cancel.keep"
  | "jobs.cancel.note"
  | "jobs.cancel.requested"
  | "jobs.cancel.title"
  | "jobs.checklist.empty"
  | "jobs.checklist.group"
  | "jobs.checklist.heading"
  | "jobs.checklist.hint"
  | "jobs.checklist.loading"
  | "jobs.checklist.mark_done"
  | "jobs.checklist.open"
  | "jobs.col.by"
  | "jobs.col.created"
  | "jobs.col.finished"
  | "jobs.col.job"
  | "jobs.col.kind"
  | "jobs.col.progress"
  | "jobs.col.state"
  | "jobs.col.step"
  | "jobs.complete.button"
  | "jobs.complete.done"
  | "jobs.crumbs"
  | "jobs.deadline.in"
  | "jobs.deadline.line"
  | "jobs.deadline.passed"
  | "jobs.duration.d"
  | "jobs.duration.h"
  | "jobs.duration.min"
  | "jobs.duration.s"
  | "jobs.empty.body"
  | "jobs.empty.filtered"
  | "jobs.empty.title"
  | "jobs.error.cancelled"
  | "jobs.error.invalid_transition"
  | "jobs.error.not_found"
  | "jobs.error.note_too_long"
  | "jobs.error.query_invalid"
  | "jobs.error.step_deadline_passed"
  | "jobs.error.step_failed"
  | "jobs.error.step_interrupted"
  | "jobs.error.step_invalid_params"
  | "jobs.error.step_not_compensable"
  | "jobs.error.step_not_found"
  | "jobs.error.step_panicked"
  | "jobs.error.step_timeout"
  | "jobs.error.timeout"
  | "jobs.error.unknown_step_kind"
  | "jobs.event.cancel_requested"
  | "jobs.event.claimed"
  | "jobs.event.step"
  | "jobs.event.submitted"
  | "jobs.fact.created"
  | "jobs.fact.finished"
  | "jobs.fact.group"
  | "jobs.fact.group_limit"
  | "jobs.fact.group_link"
  | "jobs.fact.id"
  | "jobs.fact.not_yet"
  | "jobs.fact.started"
  | "jobs.fact.targets"
  | "jobs.fact.timeout"
  | "jobs.fact.timeout_hint"
  | "jobs.fact.when_by"
  | "jobs.filter.group"
  | "jobs.filter.kind"
  | "jobs.filter.label"
  | "jobs.filter.placeholder"
  | "jobs.filter.remove"
  | "jobs.filter.target"
  | "jobs.flag.cancel_requested"
  | "jobs.group.heading"
  | "jobs.group.limit"
  | "jobs.group.not_moved.count"
  | "jobs.group.not_moved.heading"
  | "jobs.group.not_moved.hint"
  | "jobs.group.not_moved.no_reason"
  | "jobs.group.summary"
  | "jobs.kind.address"
  | "jobs.kind.custom_field"
  | "jobs.kind.host"
  | "jobs.kind.import"
  | "jobs.kind.interface"
  | "jobs.kind.prefix"
  | "jobs.kind.range"
  | "jobs.kind.site"
  | "jobs.kind.tenant"
  | "jobs.kind.vlan"
  | "jobs.kind.vrf"
  | "jobs.l2.absent"
  | "jobs.l2.col.after"
  | "jobs.l2.col.before"
  | "jobs.l2.col.path"
  | "jobs.l2.diff"
  | "jobs.l2.no_undo"
  | "jobs.l2.planned"
  | "jobs.l2.receipt"
  | "jobs.l2.reverted"
  | "jobs.l2.title"
  | "jobs.l2.unchanged"
  | "jobs.l2.undo_hint"
  | "jobs.l2.unknown_write"
  | "jobs.l2.warnings"
  | "jobs.log.change"
  | "jobs.log.col.by"
  | "jobs.log.col.change"
  | "jobs.log.col.event"
  | "jobs.log.col.note"
  | "jobs.log.col.step"
  | "jobs.log.col.time"
  | "jobs.log.heading"
  | "jobs.log.label"
  | "jobs.needs_you"
  | "jobs.no_right"
  | "jobs.note.counter"
  | "jobs.note.help"
  | "jobs.note.label"
  | "jobs.note.over"
  | "jobs.observe.address_seen"
  | "jobs.observe.address_seen_mac"
  | "jobs.observe.lease"
  | "jobs.observe.other"
  | "jobs.observe.waiting"
  | "jobs.problem.detail"
  | "jobs.problem.title"
  | "jobs.progress"
  | "jobs.state.cancelled"
  | "jobs.state.cancelled_rolled_back"
  | "jobs.state.failed"
  | "jobs.state.queued"
  | "jobs.state.rolled_back"
  | "jobs.state.rolling_back"
  | "jobs.state.running"
  | "jobs.state.succeeded"
  | "jobs.state.waiting"
  | "jobs.step.cleanup"
  | "jobs.step.device_manual"
  | "jobs.step.dhcp_manual"
  | "jobs.step.dns_import_apply"
  | "jobs.step.dns_import_parse"
  | "jobs.step.dns_list_compile"
  | "jobs.step.dns_list_fetch"
  | "jobs.step.dns_list_read"
  | "jobs.step.dns_manual"
  | "jobs.step.import_apply_chunk"
  | "jobs.step.import_parse"
  | "jobs.step.import_plan"
  | "jobs.step.ipam_apply"
  | "jobs.step.ipam_intent"
  | "jobs.step.l2_move"
  | "jobs.step.observe"
  | "jobs.step.sys_update_check"
  | "jobs.step.sys_update_fetch"
  | "jobs.step.sys_update_switch"
  | "jobs.step.sys_update_verify"
  | "jobs.step_position"
  | "jobs.step_state.compensated"
  | "jobs.step_state.compensating"
  | "jobs.step_state.compensation_failed"
  | "jobs.step_state.done"
  | "jobs.step_state.failed"
  | "jobs.step_state.pending"
  | "jobs.step_state.running"
  | "jobs.step_state.skipped"
  | "jobs.step_state.waiting_for_manual"
  | "jobs.step_state.waiting_for_observation"
  | "jobs.stepmeta.attempts"
  | "jobs.stepmeta.finished"
  | "jobs.stepmeta.started"
  | "jobs.stepname.cleanup"
  | "jobs.stepname.device_manual"
  | "jobs.stepname.dhcp_manual"
  | "jobs.stepname.dns_manual"
  | "jobs.stepname.ipam_intent"
  | "jobs.stepname.ipam_move_cleanup"
  | "jobs.stepname.ipam_move_controller"
  | "jobs.stepname.ipam_move_device"
  | "jobs.stepname.ipam_move_dhcp"
  | "jobs.stepname.ipam_move_dns"
  | "jobs.stepname.ipam_move_intent"
  | "jobs.stepname.ipam_move_l2"
  | "jobs.stepname.ipam_move_observe"
  | "jobs.stepname.ipam_vlan_activate"
  | "jobs.stepname.ipam_vlan_controller"
  | "jobs.stepname.ipam_vlan_intent"
  | "jobs.stepname.ipam_vlan_manual"
  | "jobs.stepname.l2_move"
  | "jobs.stepname.observe"
  | "jobs.stepname.sys_update_check"
  | "jobs.stepname.sys_update_fetch"
  | "jobs.stepname.sys_update_switch"
  | "jobs.stepname.sys_update_verify"
  | "jobs.steps.heading"
  | "jobs.steps.label"
  | "jobs.sub"
  | "jobs.tag.undo"
  | "jobs.targets"
  | "jobs.task.dhcp_release"
  | "jobs.task.dhcp_reserve"
  | "jobs.task.dns_revert"
  | "jobs.task.dns_update"
  | "jobs.title"
  | "jobs.title.dns_import"
  | "jobs.title.dns_list_fetch"
  | "jobs.title.dns_list_upload"
  | "jobs.title.import_apply"
  | "jobs.title.ipam_apply"
  | "jobs.title.move"
  | "jobs.title.update_install"
  | "jobs.undo.step"
  | "jobs.undo.step_named"
  | "jobs.view.active"
  | "jobs.view.all"
  | "jobs.view.failed"
  | "jobs.view.finished"
  | "languages.action.activate"
  | "languages.action.discard"
  | "languages.action.preview"
  | "languages.action.remove"
  | "languages.action.report"
  | "languages.action.revert"
  | "languages.action.template"
  | "languages.action.template_of"
  | "languages.action.template_short"
  | "languages.activate.hint"
  | "languages.built_in_texts"
  | "languages.col.actions"
  | "languages.col.active"
  | "languages.col.candidate"
  | "languages.col.language"
  | "languages.col.status"
  | "languages.confirm.activate.body"
  | "languages.confirm.activate.ok"
  | "languages.confirm.activate.title"
  | "languages.confirm.discard.body"
  | "languages.confirm.discard.ok"
  | "languages.confirm.discard.title"
  | "languages.confirm.remove.body"
  | "languages.confirm.remove.ok"
  | "languages.confirm.remove.title"
  | "languages.confirm.revert.body"
  | "languages.confirm.revert.ok"
  | "languages.confirm.revert.title"
  | "languages.lead"
  | "languages.list.heading"
  | "languages.none"
  | "languages.origin.data_dir"
  | "languages.preview.bar"
  | "languages.preview.end"
  | "languages.preview.open"
  | "languages.report.at_line"
  | "languages.report.author"
  | "languages.report.col.key"
  | "languages.report.col.line"
  | "languages.report.col.problem"
  | "languages.report.col.severity"
  | "languages.report.complete"
  | "languages.report.extra"
  | "languages.report.heading"
  | "languages.report.missing"
  | "languages.report.more"
  | "languages.report.none"
  | "languages.report.problems"
  | "languages.report.problems_label"
  | "languages.report.stale"
  | "languages.severity.error"
  | "languages.severity.warning"
  | "languages.status.active"
  | "languages.status.built_in"
  | "languages.status.previewed"
  | "languages.status.uploaded"
  | "languages.sub"
  | "languages.title"
  | "languages.toast.activated"
  | "languages.toast.discarded"
  | "languages.toast.preview"
  | "languages.toast.removed"
  | "languages.toast.reverted"
  | "languages.upload.done"
  | "languages.upload.file"
  | "languages.upload.heading"
  | "languages.upload.help"
  | "languages.upload.submit"
  | "languages.version.by"
  | "languages.version.label"
  | "languages.version.not_previewed"
  | "languages.version.percent"
  | "languages.version.previewed"
  | "metrics.bars"
  | "metrics.dhcp.ack"
  | "metrics.dhcp.ack_hint"
  | "metrics.dhcp.ack_idle"
  | "metrics.dhcp.active"
  | "metrics.dhcp.active_hint"
  | "metrics.dhcp.ddns"
  | "metrics.dhcp.ddns_hint"
  | "metrics.dhcp.ddns_outcome.failed"
  | "metrics.dhcp.ddns_outcome.refused"
  | "metrics.dhcp.ddns_outcome.removed"
  | "metrics.dhcp.ddns_outcome.written"
  | "metrics.dhcp.decline_row"
  | "metrics.dhcp.leases"
  | "metrics.dhcp.leases_hint"
  | "metrics.dhcp.nak_row"
  | "metrics.dhcp.naks"
  | "metrics.dhcp.naks_hint"
  | "metrics.dhcp.pools"
  | "metrics.dhcp.pools_hint"
  | "metrics.dhcp.pools_none"
  | "metrics.dns.answers"
  | "metrics.dns.answers_hint"
  | "metrics.dns.blocked"
  | "metrics.dns.blocked_hint"
  | "metrics.dns.blocked_none"
  | "metrics.dns.cache"
  | "metrics.dns.cache_hint"
  | "metrics.dns.cache_window"
  | "metrics.dns.encrypted"
  | "metrics.dns.encrypted_hint"
  | "metrics.dns.encrypted_none"
  | "metrics.dns.log_dropped"
  | "metrics.dns.queries"
  | "metrics.dns.queries_hint"
  | "metrics.dns.queries_idle"
  | "metrics.dns.rate"
  | "metrics.dns.rcode_other"
  | "metrics.dns.subqueries"
  | "metrics.dns.subqueries_hint"
  | "metrics.dns.upstreams"
  | "metrics.dns.upstreams_hint"
  | "metrics.dns.upstreams_idle"
  | "metrics.dns.validation"
  | "metrics.dns.validation_bogus"
  | "metrics.dns.validation_hint"
  | "metrics.dns.validation_insecure"
  | "metrics.dns.validation_secure"
  | "metrics.group.controller"
  | "metrics.group.dhcp"
  | "metrics.group.dns"
  | "metrics.group.host"
  | "metrics.host.cpu"
  | "metrics.host.cpu_hint"
  | "metrics.host.cpu_none"
  | "metrics.host.disk"
  | "metrics.host.disk_hint"
  | "metrics.host.disk_low"
  | "metrics.host.disk_none"
  | "metrics.host.memory"
  | "metrics.host.memory_hint"
  | "metrics.host.memory_none"
  | "metrics.host.unit_gib"
  | "metrics.raft.lag"
  | "metrics.raft.node"
  | "metrics.raft.stale"
  | "metrics.raft.unsupported"
  | "metrics.sparkline"
  | "metrics.sub"
  | "metrics.tile.commit"
  | "metrics.tile.commit_hint"
  | "metrics.tile.commit_idle"
  | "metrics.tile.ingest"
  | "metrics.tile.ingest_hint"
  | "metrics.tile.jobs"
  | "metrics.tile.jobs_hint"
  | "metrics.tile.nodes"
  | "metrics.tile.nodes_hint"
  | "metrics.tile.nodes_hint_unknown"
  | "metrics.tile.raft"
  | "metrics.tile.raft_hint"
  | "metrics.tile.requests"
  | "metrics.tile.requests_hint"
  | "metrics.tile.requests_idle"
  | "metrics.tile.sse"
  | "metrics.tile.sse_hint"
  | "metrics.tile.store"
  | "metrics.tile.store_hint"
  | "metrics.tile.store_memory"
  | "metrics.title"
  | "metrics.unit.bytes"
  | "metrics.unit.ms"
  | "metrics.unit.per_second"
  | "metrics.unit.percent"
  | "metrics.waiting"
  | "move.checklist"
  | "move.checklist_foot"
  | "move.checklist_sum"
  | "move.col.device"
  | "move.col.dns"
  | "move.col.include"
  | "move.col.ip"
  | "move.col.l2"
  | "move.col.manual"
  | "move.confirm"
  | "move.devices"
  | "move.group.cleanup"
  | "move.group.device_manual"
  | "move.group.dhcp_manual"
  | "move.group.dns_manual"
  | "move.group.ipam_intent"
  | "move.group.l2_move"
  | "move.group.observe"
  | "move.heading"
  | "move.heading_vlan"
  | "move.include"
  | "move.included"
  | "move.keys.include"
  | "move.keys.move"
  | "move.keys.steps"
  | "move.l2.action.client_vlan"
  | "move.l2.action.client_vlan_ssid"
  | "move.l2.action.manual"
  | "move.l2.action.port_profile"
  | "move.l2.action.refused"
  | "move.l2.action.shared"
  | "move.l2.action.unchanged"
  | "move.l2.controller"
  | "move.l2.controller_read_only"
  | "move.l2.diff"
  | "move.l2.no_controller"
  | "move.l2.note.carry_unknown"
  | "move.l2.note.link_flap"
  | "move.l2.note.no_undo"
  | "move.l2.note.reconnect"
  | "move.l2.note.tagged"
  | "move.l2.reason.already_there"
  | "move.l2.reason.controller_ambiguous"
  | "move.l2.reason.controller_unavailable"
  | "move.l2.reason.join_ssid"
  | "move.l2.reason.no_controller"
  | "move.l2.reason.no_mac"
  | "move.l2.reason.no_network"
  | "move.l2.reason.no_port"
  | "move.l2.reason.no_profile"
  | "move.l2.reason.no_ssid"
  | "move.l2.reason.no_vlan"
  | "move.l2.reason.not_seen"
  | "move.l2.reason.read_only"
  | "move.l2.reason.refused"
  | "move.l2.reason.same_interface"
  | "move.l2.reason.shared_port"
  | "move.l2.ssids"
  | "move.l2.through"
  | "move.legend.auto"
  | "move.legend.manual"
  | "move.nothing"
  | "move.open_jobs"
  | "move.other_host_part"
  | "move.parallelism"
  | "move.parallelism_help"
  | "move.phase1_body"
  | "move.phase1_title"
  | "move.plan_changed"
  | "move.preview_only"
  | "move.reason.host_part_outside"
  | "move.reason.host_part_reserved"
  | "move.reason.host_part_taken"
  | "move.rollback_note"
  | "move.show_all_steps"
  | "move.show_steps"
  | "move.start"
  | "move.started"
  | "move.step.cleanup"
  | "move.step.device_manual"
  | "move.step.dhcp_manual"
  | "move.step.dhcp_manual_no_mac"
  | "move.step.dns_manual"
  | "move.step.ipam_intent"
  | "move.step.l2_controller"
  | "move.step.l2_move"
  | "move.step.l2_move_novlan"
  | "move.step.observe"
  | "move.tasks"
  | "move.tickets"
  | "move.tickets_hint"
  | "move.timeout"
  | "move.timeout.default"
  | "move.timeout.lease"
  | "move.timeout.request"
  | "move.timeout_auto"
  | "move.title"
  | "node.role.controller"
  | "node.role.dhcp"
  | "node.role.dns"
  | "node.role.probe"
  | "nodes.action.enrol"
  | "nodes.cert.days_left"
  | "nodes.cert.expired"
  | "nodes.col.address"
  | "nodes.col.certificate"
  | "nodes.col.connected"
  | "nodes.col.id"
  | "nodes.col.last_seen"
  | "nodes.col.major"
  | "nodes.col.name"
  | "nodes.col.roles"
  | "nodes.col.version"
  | "nodes.empty.body"
  | "nodes.empty.title"
  | "nodes.enrol.command"
  | "nodes.enrol.copied_command"
  | "nodes.enrol.copied_token"
  | "nodes.enrol.copy_blocked"
  | "nodes.enrol.copy_command"
  | "nodes.enrol.copy_token"
  | "nodes.enrol.create"
  | "nodes.enrol.created_title"
  | "nodes.enrol.done"
  | "nodes.enrol.fingerprint"
  | "nodes.enrol.fingerprint_help"
  | "nodes.enrol.intro"
  | "nodes.enrol.lifetime"
  | "nodes.enrol.lifetime_help"
  | "nodes.enrol.name"
  | "nodes.enrol.name_help"
  | "nodes.enrol.name_rule"
  | "nodes.enrol.next"
  | "nodes.enrol.once"
  | "nodes.enrol.role_hint.dhcp"
  | "nodes.enrol.role_hint.dns"
  | "nodes.enrol.role_hint.probe"
  | "nodes.enrol.roles"
  | "nodes.enrol.roles_required"
  | "nodes.enrol.title"
  | "nodes.enrol.token"
  | "nodes.enrol.vrf"
  | "nodes.enrol.vrf_default"
  | "nodes.enrol.vrf_help"
  | "nodes.grid.label"
  | "nodes.lifetime.s3600"
  | "nodes.lifetime.s604800"
  | "nodes.lifetime.s86400"
  | "nodes.lifetime.s900"
  | "nodes.link.connected"
  | "nodes.link.disconnected"
  | "nodes.link.mismatch"
  | "nodes.mismatch"
  | "nodes.panel.about"
  | "nodes.panel.buffer"
  | "nodes.panel.buffer_value"
  | "nodes.panel.certificate"
  | "nodes.panel.connection"
  | "nodes.panel.dropped"
  | "nodes.panel.enrolled"
  | "nodes.panel.id"
  | "nodes.panel.label"
  | "nodes.panel.last_beat"
  | "nodes.panel.major"
  | "nodes.panel.mismatch"
  | "nodes.panel.not_connected"
  | "nodes.panel.peer"
  | "nodes.panel.renewal_due"
  | "nodes.panel.renewed"
  | "nodes.panel.serial"
  | "nodes.panel.since"
  | "nodes.panel.valid"
  | "nodes.panel.valid_range"
  | "nodes.port_closed"
  | "nodes.port_open"
  | "nodes.revoke.action"
  | "nodes.revoke.confirm"
  | "nodes.revoke.confirm_body"
  | "nodes.revoke.confirm_title"
  | "nodes.revoke.done"
  | "nodes.revoke.failed"
  | "nodes.revoke.hint"
  | "nodes.revoke.title"
  | "nodes.roles.confirm"
  | "nodes.roles.confirm_off"
  | "nodes.roles.confirm_on"
  | "nodes.roles.confirm_on_node"
  | "nodes.roles.confirm_restart"
  | "nodes.roles.confirm_title"
  | "nodes.roles.finding.dns_resolver"
  | "nodes.roles.finding.privileges"
  | "nodes.roles.finding.unprepared"
  | "nodes.roles.hint.controller"
  | "nodes.roles.hint.dhcp"
  | "nodes.roles.hint.dns"
  | "nodes.roles.hint.probe"
  | "nodes.roles.legend"
  | "nodes.roles.lock.controller_only"
  | "nodes.roles.lock.membership"
  | "nodes.roles.lock.pinned"
  | "nodes.roles.pinned"
  | "nodes.roles.prepared.no"
  | "nodes.roles.prepared.yes"
  | "nodes.roles.reset"
  | "nodes.roles.restart.back"
  | "nodes.roles.restart.down"
  | "nodes.roles.restart.late"
  | "nodes.roles.restart.on_node"
  | "nodes.roles.restart.required"
  | "nodes.roles.restart.waiting"
  | "nodes.roles.running"
  | "nodes.roles.save"
  | "nodes.roles.save_failed"
  | "nodes.roles.saved"
  | "nodes.roles.self_hint"
  | "nodes.roles.self_title"
  | "nodes.roles.title"
  | "nodes.roles.unprepared"
  | "nodes.scan.applied.active"
  | "nodes.scan.applied.applied_at"
  | "nodes.scan.applied.error"
  | "nodes.scan.applied.exclude"
  | "nodes.scan.applied.methods"
  | "nodes.scan.applied.none"
  | "nodes.scan.applied.origin"
  | "nodes.scan.applied.origin_local"
  | "nodes.scan.applied.origin_synced"
  | "nodes.scan.applied.prefixes"
  | "nodes.scan.applied.reported_at"
  | "nodes.scan.applied.revision"
  | "nodes.scan.applied.title"
  | "nodes.scan.back"
  | "nodes.scan.devices.actions"
  | "nodes.scan.devices.add"
  | "nodes.scan.devices.address"
  | "nodes.scan.devices.auth"
  | "nodes.scan.devices.auth_secret"
  | "nodes.scan.devices.empty"
  | "nodes.scan.devices.error"
  | "nodes.scan.devices.help"
  | "nodes.scan.devices.lacking"
  | "nodes.scan.devices.name"
  | "nodes.scan.devices.no_auth"
  | "nodes.scan.devices.no_privacy"
  | "nodes.scan.devices.no_secret"
  | "nodes.scan.devices.port"
  | "nodes.scan.devices.privacy"
  | "nodes.scan.devices.privacy_secret"
  | "nodes.scan.devices.remove"
  | "nodes.scan.devices.row_label"
  | "nodes.scan.devices.title"
  | "nodes.scan.devices.user"
  | "nodes.scan.dns.servers"
  | "nodes.scan.dns.servers_help"
  | "nodes.scan.error.cidr"
  | "nodes.scan.error.entries"
  | "nodes.scan.error.general"
  | "nodes.scan.error.invalid"
  | "nodes.scan.error.lines"
  | "nodes.scan.error.min"
  | "nodes.scan.error.port"
  | "nodes.scan.error.type"
  | "nodes.scan.error.unknown"
  | "nodes.scan.field.active"
  | "nodes.scan.field.active_help"
  | "nodes.scan.field.blackout"
  | "nodes.scan.field.blackout_help"
  | "nodes.scan.field.concurrency"
  | "nodes.scan.field.concurrency_help"
  | "nodes.scan.field.enabled"
  | "nodes.scan.field.enabled_help"
  | "nodes.scan.field.exclude"
  | "nodes.scan.field.exclude_help"
  | "nodes.scan.field.max_hosts"
  | "nodes.scan.field.max_hosts_help"
  | "nodes.scan.field.per_host"
  | "nodes.scan.field.per_host_help"
  | "nodes.scan.field.pps"
  | "nodes.scan.field.pps_help"
  | "nodes.scan.field.prefixes"
  | "nodes.scan.field.prefixes_help"
  | "nodes.scan.field.rate"
  | "nodes.scan.field.rate_help"
  | "nodes.scan.field.timezone"
  | "nodes.scan.field.timezone_help"
  | "nodes.scan.field.vrf"
  | "nodes.scan.field.vrf_help"
  | "nodes.scan.form.failed"
  | "nodes.scan.form.label"
  | "nodes.scan.form.readonly"
  | "nodes.scan.form.reload"
  | "nodes.scan.form.remote"
  | "nodes.scan.form.revert"
  | "nodes.scan.form.saved"
  | "nodes.scan.form.stale"
  | "nodes.scan.form.title"
  | "nodes.scan.group.general"
  | "nodes.scan.group.methods"
  | "nodes.scan.group.scope"
  | "nodes.scan.ks.at"
  | "nodes.scan.ks.by"
  | "nodes.scan.ks.confirmed"
  | "nodes.scan.ks.confirmed_no"
  | "nodes.scan.ks.confirmed_yes"
  | "nodes.scan.ks.reason"
  | "nodes.scan.ks.resume"
  | "nodes.scan.ks.running"
  | "nodes.scan.ks.stop"
  | "nodes.scan.ks.stopped"
  | "nodes.scan.ks.title"
  | "nodes.scan.lacking"
  | "nodes.scan.lldp.cdp"
  | "nodes.scan.lldp.cdp_help"
  | "nodes.scan.llmnr.port"
  | "nodes.scan.mdns.group"
  | "nodes.scan.mdns.group_help"
  | "nodes.scan.mdns.listen"
  | "nodes.scan.mdns.listen_help"
  | "nodes.scan.mdns.passive"
  | "nodes.scan.mdns.passive_help"
  | "nodes.scan.mdns.unicast_port"
  | "nodes.scan.mdns.unicast_port_help"
  | "nodes.scan.method.arp.help"
  | "nodes.scan.method.arp.name"
  | "nodes.scan.method.arp_sweep.help"
  | "nodes.scan.method.arp_sweep.name"
  | "nodes.scan.method.dhcp_snoop.help"
  | "nodes.scan.method.dhcp_snoop.name"
  | "nodes.scan.method.enabled"
  | "nodes.scan.method.icmp.help"
  | "nodes.scan.method.icmp.name"
  | "nodes.scan.method.interval"
  | "nodes.scan.method.interval_help"
  | "nodes.scan.method.lldp.help"
  | "nodes.scan.method.lldp.name"
  | "nodes.scan.method.llmnr.help"
  | "nodes.scan.method.llmnr.name"
  | "nodes.scan.method.mdns.help"
  | "nodes.scan.method.mdns.name"
  | "nodes.scan.method.nd.help"
  | "nodes.scan.method.nd.name"
  | "nodes.scan.method.os_fingerprint.help"
  | "nodes.scan.method.os_fingerprint.name"
  | "nodes.scan.method.raw"
  | "nodes.scan.method.reverse_dns.help"
  | "nodes.scan.method.reverse_dns.name"
  | "nodes.scan.method.snmp.help"
  | "nodes.scan.method.snmp.name"
  | "nodes.scan.method.tcp_connect.help"
  | "nodes.scan.method.tcp_connect.name"
  | "nodes.scan.method.tcp_syn.help"
  | "nodes.scan.method.tcp_syn.name"
  | "nodes.scan.method.timeout"
  | "nodes.scan.method.timeout_help"
  | "nodes.scan.method.ttl"
  | "nodes.scan.method.ttl_help"
  | "nodes.scan.node_fallback"
  | "nodes.scan.not_probe.body"
  | "nodes.scan.not_probe.missing"
  | "nodes.scan.not_probe.title"
  | "nodes.scan.panel.hint"
  | "nodes.scan.panel.link"
  | "nodes.scan.panel.title"
  | "nodes.scan.rate.normal"
  | "nodes.scan.rate.slow"
  | "nodes.scan.rate.slowest"
  | "nodes.scan.rate.unlimited"
  | "nodes.scan.raw.interface"
  | "nodes.scan.raw.interface_help"
  | "nodes.scan.raw.listen"
  | "nodes.scan.raw.listen_help"
  | "nodes.scan.resume.done"
  | "nodes.scan.resume.failed"
  | "nodes.scan.self_off"
  | "nodes.scan.snmp.lldp_ports"
  | "nodes.scan.snmp.lldp_ports_help"
  | "nodes.scan.snmp.retries"
  | "nodes.scan.snmp.retries_help"
  | "nodes.scan.stop.body"
  | "nodes.scan.stop.done"
  | "nodes.scan.stop.failed"
  | "nodes.scan.stop.reason"
  | "nodes.scan.stop.reason_help"
  | "nodes.scan.stop.reason_too_long"
  | "nodes.scan.stop.submit"
  | "nodes.scan.stop.title"
  | "nodes.scan.sync.in_sync"
  | "nodes.scan.sync.not_in_sync"
  | "nodes.scan.sync.not_stored"
  | "nodes.scan.sync.origin"
  | "nodes.scan.sync.origin_api"
  | "nodes.scan.sync.origin_offer"
  | "nodes.scan.sync.revision"
  | "nodes.scan.sync.title"
  | "nodes.scan.sync.updated_at"
  | "nodes.scan.sync.updated_by"
  | "nodes.scan.tcp.ports"
  | "nodes.scan.tcp.ports_help"
  | "nodes.scan.tcp.targets"
  | "nodes.scan.tcp.targets_all"
  | "nodes.scan.tcp.targets_help"
  | "nodes.scan.tcp.targets_known"
  | "nodes.scan.tcp.tls_hint"
  | "nodes.scan.tcp.tls_hint_help"
  | "nodes.scan.title"
  | "nodes.scan.vrf.default"
  | "nodes.summary"
  | "nodes.token.any_name"
  | "nodes.token.col.actions"
  | "nodes.token.col.created"
  | "nodes.token.col.expires"
  | "nodes.token.col.name"
  | "nodes.token.col.roles"
  | "nodes.token.col.state"
  | "nodes.token.col.used"
  | "nodes.token.delete"
  | "nodes.token.delete_done"
  | "nodes.token.delete_failed"
  | "nodes.token.delete_named"
  | "nodes.token.delete_pending"
  | "nodes.token.delete_title"
  | "nodes.token.deleted"
  | "nodes.token.hint"
  | "nodes.token.none"
  | "nodes.token.state.expired"
  | "nodes.token.state.pending"
  | "nodes.token.state.used"
  | "nodes.token.title"
  | "nodes.version_count"
  | "nodes.versions"
  | "prefs.density.comfortable"
  | "prefs.density.compact"
  | "prefs.density.dense"
  | "prefs.theme.dark"
  | "prefs.theme.light"
  | "prefs.theme.system"
  | "principal.node"
  | "principal.system"
  | "principal.token"
  | "principal.user"
  | "principal.you"
  | "profile.hardened.description"
  | "profile.hardened.name"
  | "profile.home.description"
  | "profile.home.name"
  | "profile.lab.description"
  | "profile.lab.name"
  | "profile.standard.description"
  | "profile.standard.name"
  | "reconciler.error.invalid"
  | "reconciler.error.range"
  | "reconciler.error.refresh"
  | "reconciler.field.adopt"
  | "reconciler.field.debounce"
  | "reconciler.field.interval"
  | "reconciler.field.orphan"
  | "reconciler.field.purge"
  | "reconciler.field.refresh"
  | "reconciler.field.retention"
  | "reconciler.help.adopt"
  | "reconciler.help.debounce"
  | "reconciler.help.interval"
  | "reconciler.help.orphan"
  | "reconciler.help.purge"
  | "reconciler.help.refresh"
  | "reconciler.help.retention"
  | "reconciler.lede"
  | "reconciler.limits"
  | "reconciler.reloaded"
  | "reconciler.saved"
  | "reconciler.title"
  | "reconciler.unit.day"
  | "reconciler.unit.hour"
  | "reconciler.unit.minute"
  | "reconciler.unit.second"
  | "recovery.copied"
  | "recovery.copy_failed"
  | "recovery.download"
  | "recovery.list_label"
  | "recovery.print"
  | "recovery.saved"
  | "role.admin.description"
  | "role.admin.name"
  | "role.auditor.description"
  | "role.auditor.name"
  | "role.operator.description"
  | "role.operator.name"
  | "role.viewer.description"
  | "role.viewer.name"
  | "scans.action.back"
  | "scans.action.resume_all"
  | "scans.action.stop_all"
  | "scans.change.changed"
  | "scans.change.gone"
  | "scans.change.new"
  | "scans.change.unchanged"
  | "scans.col.changes"
  | "scans.col.created"
  | "scans.col.finished"
  | "scans.col.kinds"
  | "scans.col.progress"
  | "scans.col.requested_by"
  | "scans.col.state"
  | "scans.col.target"
  | "scans.count"
  | "scans.diff.col.after"
  | "scans.diff.col.before"
  | "scans.diff.col.change"
  | "scans.diff.col.subject"
  | "scans.diff.col.type"
  | "scans.diff.empty"
  | "scans.diff.heading"
  | "scans.diff.items_label"
  | "scans.diff.pending"
  | "scans.diff.summary"
  | "scans.diff.total"
  | "scans.diff.totals_label"
  | "scans.diff.truncated"
  | "scans.diff.waiting"
  | "scans.empty.body"
  | "scans.empty.title"
  | "scans.fact.address"
  | "scans.fact.attachment"
  | "scans.fact.link"
  | "scans.fact.none"
  | "scans.fact.os"
  | "scans.fact.ports"
  | "scans.fact.tls"
  | "scans.fact_type.address"
  | "scans.fact_type.attachment"
  | "scans.fact_type.host"
  | "scans.fact_type.link"
  | "scans.fact_type.name"
  | "scans.fact_type.os"
  | "scans.fact_type.services"
  | "scans.fact_type.vendor"
  | "scans.kind.os_fingerprint"
  | "scans.kind.passive_refresh"
  | "scans.kind.port_scan"
  | "scans.kind.snmp_poll"
  | "scans.list.label"
  | "scans.now.action"
  | "scans.now.deadline"
  | "scans.now.deadline_hint"
  | "scans.now.follow"
  | "scans.now.intro"
  | "scans.now.kind.os_fingerprint"
  | "scans.now.kind.passive_refresh"
  | "scans.now.kind.port_scan"
  | "scans.now.kind.snmp_poll"
  | "scans.now.kinds"
  | "scans.now.kinds_required"
  | "scans.now.no_probe.many"
  | "scans.now.no_probe.none"
  | "scans.now.no_probe.one"
  | "scans.now.refused_title"
  | "scans.now.start"
  | "scans.now.started"
  | "scans.now.started_title"
  | "scans.now.starting"
  | "scans.now.title"
  | "scans.part.col.command"
  | "scans.part.col.detail"
  | "scans.part.col.ingested"
  | "scans.part.col.node"
  | "scans.part.ingested"
  | "scans.part.state.accepted"
  | "scans.part.state.cancelled"
  | "scans.part.state.done"
  | "scans.part.state.expired"
  | "scans.part.state.failed"
  | "scans.part.state.pending"
  | "scans.part.state.rejected"
  | "scans.part.state.running"
  | "scans.probe.col.config"
  | "scans.probe.col.name"
  | "scans.probe.col.scope"
  | "scans.probe.col.switch"
  | "scans.probe.col.sync"
  | "scans.probe.config"
  | "scans.probe.config_named"
  | "scans.probe.in_process"
  | "scans.probe.in_sync"
  | "scans.probe.methods_none"
  | "scans.probe.node_unnamed"
  | "scans.probe.out_of_sync"
  | "scans.probe.scope"
  | "scans.probe.scope_none"
  | "scans.probes.label"
  | "scans.progress.label"
  | "scans.progress.percent"
  | "scans.section.jobs"
  | "scans.section.probes"
  | "scans.state.cancelled"
  | "scans.state.done"
  | "scans.state.failed"
  | "scans.state.partial"
  | "scans.state.queued"
  | "scans.state.running"
  | "scans.stop.body"
  | "scans.stop.confirm"
  | "scans.stop.reason"
  | "scans.stop.reason_hint"
  | "scans.stop.title"
  | "scans.switch.active"
  | "scans.switch.reason"
  | "scans.switch.stopped"
  | "scans.switch.unconfirmed"
  | "scans.target.address"
  | "scans.target.host"
  | "scans.target.network"
  | "scans.target.prefix"
  | "scans.title"
  | "scans.toast.resumed"
  | "scans.toast.stopped"
  | "scans.view.deadline"
  | "scans.view.error"
  | "scans.view.facts"
  | "scans.view.loading"
  | "scans.view.networks"
  | "scans.view.not_found"
  | "scans.view.not_found_title"
  | "scans.view.probes"
  | "scans.view.probes_label"
  | "scans.view.tab"
  | "scans.view.title"
  | "secrets.action.create"
  | "secrets.action.delete"
  | "secrets.action.delete_named"
  | "secrets.action.edit"
  | "secrets.action.edit_named"
  | "secrets.action.replace"
  | "secrets.action.replace_named"
  | "secrets.action.reveal"
  | "secrets.action.reveal_named"
  | "secrets.col.actions"
  | "secrets.col.hosts"
  | "secrets.col.kind"
  | "secrets.col.name"
  | "secrets.col.revealed"
  | "secrets.col.tags"
  | "secrets.col.updated"
  | "secrets.col.user"
  | "secrets.count"
  | "secrets.count_filtered"
  | "secrets.created"
  | "secrets.delete.body"
  | "secrets.delete.check_failed"
  | "secrets.delete.confirm"
  | "secrets.delete.in_use_hint"
  | "secrets.delete.in_use_lead"
  | "secrets.delete.in_use_title"
  | "secrets.delete.title"
  | "secrets.deleted"
  | "secrets.detail.back"
  | "secrets.detail.close"
  | "secrets.detail.label"
  | "secrets.empty"
  | "secrets.empty_admin"
  | "secrets.field.created"
  | "secrets.field.notes"
  | "secrets.field.origin"
  | "secrets.field.value_updated"
  | "secrets.filter.kind"
  | "secrets.filter.kind_all"
  | "secrets.filter.label"
  | "secrets.filter.placeholder"
  | "secrets.form.create_submit"
  | "secrets.form.create_title"
  | "secrets.form.edit_submit"
  | "secrets.form.edit_title"
  | "secrets.form.error.name_required"
  | "secrets.form.error.value_required"
  | "secrets.form.kind"
  | "secrets.form.name"
  | "secrets.form.name_help"
  | "secrets.form.notes"
  | "secrets.form.notes_help"
  | "secrets.form.pin_enrol"
  | "secrets.form.pin_title"
  | "secrets.form.reload"
  | "secrets.form.reloaded"
  | "secrets.form.tags"
  | "secrets.form.tags_help"
  | "secrets.form.username"
  | "secrets.form.username_help"
  | "secrets.form.value"
  | "secrets.form.value_cleared"
  | "secrets.form.value_help"
  | "secrets.form.value_key_help"
  | "secrets.kind.api_key"
  | "secrets.kind.other"
  | "secrets.kind.password"
  | "secrets.kind.ssh_key"
  | "secrets.kind.token"
  | "secrets.no_access.body"
  | "secrets.no_access.title"
  | "secrets.no_match"
  | "secrets.no_user"
  | "secrets.origin.import"
  | "secrets.origin.manual"
  | "secrets.refs.connector"
  | "secrets.refs.connectors"
  | "secrets.refs.deleted"
  | "secrets.refs.hosts"
  | "secrets.refs.none"
  | "secrets.refs.role"
  | "secrets.refs.title"
  | "secrets.refs.unknown_host"
  | "secrets.replace.field"
  | "secrets.replace.lead"
  | "secrets.replace.submit"
  | "secrets.replace.title"
  | "secrets.replaced"
  | "secrets.reveal.audit"
  | "secrets.reveal.clear_failed"
  | "secrets.reveal.cleared"
  | "secrets.reveal.copied"
  | "secrets.reveal.copy"
  | "secrets.reveal.copy_blocked"
  | "secrets.reveal.hidden"
  | "secrets.reveal.hide"
  | "secrets.reveal.left"
  | "secrets.reveal.show"
  | "secrets.reveal.stepup.code_label"
  | "secrets.reveal.stepup.continue"
  | "secrets.reveal.stepup.fresh"
  | "secrets.reveal.stepup.passkey"
  | "secrets.reveal.stepup.password"
  | "secrets.reveal.stepup.password_label"
  | "secrets.reveal.stepup.title"
  | "secrets.reveal.stepup.with_passkey"
  | "secrets.reveal.title"
  | "secrets.reveal.username"
  | "secrets.reveal.value"
  | "secrets.reveal.working"
  | "secrets.revealed_by"
  | "secrets.role.admin"
  | "secrets.role.other"
  | "secrets.role.rdp"
  | "secrets.role.ssh"
  | "secrets.role.web"
  | "secrets.saved"
  | "secrets.title"
  | "settings.nav.access"
  | "settings.nav.audit_export"
  | "settings.nav.backup"
  | "settings.nav.certificates"
  | "settings.nav.dhcp"
  | "settings.nav.dns"
  | "settings.nav.guardrails"
  | "settings.nav.label"
  | "settings.nav.languages"
  | "settings.nav.reconciler"
  | "settings.nav.secrets"
  | "settings.nav.security"
  | "settings.nav.updates"
  | "settings.nav.users"
  | "settings.nav.vault"
  | "settings.reloaded"
  | "settings.security.audit_export.local"
  | "settings.security.audit_export.local_help"
  | "settings.security.audit_export.mode"
  | "settings.security.audit_export.optional"
  | "settings.security.audit_export.optional_help"
  | "settings.security.audit_export.required"
  | "settings.security.audit_export.required_help"
  | "settings.security.col.actions"
  | "settings.security.col.id"
  | "settings.security.col.profile"
  | "settings.security.col.setting"
  | "settings.security.col.status"
  | "settings.security.col.value"
  | "settings.security.consequence.differs"
  | "settings.security.consequence.matches"
  | "settings.security.consequence.none"
  | "settings.security.consequence.raised_clears"
  | "settings.security.consequence.raised_lab"
  | "settings.security.consequence.raised_others"
  | "settings.security.consequence.weak_new"
  | "settings.security.consequence.weak_stays"
  | "settings.security.edit_row"
  | "settings.security.edit_title"
  | "settings.security.marker.differs"
  | "settings.security.marker.follows"
  | "settings.security.marker.weak"
  | "settings.security.more"
  | "settings.security.passkey.hint"
  | "settings.security.policy.custom"
  | "settings.security.policy.max"
  | "settings.security.policy.max_error"
  | "settings.security.policy.max_help"
  | "settings.security.policy.min"
  | "settings.security.policy.min_error"
  | "settings.security.policy.min_help"
  | "settings.security.policy.pattern"
  | "settings.security.policy.pattern_error"
  | "settings.security.policy.pattern_help"
  | "settings.security.policy.preset"
  | "settings.security.profile.change"
  | "settings.security.profile.changes"
  | "settings.security.profile.changes_table"
  | "settings.security.profile.col_after"
  | "settings.security.profile.col_now"
  | "settings.security.profile.current"
  | "settings.security.profile.deviations"
  | "settings.security.profile.dialog_title"
  | "settings.security.profile.heading"
  | "settings.security.profile.lab_ack"
  | "settings.security.profile.lab_body"
  | "settings.security.profile.lab_tag"
  | "settings.security.profile.lab_title"
  | "settings.security.profile.lab_warning"
  | "settings.security.profile.no_changes"
  | "settings.security.profile.reset_done"
  | "settings.security.profile.reset_to"
  | "settings.security.profile.resets"
  | "settings.security.profile.resets_same"
  | "settings.security.profile.switch_done"
  | "settings.security.profile.switch_to"
  | "settings.security.profile.weak_body"
  | "settings.security.profile.weak_warning"
  | "settings.security.reset"
  | "settings.security.reset_done"
  | "settings.security.reset_row"
  | "settings.security.save"
  | "settings.security.saved"
  | "settings.security.secret_reveal.bound_host"
  | "settings.security.secret_reveal.bound_host_hint"
  | "settings.security.secret_reveal.pin_rule"
  | "settings.security.secret_reveal.step_up"
  | "settings.security.secret_reveal.step_up_fresh"
  | "settings.security.secret_reveal.step_up_fresh_help"
  | "settings.security.secret_reveal.step_up_passkey"
  | "settings.security.secret_reveal.step_up_passkey_help"
  | "settings.security.secret_reveal.step_up_session"
  | "settings.security.secret_reveal.step_up_session_help"
  | "settings.security.session.absolute"
  | "settings.security.session.absolute_help"
  | "settings.security.session.idle"
  | "settings.security.session.idle_help"
  | "settings.security.session.number_error"
  | "settings.security.session.order_error"
  | "settings.security.toggles.heading"
  | "settings.security.toggles.range"
  | "settings.security.toggles.table"
  | "settings.security.token.days"
  | "settings.security.token.days_error"
  | "settings.security.token.days_help"
  | "settings.security.token.limited"
  | "settings.security.token.unlimited_hint"
  | "settings.security.unit.days"
  | "settings.security.unit.hours"
  | "settings.security.unit.label"
  | "settings.security.unit.minutes"
  | "settings.security.updates.check"
  | "settings.security.updates.check_hint"
  | "settings.security.updates.install"
  | "settings.security.updates.install_ui"
  | "settings.security.updates.install_ui_help"
  | "settings.security.updates.install_ui_step_up"
  | "settings.security.updates.install_ui_step_up_help"
  | "settings.security.updates.install_upload_only"
  | "settings.security.updates.install_upload_only_help"
  | "settings.security.vault.body"
  | "settings.security.vault.title"
  | "settings.title"
  | "settings.users.action.access"
  | "settings.users.action.break_glass_make"
  | "settings.users.action.break_glass_off"
  | "settings.users.action.break_glass_on"
  | "settings.users.action.break_glass_remove"
  | "settings.users.action.delete"
  | "settings.users.action.delete_help"
  | "settings.users.action.details"
  | "settings.users.action.details_help"
  | "settings.users.action.disable"
  | "settings.users.action.disable_help"
  | "settings.users.action.edit"
  | "settings.users.action.enable"
  | "settings.users.action.enable_help"
  | "settings.users.action.lock"
  | "settings.users.action.own_delete"
  | "settings.users.action.own_disable"
  | "settings.users.action.password"
  | "settings.users.action.password_break_glass"
  | "settings.users.action.password_help"
  | "settings.users.action.remove"
  | "settings.users.action.roles"
  | "settings.users.action.roles_break_glass"
  | "settings.users.action.roles_help"
  | "settings.users.action.sessions"
  | "settings.users.action.sign_out"
  | "settings.users.action.sign_out_help"
  | "settings.users.action.unlock"
  | "settings.users.action.unlock_help"
  | "settings.users.actions"
  | "settings.users.add.submit"
  | "settings.users.add.title"
  | "settings.users.add_button"
  | "settings.users.added"
  | "settings.users.back"
  | "settings.users.break_glass.made"
  | "settings.users.break_glass.make_body"
  | "settings.users.break_glass.make_confirm"
  | "settings.users.break_glass.make_title"
  | "settings.users.break_glass.no_key"
  | "settings.users.break_glass.remove_body"
  | "settings.users.break_glass.remove_confirm"
  | "settings.users.break_glass.remove_title"
  | "settings.users.break_glass.removed"
  | "settings.users.col.display_name"
  | "settings.users.col.last_login"
  | "settings.users.col.methods"
  | "settings.users.col.name"
  | "settings.users.col.roles"
  | "settings.users.col.status"
  | "settings.users.count"
  | "settings.users.created"
  | "settings.users.crumbs"
  | "settings.users.delete.body"
  | "settings.users.delete.confirm"
  | "settings.users.delete.note"
  | "settings.users.delete.title"
  | "settings.users.deleted"
  | "settings.users.disable.body"
  | "settings.users.disable.confirm"
  | "settings.users.disable.title"
  | "settings.users.disabled"
  | "settings.users.edit.submit"
  | "settings.users.edit.title"
  | "settings.users.enabled"
  | "settings.users.error.display_required"
  | "settings.users.error.name_length"
  | "settings.users.error.name_required"
  | "settings.users.error.name_spaces"
  | "settings.users.error.password_required"
  | "settings.users.error.roles_required"
  | "settings.users.field.display_help"
  | "settings.users.field.display_name"
  | "settings.users.field.language"
  | "settings.users.field.name"
  | "settings.users.field.name_help"
  | "settings.users.field.new_password"
  | "settings.users.field.password"
  | "settings.users.field.password_help"
  | "settings.users.field.roles"
  | "settings.users.methods.authenticator"
  | "settings.users.methods.passkeys"
  | "settings.users.methods.password"
  | "settings.users.methods.recovery_codes"
  | "settings.users.methods.security_keys"
  | "settings.users.open"
  | "settings.users.password.help"
  | "settings.users.password.lead"
  | "settings.users.password.submit"
  | "settings.users.password.title"
  | "settings.users.roles.own_admin"
  | "settings.users.roles.submit"
  | "settings.users.roles.title"
  | "settings.users.saved_details"
  | "settings.users.saved_password"
  | "settings.users.saved_roles"
  | "settings.users.sign_out.body"
  | "settings.users.sign_out.confirm"
  | "settings.users.sign_out.title"
  | "settings.users.signed_out"
  | "settings.users.status.active"
  | "settings.users.status.break_glass"
  | "settings.users.status.disabled"
  | "settings.users.status.locked"
  | "settings.users.status.locked_manual"
  | "settings.users.status.password_change"
  | "settings.users.table"
  | "settings.users.unlocked"
  | "settings.users.you"
  | "setup.admin.check.breach"
  | "setup.admin.check.breach_found"
  | "setup.admin.check.breach_off"
  | "setup.admin.check.breach_pending"
  | "setup.admin.check.breach_pin"
  | "setup.admin.check.breach_unavailable"
  | "setup.admin.check.context"
  | "setup.admin.check.state.bad"
  | "setup.admin.check.state.idle"
  | "setup.admin.check.state.off"
  | "setup.admin.check.state.ok"
  | "setup.admin.check.state.pending"
  | "setup.admin.check.trivial"
  | "setup.admin.codes_note"
  | "setup.admin.lede"
  | "setup.admin.name.help"
  | "setup.admin.name.label"
  | "setup.admin.passkey.help.hardened"
  | "setup.admin.passkey.help.home"
  | "setup.admin.passkey.help.lab"
  | "setup.admin.passkey.help.standard"
  | "setup.admin.passkey.title"
  | "setup.admin.password.generate"
  | "setup.admin.password.help.passphrase"
  | "setup.admin.password.help.password"
  | "setup.admin.password.help.pin"
  | "setup.admin.password.help_generated"
  | "setup.admin.password.hide"
  | "setup.admin.password.label.passphrase"
  | "setup.admin.password.label.password"
  | "setup.admin.password.label.pin"
  | "setup.admin.password.placeholder.passphrase"
  | "setup.admin.password.placeholder.password"
  | "setup.admin.password.placeholder.pin"
  | "setup.admin.password.show"
  | "setup.admin.user.help"
  | "setup.admin.user.invalid"
  | "setup.admin.user.label"
  | "setup.admin.vault.body"
  | "setup.admin.vault.title"
  | "setup.banner.body"
  | "setup.banner.review"
  | "setup.banner.title"
  | "setup.cluster.join"
  | "setup.cluster.join_description"
  | "setup.cluster.later"
  | "setup.cluster.new"
  | "setup.cluster.new_description"
  | "setup.cluster.title"
  | "setup.dhcp.address"
  | "setup.dhcp.address_direct_help"
  | "setup.dhcp.address_relay_help"
  | "setup.dhcp.dns"
  | "setup.dhcp.dns_help"
  | "setup.dhcp.dns_placeholder"
  | "setup.dhcp.hardened"
  | "setup.dhcp.iface"
  | "setup.dhcp.lease"
  | "setup.dhcp.lease_unit"
  | "setup.dhcp.lede"
  | "setup.dhcp.listen"
  | "setup.dhcp.listen.direct"
  | "setup.dhcp.listen.direct_description"
  | "setup.dhcp.listen.relay"
  | "setup.dhcp.listen.relay_description"
  | "setup.dhcp.mode"
  | "setup.dhcp.mode.later"
  | "setup.dhcp.mode.later_description"
  | "setup.dhcp.mode.now"
  | "setup.dhcp.mode.now_description"
  | "setup.dhcp.network"
  | "setup.dhcp.network_help"
  | "setup.dhcp.node_networks"
  | "setup.dhcp.others_off"
  | "setup.dhcp.others_off_description"
  | "setup.dhcp.pool_first"
  | "setup.dhcp.pool_help"
  | "setup.dhcp.pool_last"
  | "setup.dhcp.privacy"
  | "setup.dhcp.router"
  | "setup.dhcp.router_help"
  | "setup.dhcp.safety"
  | "setup.dhcp.scope"
  | "setup.dhcp.skipped"
  | "setup.dhcp.summary"
  | "setup.dhcp.unit.days"
  | "setup.dhcp.unit.hours"
  | "setup.dhcp.use_network"
  | "setup.disk.contents"
  | "setup.disk.detected"
  | "setup.disk.free_aside"
  | "setup.disk.fsync"
  | "setup.disk.item.audit"
  | "setup.disk.item.audit_contains"
  | "setup.disk.item.audit_size"
  | "setup.disk.item.keys"
  | "setup.disk.item.keys_contains"
  | "setup.disk.item.keys_size"
  | "setup.disk.item.leases"
  | "setup.disk.item.leases_contains"
  | "setup.disk.item.leases_size"
  | "setup.disk.item.store"
  | "setup.disk.item.store_contains"
  | "setup.disk.item.store_size"
  | "setup.disk.lede"
  | "setup.disk.media.hdd"
  | "setup.disk.media.nvme"
  | "setup.disk.media.smr"
  | "setup.disk.media.ssd"
  | "setup.disk.media.unknown"
  | "setup.disk.media_free"
  | "setup.disk.move"
  | "setup.disk.move_path"
  | "setup.disk.on"
  | "setup.disk.override"
  | "setup.disk.table.contains"
  | "setup.disk.table.item"
  | "setup.disk.table.label"
  | "setup.disk.table.size"
  | "setup.disk.tag.rotating"
  | "setup.disk.tag.slow"
  | "setup.disk.total_note"
  | "setup.disk.total_size"
  | "setup.disk.unknown"
  | "setup.disk.warn.rotating_body"
  | "setup.disk.warn.rotating_title"
  | "setup.disk.warn.slow_body"
  | "setup.disk.warn.slow_title"
  | "setup.dns.cache"
  | "setup.dns.cache_description"
  | "setup.dns.check.capability"
  | "setup.dns.check.firewall"
  | "setup.dns.check.port"
  | "setup.dns.check.role"
  | "setup.dns.check.tls_ports"
  | "setup.dns.checklist"
  | "setup.dns.doh"
  | "setup.dns.doh_description"
  | "setup.dns.dot"
  | "setup.dns.dot_description"
  | "setup.dns.entries"
  | "setup.dns.known"
  | "setup.dns.lede"
  | "setup.dns.log"
  | "setup.dns.log_description"
  | "setup.dns.preset"
  | "setup.dns.preset_apply"
  | "setup.dns.preset_help"
  | "setup.dns.preset_on"
  | "setup.dns.privacy"
  | "setup.dns.resolve"
  | "setup.dns.resolve.forward"
  | "setup.dns.resolve.forward_description"
  | "setup.dns.resolve.recurse"
  | "setup.dns.resolve.recurse_description"
  | "setup.dns.skipped"
  | "setup.dns.tls_name"
  | "setup.dns.tls_name_help"
  | "setup.dns.transport"
  | "setup.dns.transport.doh"
  | "setup.dns.transport.doh_description"
  | "setup.dns.transport.dot"
  | "setup.dns.transport.dot_description"
  | "setup.dns.transport.plain"
  | "setup.dns.transport.plain_description"
  | "setup.dns.upstreams"
  | "setup.dns.upstreams_help"
  | "setup.dns.upstreams_none"
  | "setup.dns.use_dot"
  | "setup.done.admin"
  | "setup.done.change"
  | "setup.done.change_item"
  | "setup.done.choices"
  | "setup.done.cluster"
  | "setup.done.dhcp"
  | "setup.done.dhcp_detail"
  | "setup.done.dhcp_later"
  | "setup.done.disk"
  | "setup.done.disk_override"
  | "setup.done.disk_unknown"
  | "setup.done.dns"
  | "setup.done.dns_none"
  | "setup.done.dns_recurse"
  | "setup.done.host"
  | "setup.done.lab_note"
  | "setup.done.lede"
  | "setup.done.not_production"
  | "setup.done.passkey"
  | "setup.done.passkey_optional"
  | "setup.done.passkey_required"
  | "setup.done.probe_none"
  | "setup.done.probe_on"
  | "setup.done.profile"
  | "setup.done.proxies"
  | "setup.done.roles"
  | "setup.footer.finish"
  | "setup.footer.finishing"
  | "setup.footer.open"
  | "setup.gate.codes_ack"
  | "setup.gate.codes_loading"
  | "setup.gate.dhcp.address"
  | "setup.gate.dhcp.dns"
  | "setup.gate.dhcp.iface"
  | "setup.gate.dhcp.lease"
  | "setup.gate.dhcp.network"
  | "setup.gate.dhcp.others_off"
  | "setup.gate.dhcp.pool_first"
  | "setup.gate.dhcp.pool_last"
  | "setup.gate.dhcp.pool_order"
  | "setup.gate.dhcp.router"
  | "setup.gate.dhcp.router_in_pool"
  | "setup.gate.disk"
  | "setup.gate.display_name"
  | "setup.gate.dns_entries"
  | "setup.gate.dns_tls_name"
  | "setup.gate.dns_upstreams"
  | "setup.gate.host_empty"
  | "setup.gate.host_invalid"
  | "setup.gate.lab_ack"
  | "setup.gate.modules_none"
  | "setup.gate.passkey_required"
  | "setup.gate.passkey_waiting"
  | "setup.gate.password.passphrase"
  | "setup.gate.password.password"
  | "setup.gate.password.pin"
  | "setup.gate.password_error"
  | "setup.gate.password_pending"
  | "setup.gate.password_policy"
  | "setup.gate.probe_networks"
  | "setup.gate.proxies_empty"
  | "setup.gate.proxies_invalid"
  | "setup.gate.roles_controller"
  | "setup.gate.roles_none"
  | "setup.gate.tls_plain"
  | "setup.gate.token"
  | "setup.gate.user_name"
  | "setup.host.error.address"
  | "setup.host.error.chars"
  | "setup.host.error.empty"
  | "setup.host.error.length"
  | "setup.host.help"
  | "setup.host.label"
  | "setup.host.lede"
  | "setup.host.placeholder"
  | "setup.lab.ack"
  | "setup.lab.enforced"
  | "setup.lab.enforced.attribution"
  | "setup.lab.enforced.audit"
  | "setup.lab.enforced.secrets"
  | "setup.lab.never_body"
  | "setup.lab.never_title"
  | "setup.lab.relax.breach"
  | "setup.lab.relax.ddns"
  | "setup.lab.relax.http"
  | "setup.lab.relax.lockout"
  | "setup.lab.relax.recursion"
  | "setup.lab.relax.scan"
  | "setup.lab.relax.tokens"
  | "setup.lab.relaxes"
  | "setup.lab.title"
  | "setup.modules.aside"
  | "setup.modules.dhcp.description"
  | "setup.modules.dhcp.name"
  | "setup.modules.discovery.description"
  | "setup.modules.discovery.name"
  | "setup.modules.dns.description"
  | "setup.modules.dns.name"
  | "setup.modules.ipam.description"
  | "setup.modules.ipam.name"
  | "setup.modules.later"
  | "setup.modules.save_failed"
  | "setup.modules.title"
  | "setup.profile.group"
  | "setup.profile.hint.hardened"
  | "setup.profile.hint.home"
  | "setup.profile.hint.lab"
  | "setup.profile.hint.standard"
  | "setup.profile.lede"
  | "setup.profile.table.aside"
  | "setup.profile.table.id"
  | "setup.profile.table.label"
  | "setup.profile.table.note"
  | "setup.profile.table.setting"
  | "setup.profile.table.title"
  | "setup.profile.table.value"
  | "setup.profile.weaker"
  | "setup.result.ca.compare"
  | "setup.result.ca.copied"
  | "setup.result.ca.copy"
  | "setup.result.ca.copy_failed"
  | "setup.result.ca.help"
  | "setup.result.ca.title"
  | "setup.result.codes.deferred"
  | "setup.result.codes.lede"
  | "setup.result.codes.loading"
  | "setup.result.codes.title"
  | "setup.result.dhcp.config_help"
  | "setup.result.dhcp.copied"
  | "setup.result.dhcp.copy"
  | "setup.result.dhcp.failed.options"
  | "setup.result.dhcp.failed.pool"
  | "setup.result.dhcp.failed.prefix"
  | "setup.result.dhcp.failed.scope"
  | "setup.result.dhcp.none"
  | "setup.result.dhcp.open_scope"
  | "setup.result.dhcp.saved"
  | "setup.result.dhcp.title"
  | "setup.result.dns.config_help"
  | "setup.result.dns.copied"
  | "setup.result.dns.copy"
  | "setup.result.dns.copy_failed"
  | "setup.result.dns.failed"
  | "setup.result.dns.none"
  | "setup.result.dns.recurse"
  | "setup.result.dns.saved"
  | "setup.result.dns.title"
  | "setup.result.lede"
  | "setup.result.next.connector_later"
  | "setup.result.next.import"
  | "setup.result.next.import_description"
  | "setup.result.next.ipam"
  | "setup.result.next.ipam_description"
  | "setup.result.next.passkey_first"
  | "setup.result.next.passkey_first_proxmox"
  | "setup.result.next.passkey_first_unifi"
  | "setup.result.next.proxmox"
  | "setup.result.next.proxmox_description"
  | "setup.result.next.title"
  | "setup.result.next.unifi"
  | "setup.result.next.unifi_description"
  | "setup.result.passkey.add"
  | "setup.result.passkey.added"
  | "setup.result.passkey.help.hardened"
  | "setup.result.passkey.help.home"
  | "setup.result.passkey.help.lab"
  | "setup.result.passkey.help.standard"
  | "setup.result.passkey.title"
  | "setup.result.passkey.unavailable"
  | "setup.result.passkey.waiting"
  | "setup.result.passkey_label"
  | "setup.result.title"
  | "setup.roles.controller.description"
  | "setup.roles.dhcp.description"
  | "setup.roles.dmz.note"
  | "setup.roles.dmz.ticked"
  | "setup.roles.dns.description"
  | "setup.roles.group"
  | "setup.roles.hint"
  | "setup.roles.hint.hardened"
  | "setup.roles.hint.home"
  | "setup.roles.hint.lab"
  | "setup.roles.hint.standard"
  | "setup.roles.hint_probe"
  | "setup.roles.lede"
  | "setup.roles.memory"
  | "setup.roles.memory_none"
  | "setup.roles.memory_unknown_total"
  | "setup.roles.probe.aside"
  | "setup.roles.probe.description"
  | "setup.roles.probe.none"
  | "setup.roles.probe.title"
  | "setup.step.admin.name"
  | "setup.step.admin.title"
  | "setup.step.dhcp.name"
  | "setup.step.dhcp.title"
  | "setup.step.disk.name"
  | "setup.step.disk.title"
  | "setup.step.dns.name"
  | "setup.step.dns.title"
  | "setup.step.done.name"
  | "setup.step.done.title"
  | "setup.step.host.name"
  | "setup.step.host.title"
  | "setup.step.profile.name"
  | "setup.step.profile.title"
  | "setup.step.roles.name"
  | "setup.step.roles.title"
  | "setup.step.welcome.name"
  | "setup.step.welcome.title"
  | "setup.stepno"
  | "setup.steps.completed"
  | "setup.steps.dhcp_later"
  | "setup.steps.dhcp_skipped"
  | "setup.steps.dns_meta"
  | "setup.steps.dns_skipped"
  | "setup.steps.item"
  | "setup.steps.label"
  | "setup.steps.roles_meta"
  | "setup.title"
  | "setup.tls.default"
  | "setup.tls.imported.description"
  | "setup.tls.imported.name"
  | "setup.tls.internal_ca.description"
  | "setup.tls.internal_ca.name"
  | "setup.tls.passkey_note"
  | "setup.tls.passkey_note_plain"
  | "setup.tls.plain.description"
  | "setup.tls.plain.disabled"
  | "setup.tls.plain.name"
  | "setup.tls.proxies.help"
  | "setup.tls.proxies.invalid"
  | "setup.tls.proxies.label"
  | "setup.tls.reverse_proxy.description"
  | "setup.tls.reverse_proxy.name"
  | "setup.tls.title"
  | "setup.welcome.cores"
  | "setup.welcome.fact.address"
  | "setup.welcome.fact.cpu"
  | "setup.welcome.fact.memory"
  | "setup.welcome.fact.node"
  | "setup.welcome.fact.os"
  | "setup.welcome.found"
  | "setup.welcome.found_none"
  | "setup.welcome.handy"
  | "setup.welcome.handy.disk"
  | "setup.welcome.handy.host"
  | "setup.welcome.handy.passkey"
  | "setup.welcome.lede"
  | "setup.welcome.restore"
  | "setup.welcome.restore_body"
  | "setup.welcome.restore_link"
  | "setup.welcome.restore_title"
  | "setup.welcome.token.help"
  | "setup.welcome.token.label"
  | "setup.welcome.token.title"
  | "shell.account.density"
  | "shell.account.emphasis"
  | "shell.account.emphasis_hint"
  | "shell.account.language"
  | "shell.account.language_auto"
  | "shell.account.language_local"
  | "shell.account.open"
  | "shell.account.security"
  | "shell.account.sign_out"
  | "shell.account.theme"
  | "shell.account.title"
  | "shell.account.who"
  | "shell.banner.break_glass_body"
  | "shell.banner.break_glass_title"
  | "shell.banner.fix"
  | "shell.banner.lab_body"
  | "shell.banner.lab_title"
  | "shell.banner.mfa_required"
  | "shell.banner.password_change"
  | "shell.banner.review"
  | "shell.banner.weak_body"
  | "shell.banner.weak_title"
  | "shell.brand.home"
  | "shell.command.addresses"
  | "shell.command.audit_verify"
  | "shell.command.dashboard_hint"
  | "shell.command.density_comfortable"
  | "shell.command.density_compact"
  | "shell.command.density_dense"
  | "shell.command.emphasis_off"
  | "shell.command.emphasis_on"
  | "shell.command.hosts"
  | "shell.command.import"
  | "shell.command.secrets"
  | "shell.command.shortcuts"
  | "shell.command.theme_dark"
  | "shell.command.theme_light"
  | "shell.command.theme_system"
  | "shell.command.updates"
  | "shell.command.vlans"
  | "shell.command.whats_new"
  | "shell.dashboard.jobs"
  | "shell.dashboard.no_roles"
  | "shell.dashboard.node"
  | "shell.dashboard.sub"
  | "shell.dashboard.uptime"
  | "shell.forbidden.body"
  | "shell.forbidden.title"
  | "shell.keys.cancel"
  | "shell.keys.claim"
  | "shell.keys.close_panel"
  | "shell.keys.details"
  | "shell.keys.edit"
  | "shell.keys.expand"
  | "shell.keys.export"
  | "shell.keys.extend"
  | "shell.keys.filter"
  | "shell.keys.focus_grid"
  | "shell.keys.focus_tree"
  | "shell.keys.full_page"
  | "shell.keys.goto"
  | "shell.keys.job_panel"
  | "shell.keys.lock"
  | "shell.keys.mode"
  | "shell.keys.move"
  | "shell.keys.move_focus"
  | "shell.keys.move_focus_alt"
  | "shell.keys.note"
  | "shell.keys.palette"
  | "shell.keys.section.anywhere"
  | "shell.keys.section.changes"
  | "shell.keys.section.grids"
  | "shell.keys.section.tree"
  | "shell.keys.select_all"
  | "shell.keys.select_row"
  | "shell.keys.theme"
  | "shell.keys.title"
  | "shell.keys.undo"
  | "shell.nav.audit"
  | "shell.nav.cluster"
  | "shell.nav.connectors"
  | "shell.nav.dashboard"
  | "shell.nav.dhcp"
  | "shell.nav.discovery"
  | "shell.nav.dns"
  | "shell.nav.ipam"
  | "shell.nav.jobs"
  | "shell.nav.jobs_badge"
  | "shell.nav.label"
  | "shell.nav.nodes"
  | "shell.nav.settings"
  | "shell.nav.tooltip"
  | "shell.nav.topology"
  | "shell.notfound.body"
  | "shell.notfound.home"
  | "shell.notfound.title"
  | "shell.palette.foot.commands"
  | "shell.palette.foot.move"
  | "shell.palette.foot.open"
  | "shell.palette.group.actions"
  | "shell.palette.group.goto"
  | "shell.palette.group.preferences"
  | "shell.palette.group.search"
  | "shell.palette.label"
  | "shell.palette.no_match"
  | "shell.palette.no_match_hint"
  | "shell.palette.placeholder"
  | "shell.palette.search_all"
  | "shell.palette.search_label"
  | "shell.palette.searching"
  | "shell.placeholder.body"
  | "shell.placeholder.title"
  | "shell.report.account"
  | "shell.report.copy"
  | "shell.report.copy_failed"
  | "shell.report.failed"
  | "shell.report.hardened"
  | "shell.report.intro"
  | "shell.report.loading"
  | "shell.report.open"
  | "shell.report.title"
  | "shell.search.empty"
  | "shell.search.kind.address"
  | "shell.search.kind.host"
  | "shell.search.kind.interface"
  | "shell.search.kind.mac"
  | "shell.search.kind.prefix"
  | "shell.search.kind.range"
  | "shell.search.kind.vlan"
  | "shell.search.results"
  | "shell.search.title"
  | "shell.skip_to_content"
  | "shell.splash"
  | "shell.status.alarms"
  | "shell.status.alarms_title"
  | "shell.status.connecting"
  | "shell.status.critical"
  | "shell.status.idle"
  | "shell.status.jobs_title"
  | "shell.status.last_event"
  | "shell.status.live"
  | "shell.status.live_title"
  | "shell.status.modules_restart"
  | "shell.status.modules_restart_title"
  | "shell.status.no_events"
  | "shell.status.offline"
  | "shell.status.proposals"
  | "shell.status.reconnecting"
  | "shell.status.running"
  | "shell.status.selection"
  | "shell.status.update"
  | "shell.status.update_security"
  | "shell.status.update_title"
  | "shell.status.version"
  | "shell.status.waiting"
  | "shell.theme.change"
  | "shell.theme.dark"
  | "shell.theme.light"
  | "shell.theme.mode.dark"
  | "shell.theme.mode.light"
  | "shell.theme.system"
  | "shell.top.command_hint"
  | "shell.top.command_open"
  | "shell.top.node"
  | "shell.top.node_title"
  | "shell.top.node_unreachable"
  | "shell.top.profile"
  | "shell.top.profile_title"
  | "shell.top.role.candidate"
  | "shell.top.role.follower"
  | "shell.top.role.leader"
  | "shell.top.role.learner"
  | "shell.top.role.memory"
  | "shell.top.role.shutdown"
  | "shell.top.role.unknown"
  | "shell.top.shortcuts_title"
  | "toggles.audit_export.local"
  | "toggles.audit_export.name"
  | "toggles.audit_export.optional"
  | "toggles.audit_export.required"
  | "toggles.breach_check.name"
  | "toggles.breach_check.off"
  | "toggles.breach_check.offline"
  | "toggles.breach_check.offline_preferred"
  | "toggles.breach_check.online"
  | "toggles.lockout.delay_then_temporary_lock"
  | "toggles.lockout.lock_until_unlock"
  | "toggles.lockout.name"
  | "toggles.lockout.off"
  | "toggles.lockout.progressive_delay"
  | "toggles.mfa.administrators"
  | "toggles.mfa.everyone"
  | "toggles.mfa.name"
  | "toggles.mfa.optional"
  | "toggles.passkey_for_admins.name"
  | "toggles.password_policy.custom"
  | "toggles.password_policy.hardened"
  | "toggles.password_policy.name"
  | "toggles.password_policy.pin"
  | "toggles.password_policy.standard"
  | "toggles.secret_reveal.name"
  | "toggles.secret_reveal.step_up.fresh"
  | "toggles.secret_reveal.step_up.passkey"
  | "toggles.secret_reveal.step_up.session"
  | "toggles.secret_reveal.value"
  | "toggles.session.name"
  | "toggles.session.value"
  | "toggles.token_max_days.days"
  | "toggles.token_max_days.name"
  | "toggles.token_max_days.unlimited"
  | "toggles.updates.check_off"
  | "toggles.updates.check_on"
  | "toggles.updates.install.ui"
  | "toggles.updates.install.ui_step_up"
  | "toggles.updates.install.upload_only"
  | "toggles.updates.name"
  | "toggles.updates.value"
  | "topology.controller.error_generic"
  | "topology.controller.label"
  | "topology.controller.ok"
  | "topology.edge.lldp"
  | "topology.edge.uplink"
  | "topology.edge.vm_host"
  | "topology.edge.wired"
  | "topology.edge.wireless"
  | "topology.empty.body"
  | "topology.empty.filtered"
  | "topology.empty.filtered_hint"
  | "topology.empty.link"
  | "topology.empty.title"
  | "topology.filter.clear"
  | "topology.filter.label"
  | "topology.filter.placeholder"
  | "topology.filter.site"
  | "topology.filter.site_all"
  | "topology.filter.unknown_site"
  | "topology.filter.unknown_vlan"
  | "topology.filter.vlan"
  | "topology.filter.vlan_all"
  | "topology.group.aria"
  | "topology.group.close_all"
  | "topology.group.label"
  | "topology.kind.access_point"
  | "topology.kind.container"
  | "topology.kind.device"
  | "topology.kind.host"
  | "topology.kind.hypervisor"
  | "topology.kind.router"
  | "topology.kind.switch"
  | "topology.kind.vm"
  | "topology.legend.edges"
  | "topology.legend.kinds"
  | "topology.legend.label"
  | "topology.legend.too_many"
  | "topology.legend.vlans"
  | "topology.legend.vlans_none"
  | "topology.loading"
  | "topology.map.label"
  | "topology.neighbour.local"
  | "topology.neighbour.remote"
  | "topology.neighbour.ssid"
  | "topology.networks.dhcp.disabled"
  | "topology.networks.dhcp.relay"
  | "topology.networks.dhcp.server"
  | "topology.networks.management"
  | "topology.networks.no_subnet"
  | "topology.networks.none"
  | "topology.networks.summary"
  | "topology.networks.title"
  | "topology.networks.untagged"
  | "topology.node.aria"
  | "topology.panel.back"
  | "topology.panel.details"
  | "topology.panel.host_link"
  | "topology.panel.intent"
  | "topology.panel.intent_addresses"
  | "topology.panel.intent_no_addresses"
  | "topology.panel.intent_none"
  | "topology.panel.ips"
  | "topology.panel.label"
  | "topology.panel.last_seen"
  | "topology.panel.macs"
  | "topology.panel.model"
  | "topology.panel.neighbours"
  | "topology.panel.neighbours_none"
  | "topology.panel.observation_link"
  | "topology.panel.os"
  | "topology.panel.paths"
  | "topology.panel.ports"
  | "topology.panel.ports_none"
  | "topology.panel.sources"
  | "topology.panel.ssids"
  | "topology.panel.vendor"
  | "topology.panel.vlans"
  | "topology.path.clear"
  | "topology.path.from"
  | "topology.path.is_router"
  | "topology.path.no_route"
  | "topology.path.none"
  | "topology.path.router"
  | "topology.path.show"
  | "topology.path.start"
  | "topology.path.start_here"
  | "topology.port.connected"
  | "topology.port.count"
  | "topology.port.down"
  | "topology.port.hide"
  | "topology.port.hide_aria"
  | "topology.port.nothing"
  | "topology.port.open"
  | "topology.port.open_aria"
  | "topology.port.unknown"
  | "topology.port.up"
  | "topology.port.uplink"
  | "topology.port.vlan"
  | "topology.source.intent"
  | "topology.source.inventory"
  | "topology.source.network_controller"
  | "topology.source.probe"
  | "topology.summary"
  | "topology.truncated"
  | "topology.zoom.fit"
  | "topology.zoom.in"
  | "topology.zoom.label"
  | "topology.zoom.out"
  | "updates.attempt.failed"
  | "updates.attempt.rolled_back"
  | "updates.blocked.air_gapped"
  | "updates.blocked.cluster"
  | "updates.blocked.container"
  | "updates.blocked.in_progress"
  | "updates.blocked.layout_missing"
  | "updates.blocked.no_asset"
  | "updates.blocked.other"
  | "updates.blocked.settings_link"
  | "updates.blocked.unsupervised"
  | "updates.blocked.unsupported_platform"
  | "updates.blocked.up_to_date"
  | "updates.blocked.upload_only"
  | "updates.check.checking"
  | "updates.check.error"
  | "updates.check.found"
  | "updates.check.heading"
  | "updates.check.last"
  | "updates.check.never"
  | "updates.check.none"
  | "updates.check.now"
  | "updates.check.off_air_gapped"
  | "updates.check.off_setting"
  | "updates.check.on"
  | "updates.check.settings_link"
  | "updates.check.source"
  | "updates.check.state"
  | "updates.code_unknown"
  | "updates.install.blocked_title"
  | "updates.install.button"
  | "updates.install.confirm_action"
  | "updates.install.confirm_body"
  | "updates.install.confirm_ok"
  | "updates.install.confirm_security"
  | "updates.install.confirm_title"
  | "updates.install.confirm_upload"
  | "updates.install.copy_failed"
  | "updates.install.heading"
  | "updates.install.lead"
  | "updates.install.pull_lead"
  | "updates.install.step_up_hint"
  | "updates.install.up_to_date"
  | "updates.manifest.fetched"
  | "updates.manifest.heading"
  | "updates.manifest.uploaded"
  | "updates.mark.action"
  | "updates.mark.security"
  | "updates.module.body"
  | "updates.module.home"
  | "updates.module.name.dhcp"
  | "updates.module.name.discovery"
  | "updates.module.name.dns"
  | "updates.module.name.ipam"
  | "updates.module.title"
  | "updates.progress.failed"
  | "updates.progress.failed_unknown"
  | "updates.progress.heading"
  | "updates.progress.job_link"
  | "updates.release.action_title"
  | "updates.release.action_unspecified"
  | "updates.release.format"
  | "updates.release.newest"
  | "updates.release.no_notes"
  | "updates.release.title"
  | "updates.releases.count"
  | "updates.releases.heading"
  | "updates.releases.none"
  | "updates.restart.body"
  | "updates.restart.check_log"
  | "updates.restart.check_previous"
  | "updates.restart.check_service"
  | "updates.restart.confirmed"
  | "updates.restart.reason"
  | "updates.restart.reload"
  | "updates.restart.rolled_back"
  | "updates.restart.timeout_body"
  | "updates.restart.timeout_title"
  | "updates.restart.title"
  | "updates.running.format"
  | "updates.running.heading"
  | "updates.running.newest"
  | "updates.running.platform"
  | "updates.running.up_to_date"
  | "updates.running.version"
  | "updates.stepup.body"
  | "updates.stepup.button"
  | "updates.stepup.title"
  | "updates.sub"
  | "updates.title"
  | "updates.unavailable"
  | "updates.upload.button"
  | "updates.upload.chosen"
  | "updates.upload.expected"
  | "updates.upload.file_label"
  | "updates.upload.heading"
  | "updates.upload.lead"
  | "updates.upload.manifest_button"
  | "updates.upload.manifest_done"
  | "updates.upload.manifest_help"
  | "updates.upload.manifest_label"
  | "updates.upload.need_manifest"
  | "updates.upload.uploading"
  | "updates.upload.version_label"
  | "updates.whatsnew.close"
  | "updates.whatsnew.empty"
  | "updates.whatsnew.lead"
  | "updates.whatsnew.lead_first"
  | "updates.whatsnew.title"
  | "vault.controllers.col.node"
  | "vault.controllers.col.updated"
  | "vault.controllers.heading"
  | "vault.downgrade"
  | "vault.generations.active"
  | "vault.generations.col.created"
  | "vault.generations.col.id"
  | "vault.generations.col.state"
  | "vault.generations.heading"
  | "vault.generations.loaded"
  | "vault.generations.missing"
  | "vault.key.active"
  | "vault.key.epoch"
  | "vault.key.heading"
  | "vault.key.protection"
  | "vault.key.provider"
  | "vault.key.strongest"
  | "vault.lede"
  | "vault.phase.distributing"
  | "vault.phase.done"
  | "vault.phase.failed"
  | "vault.phase.requested"
  | "vault.phase.rewrapping"
  | "vault.protection.dpapi_machine"
  | "vault.protection.dpapi_user"
  | "vault.protection.memory"
  | "vault.protection.plain_file"
  | "vault.protection.systemd_creds_host"
  | "vault.protection.systemd_creds_tpm2"
  | "vault.provider.dpapi"
  | "vault.provider.file"
  | "vault.provider.systemd_credential"
  | "vault.provider.systemd_creds"
  | "vault.refused.title"
  | "vault.rotation.confirm_body"
  | "vault.rotation.confirm_note"
  | "vault.rotation.confirm_title"
  | "vault.rotation.error"
  | "vault.rotation.finished_at"
  | "vault.rotation.generation"
  | "vault.rotation.heading"
  | "vault.rotation.lede"
  | "vault.rotation.never"
  | "vault.rotation.phase"
  | "vault.rotation.requested"
  | "vault.rotation.requested_at"
  | "vault.rotation.rewrapped"
  | "vault.rotation.rotate"
  | "vault.rotation.unreachable"
  | "vault.rotation.unreachable_text"
  | "vault.rotation.waiting_for"
  | "vault.step_up.body"
  | "vault.step_up.sign_in"
  | "vault.step_up.title"
  | "vault.title"
  | "vault.warning.downgrade"
  | "vault.warning.missing"
  | "vault.warning.rotation_failed"
  | "vault.warning.weak"
  | "vault.weak";
/** Arguments of the messages that take any. */
export interface MessageArgs {
  "access.grant.text": { role: string | number; scope: string | number };
  "access.grants.created": { holder: string | number };
  "access.grants.revoke_body": { grant: string | number; holder: string | number };
  "access.grants.revoke_cascade": { count: number };
  "access.grants.revoke_named": { grant: string | number; holder: string | number };
  "access.grants.revoke_title": { holder: string | number };
  "access.grants.revoked": { count: number; holder: string | number };
  "access.picker.prefix_option": { cidr: string | number; vrf: string | number };
  "access.roles.dialog_title": { role: string | number };
  "access.roles.edit_named": { role: string | number };
  "access.roles.follow_profile": { profile: string | number };
  "access.roles.saved": { role: string | number };
  "access.roles.stored": { profile: string | number };
  "access.roles.weaker": { profile: string | number };
  "access.sa.created": { name: string | number };
  "access.sa.summary": { display: string | number; owner: string | number; roles: string | number };
  "access.sa.token_revoked": { name: string | number };
  "access.sa.tokens_of": { name: string | number };
  "access.scope.object": { id: string | number; kind: string | number };
  "access.scope.prefix": { cidr: string | number };
  "access.scope.prefix_subtree": { cidr: string | number };
  "access.scope.site": { name: string | number };
  "access.scope.site_subtree": { name: string | number };
  "access.scope.tenant": { id: string | number };
  "access.scope.vrf": { name: string | number };
  "access.subject.option": { label: string | number; name: string | number };
  "access.subject.service": { name: string | number };
  "access.token.created_body": { name: string | number };
  "access.token.days": { count: number };
  "access.token.max_days": { days: string | number };
  "access.token.remove_grant": { n: string | number };
  "access.token.revoke_body": { account: string | number };
  "access.token.revoke_named": { name: string | number };
  "access.token.revoke_title": { name: string | number };
  "account.methods.requires": { method: string | number; profile: string | number };
  "account.methods.signed_in_with": { method: string | number };
  "account.passkey.created": { date: string | number };
  "account.passkey.last_used": { when: string | number };
  "account.passkey.remove_named": { name: string | number };
  "account.passkey.remove_title": { name: string | number };
  "account.passkey.removed": { name: string | number };
  "account.password.changed_others": { count: number };
  "account.password.rule.length": { min: string | number };
  "account.password.rule.passphrase": { min: string | number };
  "account.password.rule.pattern": { min: string | number };
  "account.password.rule.pin": { min: string | number };
  "account.password.rule.profile": { profile: string | number };
  "account.recovery.left": { count: number };
  "account.sessions.client": { browser: string | number; os: string | number };
  "account.sessions.confirm_body": { count: number };
  "account.sessions.confirm_button": { count: number };
  "account.sessions.revoke_named": { client: string | number };
  "account.sessions.revoked_many": { count: number };
  "account.tokens.created_body": { name: string | number };
  "account.tokens.days": { count: number };
  "account.tokens.max_days": { days: string | number; profile: string | number };
  "account.tokens.max_none": { profile: string | number };
  "account.tokens.revoke_named": { name: string | number };
  "account.tokens.revoke_title": { name: string | number };
  "account.tokens.revoked": { name: string | number };
  "account.totp.params": { algorithm: string | number; digits: string | number; period: string | number };
  "audit.chain.broken": { seq: string | number };
  "audit.chain.checked": { time: string | number };
  "audit.chain.detail": { detail: string | number };
  "audit.chain.intact": { count: number; seq: string | number };
  "audit.chain.open_record": { seq: string | number };
  "audit.chain.verified_before": { count: number };
  "audit.live.new": { count: number };
  "audit.live.new_many": { count: string | number };
  "audit.record.not_found": { seq: string | number };
  "audit.record.open_newest": { seq: string | number };
  "audit.record.title": { seq: string | number };
  "audit.row": { seq: string | number };
  "audit_export.checkpoint": { seq: string | number; when: string | number };
  "audit_export.delivered": { when: string | number };
  "audit_export.failing_since": { when: string | number };
  "audit_export.paused": { name: string | number };
  "audit_export.policy.value": { value: string | number };
  "audit_export.remove_named": { name: string | number };
  "audit_export.remove_title": { name: string | number };
  "audit_export.removed": { name: string | number };
  "audit_export.resumed": { name: string | number };
  "audit_export.saved": { name: string | number };
  "audit_export.test_failed": { detail: string | number; ms: string | number };
  "audit_export.test_ok": { ms: string | number };
  "audit_export.warning.failing": { sinks: string | number };
  "auth.signin.retry_in": { seconds: number };
  "backup.create.done": { file: string | number };
  "backup.create.error.short": { min: number };
  "backup.create.passphrase_help": { min: number };
  "backup.restore.open_named": { file: string | number };
  "backup.restore.slots": { slots: string | number };
  "backup.restore.title": { file: string | number };
  "backup.restored.body": { at: string | number; created: string | number; file: string | number };
  "backup.restored.nodes": { node: string | number; revision: number; source: string | number };
  "backup.schedule.error.interval": { max: number; min: number };
  "backup.schedule.error.keep": { max: number; min: number };
  "backup.schedule.every": { interval: string | number };
  "backup.schedule.interval_help": { every: string | number };
  "backup.schedule.saved": { schedule: string | number };
  "backup.schedule.target_dir_help": { dir: string | number };
  "backup.warning.failed": { error: string | number };
  "backup.warning.stale": { days: number };
  "certificates.chain_len": { count: number };
  "certificates.days": { days: number };
  "certificates.error": { error: string | number };
  "certificates.expiry.expired": { date: string | number };
  "certificates.expiry.not_yet_valid": { date: string | number };
  "certificates.expiry.soon": { date: string | number; days: number };
  "certificates.imported.interval.value": { seconds: number };
  "certificates.min_version.value": { version: string | number };
  "certificates.pending.detected": { time: string | number };
  "certificates.read_at": { time: string | number };
  "cluster.action.promote_named": { name: string | number };
  "cluster.action.remove_named": { name: string | number };
  "cluster.col.format": { format: string | number };
  "cluster.compat.format_one": { format: number };
  "cluster.compat.format_range": { from: number; to: number };
  "cluster.compat.tooltip": { formats: string | number; majors: string | number; wire: string | number };
  "cluster.digests.agree": { count: number; revision: string | number };
  "cluster.digests.differ": { revision: string | number };
  "cluster.done.promoted": { name: string | number };
  "cluster.done.removed": { name: string | number };
  "cluster.done.stepped_down": { name: string | number; term: string | number };
  "cluster.format.knows": { format: number };
  "cluster.member.unnamed": { id: string | number };
  "cluster.members.count": { count: number };
  "cluster.no_quorum.body_since": { since: string | number };
  "cluster.no_quorum.queued": { expires: string | number };
  "cluster.partition.conflicts": { count: number };
  "cluster.partition.electing.body": { duration: string | number };
  "cluster.partition.isolated.body": { duration: string | number };
  "cluster.partition.stale": { age: string | number };
  "cluster.partition.stale_title": { revision: string | number };
  "cluster.preview.change": { after: string | number; before: string | number };
  "cluster.preview.same": { count: string | number };
  "cluster.promote.title": { name: string | number };
  "cluster.queue.action": { action: string; kind: string | number };
  "cluster.queue.cancel_body": { what: string | number };
  "cluster.queue.cancel_named": { what: string | number };
  "cluster.queue.count": { count: number };
  "cluster.queue.discard_body": { what: string | number };
  "cluster.queue.discard_named": { what: string | number };
  "cluster.queue.dismiss_named": { what: string | number };
  "cluster.queue.kind": { kind: string };
  "cluster.queue.reapply_intro": { what: string | number };
  "cluster.queue.reapply_named": { what: string | number };
  "cluster.remove.title": { name: string | number };
  "cluster.step_down.successor": { name: string | number };
  "cluster.summary.since": { since: string | number };
  "cluster.summary.voters_value": { count: number; tolerance: string | number };
  "cluster.tolerance": { count: number };
  "cluster.warning.migration_blocked": { nodes: string | number; stored: string | number; target: string | number };
  "common.count.items": { count: number };
  "common.greeting": { name: string | number };
  "connectors.delete.title": { name: string | number };
  "connectors.detail.check_failed": { error: string | number };
  "connectors.detail.ms": { ms: string | number };
  "connectors.detail.pages": { observations: number; pages: number };
  "connectors.form.default": { value: string | number };
  "connectors.form.default_secs": { secs: string | number };
  "connectors.form.example": { value: string | number };
  "connectors.form.interval_range": { max: string | number; min: string | number };
  "connectors.form.item_add_to": { field: string | number };
  "connectors.form.item_label": { field: string | number; n: string | number };
  "connectors.form.item_remove": { field: string | number; n: string | number };
  "connectors.form.name_long": { max: string | number };
  "connectors.form.plugin_fixed": { plugin: string | number; version: string | number };
  "connectors.form.secret_purpose": { purpose: string | number };
  "connectors.form.secret_tagged": { purpose: string | number };
  "connectors.form.title_edit": { name: string | number };
  "connectors.problem.enum": { values: string | number };
  "connectors.problem.format": { format: string };
  "connectors.problem.items": { max: number; min: string | number };
  "connectors.problem.items_max": { max: number };
  "connectors.problem.items_min": { min: number };
  "connectors.problem.length": { max: number; min: string | number };
  "connectors.problem.length_max": { max: number };
  "connectors.problem.length_min": { min: number };
  "connectors.problem.pattern": { pattern: string | number };
  "connectors.problem.range": { max: string | number; min: string | number };
  "connectors.problem.range_max": { max: string | number };
  "connectors.problem.range_min": { min: string | number };
  "connectors.problem.type": { type: string | number };
  "connectors.process.until": { at: string | number };
  "connectors.run.succeeded": { count: number };
  "connectors.seconds": { secs: string | number };
  "connectors.seconds_default": { secs: string | number };
  "connectors.toast.change_failed": { name: string | number };
  "connectors.toast.check_failed": { name: string | number };
  "connectors.toast.checked": { health: string | number; name: string | number };
  "connectors.toast.delete_failed": { name: string | number };
  "connectors.toast.deleted": { name: string | number };
  "connectors.toast.disabled": { name: string | number };
  "connectors.toast.enabled": { name: string | number };
  "connectors.toast.run": { name: string | number };
  "connectors.toast.run_failed": { name: string | number };
  "dashboard.modules.restart_body": { configured: string | number; running: string | number };
  "dashboard.tile.alarms_hint": { critical: number };
  "dashboard.tile.connectors_hint": { failing: number; total: string | number };
  "dashboard.tile.nodes_hint": { mismatched: number; total: string | number };
  "dashboard.tile.proposals_hint": { conflicts: number };
  "dashboard.tile.waiting_for_you": { count: number };
  "dashboard.update.body": { running: string | number; version: string | number };
  "dashboard.use.more": { count: number };
  "dashboard.use.vrf": { tenant: string | number; vrf: string | number };
  "dashboard.waiting.step": { step: number; total: number };
  "dhcp.action.ddns_on_zone": { zone: string | number };
  "dhcp.action.lease": { lease: string | number };
  "dhcp.action.range": { first: string | number; last: string | number };
  "dhcp.arch.option": { code: string | number; name: string | number };
  "dhcp.boot.add_done": { name: string | number };
  "dhcp.boot.add_matches": { words: string | number };
  "dhcp.boot.add_partial_class": { class: string | number };
  "dhcp.boot.add_partial_policy": { policy: string | number };
  "dhcp.boot.form_help": { network: string | number };
  "dhcp.boot.inherited": { value: string | number };
  "dhcp.check.exclusion_first": { network: string | number };
  "dhcp.check.exclusion_last": { network: string | number };
  "dhcp.check.exclusion_order": { network: string | number };
  "dhcp.check.exclusion_outside": { network: string | number };
  "dhcp.class.created": { name: string | number };
  "dhcp.class.delete_title": { name: string | number };
  "dhcp.class.deleted": { name: string | number };
  "dhcp.class.edit_title": { name: string | number };
  "dhcp.class.saved": { name: string | number };
  "dhcp.ddns.hardened_note": { profile: string | number };
  "dhcp.ddns.profile_open": { profile: string | number };
  "dhcp.ddns.profile_strict": { profile: string | number };
  "dhcp.ddns.saved": { network: string | number };
  "dhcp.ddns.server_now": { words: string | number };
  "dhcp.ddns.title": { network: string | number };
  "dhcp.ddns.words.on": { parts: string | number };
  "dhcp.ddns.words.ttl": { seconds: string | number };
  "dhcp.ddns.words.zone": { zone: string | number };
  "dhcp.ddns.zone_state.profile_off": { profile: string | number };
  "dhcp.ddns.zone_state.profile_on": { profile: string | number };
  "dhcp.ddns.zone_unknown": { id: string | number };
  "dhcp.def.created": { name: string | number };
  "dhcp.def.delete_title": { name: string | number };
  "dhcp.def.deleted": { name: string | number };
  "dhcp.effective.why.policy": { name: string | number };
  "dhcp.exclusion.created": { count: number };
  "dhcp.exclusion.delete_title": { range: string | number };
  "dhcp.exclusion.deleted": { range: string | number };
  "dhcp.exclusion.help": { network: string | number };
  "dhcp.filter.created": { mac: string | number };
  "dhcp.filter.delete_title": { mac: string | number };
  "dhcp.filter.deleted": { mac: string | number };
  "dhcp.filter.edit_title": { mac: string | number };
  "dhcp.filter.saved": { mac: string | number };
  "dhcp.lease.release_body": { addr: string | number; mac: string | number };
  "dhcp.lease.release_title": { addr: string | number };
  "dhcp.lease.released": { addr: string | number };
  "dhcp.lease.server_now": { lease: string | number };
  "dhcp.lease.unit": { name: string | number };
  "dhcp.lease.words": { default: string | number; max: string | number; min: string | number };
  "dhcp.live.folded": { count: number };
  "dhcp.live.new": { count: number };
  "dhcp.live.new_capped": { count: string | number };
  "dhcp.live.new_since": { time: string | number };
  "dhcp.live.scope_more": { count: number };
  "dhcp.live.scope_pick": { network: string | number };
  "dhcp.match.architecture": { value: string | number };
  "dhcp.match.architecture_named": { code: string | number; name: string | number };
  "dhcp.match.circuit_id": { value: string | number };
  "dhcp.match.client_id": { value: string | number };
  "dhcp.match.host_name": { value: string | number };
  "dhcp.match.host_name_prefix": { value: string | number };
  "dhcp.match.mac": { value: string | number };
  "dhcp.match.remote_id": { value: string | number };
  "dhcp.match.remove": { label: string | number };
  "dhcp.match.row": { n: string | number };
  "dhcp.match.user_class": { value: string | number };
  "dhcp.match.vendor_class": { value: string | number };
  "dhcp.match.vendor_class_prefix": { value: string | number };
  "dhcp.network.created": { name: string | number };
  "dhcp.network.delete_title": { name: string | number };
  "dhcp.network.deleted": { name: string | number };
  "dhcp.network.edit_title": { name: string | number };
  "dhcp.network.saved": { name: string | number };
  "dhcp.optset.kind_list": { kind: string | number };
  "dhcp.optset.remove": { name: string | number };
  "dhcp.optset.unknown": { code: string | number };
  "dhcp.optset.value_of": { name: string | number };
  "dhcp.policy.created": { name: string | number };
  "dhcp.policy.delete_title": { name: string | number };
  "dhcp.policy.deleted": { name: string | number };
  "dhcp.policy.edit_title": { name: string | number };
  "dhcp.policy.options.label": { name: string | number };
  "dhcp.policy.saved": { name: string | number };
  "dhcp.pool.clear_title": { first: string | number; last: string | number };
  "dhcp.pool.cleared": { first: string | number; last: string | number };
  "dhcp.pool.edit_title": { first: string | number; last: string | number };
  "dhcp.pool.lease_range": { lease: string | number };
  "dhcp.pool.saved": { first: string | number; last: string | number };
  "dhcp.pools.ipam_link": { network: string | number };
  "dhcp.reservations.lease_ends": { when: string | number };
  "dhcp.reservations.lease_other": { client: string | number };
  "dhcp.reserve.host_option": { mode: string | number; name: string | number };
  "dhcp.reserve.in_pool": { first: string | number; ip: string | number; last: string | number };
  "dhcp.reserve.in_pool_lease": { first: string | number; ip: string | number; last: string | number };
  "dhcp.reserve.no_scope": { ip: string | number };
  "dhcp.reserve.open_host": { host: string | number };
  "dhcp.reserve.outside": { cidr: string | number; ip: string | number };
  "dhcp.reserve.saved": { host: string | number; ip: string | number };
  "dhcp.reserve.saved_unchanged": { host: string | number; ip: string | number };
  "dhcp.reserve.scope_disabled": { cidr: string | number };
  "dhcp.reserve.scope_not_serving": { cidr: string | number };
  "dhcp.reserve.scope_served": { cidr: string | number };
  "dhcp.reserve.title": { ip: string | number };
  "dhcp.reserve.use_free": { ip: string | number };
  "dhcp.reserve.will.address_bound": { ip: string | number; name: string | number };
  "dhcp.reserve.will.address_kept": { ip: string | number; status: string | number };
  "dhcp.reserve.will.address_new": { ip: string | number; name: string | number; status: string | number };
  "dhcp.reserve.will.address_status": { ip: string | number; status: string | number };
  "dhcp.reserve.will.host_kept": { name: string | number };
  "dhcp.reserve.will.host_mode": { mode: string | number; name: string | number };
  "dhcp.reserve.will.host_new": { name: string | number };
  "dhcp.reserve.will.interface_client_id": { client_id: string | number; name: string | number };
  "dhcp.reserve.will.interface_client_id_cleared": { name: string | number };
  "dhcp.reserve.will.interface_mac": { mac: string | number; name: string | number };
  "dhcp.reserve.will.interface_mac_kept": { mac: string | number; name: string | number };
  "dhcp.reserve.will.interface_mac_replaced": { mac: string | number; name: string | number; old: string | number };
  "dhcp.reserve.will.interface_new": { name: string | number };
  "dhcp.reserve.will.interface_new_mac": { mac: string | number; name: string | number };
  "dhcp.reserve.will.keyed_client_id": { value: string | number };
  "dhcp.reserve.will.keyed_mac": { value: string | number };
  "dhcp.reserve.will.lease_other": { ip: string | number; mac: string | number };
  "dhcp.reserve.will.not_serving": { cidr: string | number };
  "dhcp.reserve.will.scope_disabled": { cidr: string | number };
  "dhcp.reserve.will.scope_served": { cidr: string | number };
  "dhcp.scope.created": { network: string | number };
  "dhcp.scope.delete_body": { network: string | number };
  "dhcp.scope.delete_title": { network: string | number };
  "dhcp.scope.deleted": { network: string | number };
  "dhcp.scope.options_title": { network: string | number };
  "dhcp.scope.saved": { network: string | number };
  "dhcp.settings.effective": { value: string | number };
  "dhcp.settings.effective_days": { days: number };
  "dhcp.strip.commit": { ms: string | number };
  "dhcp.strip.listeners": { count: number };
  "dhcp.strip.revision": { revision: string | number };
  "dhcp.strip.scopes": { count: number };
  "dhcp.term.class": { name: string | number };
  "dhcp.term.not_class": { name: string | number };
  "dhcp.term.not_match": { match: string | number };
  "dhcp.term.remove": { n: string | number };
  "dhcp.term.row": { n: string | number };
  "dhcp.util.at": { time: string | number };
  "dhcp.util.label": { percent: string | number };
  "discovery.approve.confirm": { count: number };
  "discovery.batch.approve": { count: number };
  "discovery.batch.approve_body": { kinds: string | number };
  "discovery.batch.approve_confirm": { count: number };
  "discovery.batch.approve_title": { count: number };
  "discovery.batch.done_approved": { count: number };
  "discovery.batch.done_rejected": { count: number };
  "discovery.batch.done_skipped": { count: number };
  "discovery.batch.kind.address_mismatch": { count: number };
  "discovery.batch.kind.conflict": { count: number };
  "discovery.batch.kind.discovered_host": { count: number };
  "discovery.batch.kind.orphaned_intent": { count: number };
  "discovery.batch.kind.outside_prefixes": { count: number };
  "discovery.batch.kind.prefix_vlan_mismatch": { count: number };
  "discovery.batch.kind.vlan_discovered": { count: number };
  "discovery.batch.loaded_only": { count: number };
  "discovery.batch.reject": { count: number };
  "discovery.batch.reject_body": { kinds: string | number };
  "discovery.batch.reject_title": { count: number };
  "discovery.batch.skipped_title": { count: number };
  "discovery.count": { count: number; more: string };
  "discovery.count_open": { count: number; more: string };
  "discovery.fact.address_mac": { ip: string | number; mac: string | number };
  "discovery.fact.attachment": { mac: string | number; where: string | number };
  "discovery.fact.attachment_vlan": { mac: string | number; vlan: string | number; where: string | number };
  "discovery.fact.link": { a: string | number; b: string | number; kind: string | number };
  "discovery.fact.name": { ip: string | number; name: string | number };
  "discovery.fact.network": { name: string | number; subnet: string; vlan: string };
  "discovery.fact.no_ports": { ip: string | number };
  "discovery.fact.os": { confidence: string | number; guess: string | number; ip: string | number };
  "discovery.fact.parent": { parent: string | number };
  "discovery.fact.port": { port: string | number };
  "discovery.fact.ports": { ip: string | number; ports: string | number };
  "discovery.fact.ssid": { ssid: string | number };
  "discovery.fact.tls": { ports: string | number };
  "discovery.fact.vendor": { mac: string | number; vendor: string | number };
  "discovery.filter.prefix": { prefix: string | number };
  "discovery.filter.remove": { filter: string | number };
  "discovery.panel.adoption_failed": { error: string | number };
  "discovery.panel.change_count": { count: number };
  "discovery.panel.evidence_count": { count: number };
  "discovery.panel.opened": { rule: string | number };
  "discovery.panel.sightings": { count: number };
  "discovery.reject.reason_too_long": { max: number };
  "discovery.report.at": { at: string | number };
  "discovery.rule.address_mismatch": { host: string | number; intended: string | number; ip: string | number };
  "discovery.rule.address_unrecorded": { host: string | number; ip: string | number };
  "discovery.rule.conflict_address_taken": { host: string | number; intended_mac: string | number; ip: string | number; macs: string | number };
  "discovery.rule.conflict_networks": { count: number; mac: string | number; networks: string | number };
  "discovery.rule.conflict_shared_address": { count: number; ip: string | number; macs: string | number };
  "discovery.rule.discovered_address": { ips: string; mac: string; name: string | number; sources: number };
  "discovery.rule.discovered_mac": { ips: string; mac: string; name: string | number; sources: number };
  "discovery.rule.orphaned_address": { host: string; ip: string | number; last_seen: string | number };
  "discovery.rule.outside_prefixes": { cidr: string | number; count: number };
  "discovery.rule.prefix_vlan_differs": { cidr: string | number; current: string | number; name: string | number; vid: string | number };
  "discovery.rule.prefix_vlan_unset": { cidr: string | number; name: string | number; vid: string | number };
  "discovery.rule.vlan_discovered": { name: string | number; vid: string | number };
  "discovery.source.dhcp": { node: string | number };
  "discovery.source.dns": { zone: string | number };
  "discovery.source.inventory": { name: string | number };
  "discovery.source.network_controller": { name: string | number };
  "discovery.source.probe": { method: string | number; node: string | number };
  "discovery.subject.fact_count": { count: number };
  "discovery.subject.unknown": { subject: string | number };
  "discovery.subject.vlan": { vlan: string | number };
  "dns.acl.created": { name: string | number };
  "dns.acl.delete_title": { name: string | number };
  "dns.acl.delete_used": { zones: string | number };
  "dns.acl.deleted": { name: string | number };
  "dns.acl.edit_title": { name: string | number };
  "dns.acl.entry_invalid": { line: string | number };
  "dns.acl.saved": { name: string | number };
  "dns.anchor.added": { zone: string | number };
  "dns.anchor.form.ds": { digest: string | number };
  "dns.anchor.keys_of": { zone: string | number };
  "dns.anchor.pending": { count: number };
  "dns.anchor.refresh_sent": { zone: string | number };
  "dns.anchor.remove_body": { zone: string | number };
  "dns.anchor.remove_title": { zone: string | number };
  "dns.anchor.removed": { zone: string | number };
  "dns.anchor.source.shipped": { release: string | number };
  "dns.anchor.state_since": { time: string | number };
  "dns.batch.applied": { count: number; serial: string | number };
  "dns.batch.apply": { count: number };
  "dns.batch.count": { changes: string | number; count: number };
  "dns.batch.diff_summary": { count: number };
  "dns.batch.drop": { name: string | number; type: string | number };
  "dns.blocking.allow.added": { list: string | number };
  "dns.blocking.allow_label": { name: string | number };
  "dns.blocking.hours.bar": { blocked: string | number; queries: number; time: string | number };
  "dns.blocking.pause.left": { left: string | number };
  "dns.blocking.pause.until": { time: string | number };
  "dns.blocking.period": { from: string | number; until: string | number };
  "dns.blocking.sample": { sample: string | number };
  "dns.blocking.short_log": { days: number };
  "dns.blocking.tile.cached_hint": { share: string | number };
  "dns.blocking.tile.clients_hint": { mode: string };
  "dns.blocking.tile.queries_hint": { window: string };
  "dns.cache.capped": { count: string | number };
  "dns.cache.ede": { code: string | number };
  "dns.cache.ede_hint": { code: string | number };
  "dns.cache.empty_suffix": { suffix: string | number };
  "dns.cache.flush": { suffix: string | number };
  "dns.cache.flush_body": { suffix: string | number };
  "dns.cache.flush_title": { suffix: string | number };
  "dns.cache.flushed": { suffix: string | number };
  "dns.cache.more": { count: string | number };
  "dns.cache.page": { page: string | number };
  "dns.cache.rows_shown": { shown: string | number; total: string | number };
  "dns.cache.signature": { signer: string | number; time: string | number; type: string | number };
  "dns.cache.signature_expiry": { time: string | number };
  "dns.cache.ttl_h": { value: string | number };
  "dns.cache.ttl_min": { value: string | number };
  "dns.cache.ttl_s": { value: string | number };
  "dns.dnssec.parent_ds": { ds: string | number; zone: string | number };
  "dns.fwd.check.address": { entry: string | number };
  "dns.fwd.check.path": { entry: string | number };
  "dns.fwd.check.path_transport": { entry: string | number };
  "dns.fwd.check.port": { entry: string | number };
  "dns.fwd.created": { suffix: string | number };
  "dns.fwd.delete_title": { suffix: string | number };
  "dns.fwd.deleted": { suffix: string | number };
  "dns.fwd.edit_title": { suffix: string | number };
  "dns.fwd.field.all_views_help": { view: string | number };
  "dns.fwd.known": { name: string | number; tls: string | number };
  "dns.fwd.recursion.hardened": { profile: string | number };
  "dns.fwd.recursion.known": { profile: string | number };
  "dns.fwd.recursion.lab": { profile: string | number };
  "dns.fwd.resolution.choice.default": { profile: string | number };
  "dns.fwd.resolution.of": { view: string | number };
  "dns.fwd.resolution.saved": { view: string | number };
  "dns.fwd.saved": { suffix: string | number };
  "dns.import.apply.progress": { done: string | number; total: string | number };
  "dns.import.apply.serial": { serial: string | number };
  "dns.import.fact.added": { count: number };
  "dns.import.fact.removed": { count: number };
  "dns.import.fact.replaced": { count: number };
  "dns.import.losses.title": { count: number };
  "dns.import.parse_error": { line: string | number };
  "dns.import.upload.lines": { count: number };
  "dns.infra.empty_suffix": { suffix: string | number };
  "dns.infra.flush_body_suffix": { suffix: string | number };
  "dns.infra.flush_suffix": { suffix: string | number };
  "dns.infra.flush_title_suffix": { suffix: string | number };
  "dns.infra.flushed_all": { entries: number };
  "dns.infra.flushed_suffix": { entries: number; suffix: string | number };
  "dns.infra.ms": { ms: string | number };
  "dns.infra.no_addresses": { servers: number };
  "dns.infra.servers_of": { zone: string | number };
  "dns.key.created_body": { name: string | number };
  "dns.key.delete_title": { name: string | number };
  "dns.key.deleted": { name: string | number };
  "dns.list.check.interval": { max: string | number; min: string | number };
  "dns.list.created": { name: string | number };
  "dns.list.delete_title": { name: string | number };
  "dns.list.deleted": { name: string | number };
  "dns.list.edit_title": { name: string | number };
  "dns.list.every": { hours: number };
  "dns.list.fetch_failed": { name: string | number };
  "dns.list.fetch_started": { name: string | number };
  "dns.list.field.interval_help": { max: string | number; min: string | number };
  "dns.list.file_chosen": { name: string | number };
  "dns.list.job": { name: string | number };
  "dns.list.saved": { name: string | number };
  "dns.list.upload_title": { name: string | number };
  "dns.list.uploaded": { name: string | number };
  "dns.log.ede": { code: string | number; name: string | number };
  "dns.log.figures": { client: string | number; days: number; dropped: number; sample: number; written: number };
  "dns.log.latency": { ms: string | number };
  "dns.log.node": { id: string | number };
  "dns.log.page": { page: string | number };
  "dns.node.no_role_body": { roles: string | number };
  "dns.node.tls": { doh: string | number; dot: string | number };
  "dns.nta.check.reason_long": { max: string | number };
  "dns.nta.created": { zone: string | number };
  "dns.nta.delete_body": { zone: string | number };
  "dns.nta.delete_title": { zone: string | number };
  "dns.nta.deleted": { zone: string | number };
  "dns.record.line_error": { line: string | number; message: string | number };
  "dns.records.label": { zone: string | number };
  "dns.recursion.infra.of": { count: string | number; max: string | number };
  "dns.recursion.ms": { ms: string | number };
  "dns.recursion.priming.duration": { ms: string | number };
  "dns.rrset.add_records_title": { name: string | number; type: string | number };
  "dns.rrset.delete_body": { count: number };
  "dns.rrset.delete_title": { name: string | number; type: string | number };
  "dns.rrset.edit_data": { name: string | number; type: string | number };
  "dns.rrset.edit_ttl": { name: string | number; type: string | number };
  "dns.rrset.field.data_help": { example: string | number };
  "dns.rrset.field.name_help": { zone: string | number };
  "dns.rrset.saved": { count: number; serial: string | number };
  "dns.settings.saved": { name: string | number };
  "dns.takeover.body": { origin: string | number };
  "dns.takeover.title": { name: string | number; type: string | number };
  "dns.transfer.allow_remove": { name: string | number };
  "dns.transfer.notify_remove": { n: string | number };
  "dns.transfer.primary_remove": { n: string | number };
  "dns.transfer.queued": { name: string | number };
  "dns.update.allow_remove": { name: string | number };
  "dns.update.default_hardened": { profile: string | number };
  "dns.update.default_home": { profile: string | number };
  "dns.update.default_lab": { profile: string | number };
  "dns.update.default_standard": { profile: string | number };
  "dns.update.require_tsig_hardened": { profile: string | number };
  "dns.update.require_tsig_lab": { profile: string | number };
  "dns.upstream.counts": { answered: string | number; failed: string | number };
  "dns.upstream.last_error": { error: string | number; time: string | number };
  "dns.upstream.ms": { ms: string | number };
  "dns.upstream.rule.stub": { zone: string | number };
  "dns.upstream.times": { answers: string | number; ewma: string | number; last: string | number; p50: string | number; p99: string | number };
  "dns.view.check.address": { entry: string | number; n: string | number };
  "dns.view.check.name": { entry: string | number; n: string | number };
  "dns.view.check.no_scope": { scope: string | number; zone: string | number };
  "dns.view.check.prefix": { entry: string | number; n: string | number };
  "dns.view.check.rule_empty": { n: string | number };
  "dns.view.check.rule_too_many": { n: string | number };
  "dns.view.check.scope_twice": { n: string | number };
  "dns.view.check.scope_weight": { n: string | number };
  "dns.view.check.scope_zone": { n: string | number };
  "dns.view.check.time": { entry: string | number; n: string | number };
  "dns.view.check.type": { entry: string | number; n: string | number };
  "dns.view.created": { name: string | number };
  "dns.view.default.body": { profile: string | number };
  "dns.view.delete_title": { name: string | number };
  "dns.view.deleted": { name: string | number };
  "dns.view.drag": { name: string | number };
  "dns.view.edit_title": { name: string | number };
  "dns.view.field.order_at": { n: string | number };
  "dns.view.field.order_last": { n: string | number };
  "dns.view.field.scope": { n: string | number };
  "dns.view.field.weight": { n: string | number };
  "dns.view.field.zone": { n: string | number };
  "dns.view.move_down": { name: string | number };
  "dns.view.move_up": { name: string | number };
  "dns.view.moved": { name: string | number; order: string | number };
  "dns.view.rule.remove": { n: string | number };
  "dns.view.rule.words.client_subnet": { values: string | number };
  "dns.view.rule.words.interface": { values: string | number };
  "dns.view.rule.words.qname": { values: string | number };
  "dns.view.rule.words.qtype": { values: string | number };
  "dns.view.rule.words.time_of_day": { from: string | number; to: string | number };
  "dns.view.rule.words.transport": { values: string | number };
  "dns.view.saved": { name: string | number };
  "dns.view.scope.remove": { n: string | number };
  "dns.view.scope_chip": { scope: string | number; share: string | number; weight: string | number; zone: string | number };
  "dns.view.share": { share: string | number };
  "dns.zone.create.done": { name: string | number };
  "dns.zone.create.reverse_notice": { count: number };
  "dns.zone.delete.body": { count: number; name: string | number; rrsets: string | number };
  "dns.zone.delete.done": { name: string | number };
  "dns.zone.delete.title": { name: string | number };
  "dns.zone.serial": { serial: string | number };
  "errors.auth.password.too_long": { max: string | number };
  "errors.auth.password.too_short": { min: string | number };
  "errors.auth.setup.invalid_host_name": { host_name: string | number };
  "errors.auth.throttled": { retry_after: string | number };
  "errors.auth.token.lifetime_exceeded": { max_days: string | number };
  "errors.client.bad_response": { status: string | number };
  "errors.connect.secret.missing": { purpose: string | number };
  "errors.connect.secret.not_found": { purpose: string | number };
  "errors.connect.secret.not_operator": { purpose: string | number };
  "errors.connect.secret.undeclared": { purpose: string | number };
  "errors.dhcp.class.in_use": { by: string | number };
  "errors.dhcp.class.invalid": { field: string | number };
  "errors.dhcp.ddns.invalid": { field: string | number };
  "errors.dhcp.exclusion.invalid": { field: string | number };
  "errors.dhcp.filter.invalid": { field: string | number };
  "errors.dhcp.lease_times.invalid": { field: string | number };
  "errors.dhcp.option_def.in_use": { by: string | number };
  "errors.dhcp.policy.invalid": { field: string | number };
  "errors.dhcp.scope.invalid": { field: string | number };
  "errors.dhcp.settings.invalid": { field: string | number };
  "errors.dhcp.shared_network.in_use": { count: number };
  "errors.dhcp.shared_network.invalid": { field: string | number };
  "errors.dns.default_zone.invalid": { reason: string };
  "errors.dns.record.conflict": { name: string | number };
  "errors.dns.record.invalid": { name: string | number; type: string | number };
  "errors.dns.record.origin": { name: string | number; type: string | number };
  "errors.dns.view.in_use": { by: string | number };
  "errors.dns.zone.invalid": { field: string | number };
  "errors.ipam.address.duplicate": { ip: string | number };
  "errors.ipam.address.full": { cidr: string | number };
  "errors.ipam.address.in_dhcp_pool": { ip: string | number; range: string | number };
  "errors.ipam.address.network_or_broadcast": { cidr: string | number; ip: string | number };
  "errors.ipam.address.no_prefix": { ip: string | number };
  "errors.ipam.adoption.invalid": { field: string | number };
  "errors.ipam.bulk.too_large": { count: number; limit: number };
  "errors.ipam.bulk.wrong_collection": { index: string | number };
  "errors.ipam.host.locked": { host: string | number };
  "errors.ipam.immutable": { field: string | number };
  "errors.ipam.in_use": { count: number; kind: string | number };
  "errors.ipam.invalid_filter": { name: string | number };
  "errors.ipam.move.controller_unavailable": { connector: string | number; error: string | number };
  "errors.ipam.move.l2_refused": { host: string | number; rule: string | number };
  "errors.ipam.name_taken": { name: string | number };
  "errors.ipam.not_deleted": { kind: string | number };
  "errors.ipam.not_found": { kind: string | number };
  "errors.ipam.object_deleted": { kind: string | number };
  "errors.ipam.plan.unacknowledged": { codes: string | number };
  "errors.ipam.prefix.becomes_supernet": { cidr: string | number };
  "errors.ipam.prefix.full": { cidr: string | number; length: string | number };
  "errors.ipam.prefix.has_children": { cidr: string | number };
  "errors.ipam.prefix.has_ranges": { cidr: string | number };
  "errors.ipam.prefix.host_bits": { cidr: string | number; network: string | number };
  "errors.ipam.prefix.overlap": { cidr: string | number; existing: string | number };
  "errors.ipam.prefix.overlaps_range": { range: string | number };
  "errors.ipam.proposal.batch_too_large": { count: number; limit: number };
  "errors.ipam.proposal.not_open": { state: string | number };
  "errors.ipam.range.covers_reservation": { host: string | number; ip: string | number };
  "errors.ipam.range.not_in_network": { cidr: string | number };
  "errors.ipam.range.outside_prefix": { cidr: string | number };
  "errors.ipam.range.overlap": { existing: string | number };
  "errors.ipam.reference_missing": { kind: string | number };
  "errors.ipam.revision_mismatch": { kind: string | number };
  "errors.ipam.status.transition": { from: string | number; to: string | number };
  "errors.ipam.vlan.duplicate": { vid: string | number };
  "errors.vault.pin_coupling": { accounts: string | number };
  "errors.vault.reveal.rate_limited": { retry_after: string | number };
  "errors.vault.secret.in_use": { connectors: number; hosts: number };
  "errors.vault.secret.invalid": { field: string | number };
  "grid.actionbar.selected": { count: number };
  "grid.columns.move_down": { column: string | number };
  "grid.columns.move_up": { column: string | number };
  "grid.filter.invalid": { field: string | number; value: string | number };
  "grid.row_actions": { row: string | number };
  "grid.rows": { count: number };
  "grid.select_row": { row: string | number };
  "grid.selected": { count: number };
  "guardrails.error.invalid": { field: string | number };
  "guardrails.error.parallel": { max: number; min: number };
  "guardrails.error.reference": { max: number };
  "guardrails.error.vid": { max: number; min: number };
  "guardrails.parallel.limits": { default: number; max: number; min: number };
  "guardrails.path.port": { device: string | number; port: string | number };
  "guardrails.path.vlan": { vid: string | number };
  "guardrails.remove_label": { path: string | number };
  "hosts.bulk.lock_title": { count: number };
  "hosts.bulk.mode_title": { count: number; mode: string | number };
  "hosts.bulk.unlock_title": { count: number };
  "hosts.credentials.bind_title": { host: string | number };
  "hosts.credentials.option": { name: string | number; user: string | number };
  "hosts.credentials.revealed_by": { user: string | number; when: string | number };
  "hosts.credentials.unbind_body": { host: string | number; name: string | number };
  "hosts.credentials.unbind_label": { name: string | number };
  "hosts.credentials.unbind_title": { name: string | number };
  "hosts.credentials.unbound": { name: string | number };
  "hosts.dns.no_records": { zone: string | number };
  "hosts.form.created": { name: string | number };
  "hosts.form.edit_title": { name: string | number };
  "hosts.form.iface_create_title": { host: string | number };
  "hosts.form.iface_edit_title": { host: string | number; name: string | number };
  "hosts.form.iface_saved": { host: string | number; name: string | number };
  "hosts.form.saved": { name: string | number };
  "hosts.in_several": { name: string | number };
  "hosts.lock_failed": { name: string | number };
  "hosts.locked": { name: string | number };
  "hosts.mode.change": { mode: string | number };
  "hosts.mode.change_title": { mode: string | number; name: string | number };
  "hosts.mode.changed": { mode: string | number; name: string | number };
  "hosts.not_found": { name: string | number };
  "hosts.unlocked": { name: string | number };
  "import.changes.first_rows": { shown: number; total: number };
  "import.changes.group": { action: string | number; count: number; kind: string | number };
  "import.columns.credential_option": { target: string | number };
  "import.columns.interface": { column: string | number };
  "import.columns.label": { sheet: string | number };
  "import.columns.suggested": { target: string | number };
  "import.columns.target_of": { column: string | number; sheet: string | number };
  "import.credentials.statement": { changed: number; created: number; hosts: number; unchanged: number };
  "import.loss.counts": { error: number; info: number; warning: number };
  "import.mapping.text": { delimiter: string | number; encoding: string | number };
  "import.preview.apply": { count: number };
  "import.preview.supernet_step": { cidr: string | number; networks: number };
  "import.proposals.holds": { count: number; row: string | number; sheet: string | number };
  "import.result.count": { action: string | number; count: number; kind: string | number };
  "import.result.more": { count: number };
  "import.result.progress": { done: number; total: number };
  "import.result.show_all": { count: number };
  "import.rows.count": { shown: number; total: number };
  "import.rows.more": { count: number };
  "import.shape.count": { count: number; shape: string | number };
  "import.sheet.roles_from": { sheet: string | number };
  "import.sheet.summary": { file: string | number; rows: number; width: number };
  "import.upload.remove": { name: string | number };
  "import.upload.size": { kb: string | number };
  "import.upload.start": { count: number };
  "import.upload.unsupported": { names: string | number };
  "ipam.action.create": { count: number };
  "ipam.action.delete": { count: number };
  "ipam.action.lock": { count: number };
  "ipam.action.remove": { count: number };
  "ipam.action.restore": { count: number };
  "ipam.action.unlock": { count: number };
  "ipam.action.update": { count: number };
  "ipam.address.claim_failed": { ip: string | number };
  "ipam.address.claimed": { ip: string | number };
  "ipam.address.in_several": { ip: string | number };
  "ipam.address.not_found": { ip: string | number };
  "ipam.address.renamed": { ip: string | number; name: string | number };
  "ipam.addresses.claim": { ip: string | number };
  "ipam.addresses.free": { count: number };
  "ipam.addresses.grid": { cidr: string | number };
  "ipam.adoption.cleared": { prefix: string | number };
  "ipam.adoption.error.sightings": { max: string | number };
  "ipam.adoption.error.vendors_count": { max: string | number };
  "ipam.adoption.host_mode_on": { mode: string | number };
  "ipam.adoption.saved": { prefix: string | number };
  "ipam.adoption.sightings_on": { count: string | number };
  "ipam.adoption.vendors_on": { vendors: string | number };
  "ipam.cfdef.delete_title": { key: string | number };
  "ipam.cfdef.deleted": { key: string | number };
  "ipam.cfdef.edit_title": { key: string | number };
  "ipam.delete.done": { kind: string | number; label: string | number };
  "ipam.delete.title": { kind: string | number; label: string | number };
  "ipam.delete.undo_failed": { kind: string | number; label: string | number };
  "ipam.field.inside_prefix": { cidr: string | number };
  "ipam.field.tag_invalid": { max: string | number };
  "ipam.field.tag_remove": { tag: string | number };
  "ipam.form.create_kind": { kind: string | number };
  "ipam.form.create_title": { kind: string | number; label: string | number };
  "ipam.form.created": { kind: string | number; label: string | number };
  "ipam.form.edit_title": { kind: string | number; label: string | number };
  "ipam.form.save_title": { kind: string | number; label: string | number };
  "ipam.form.saved": { label: string | number };
  "ipam.form.use_network": { network: string | number };
  "ipam.history.label": { label: string | number };
  "ipam.history.title": { label: string | number };
  "ipam.kind.address": { count: number };
  "ipam.kind.custom_field": { count: number };
  "ipam.kind.host": { count: number };
  "ipam.kind.interface": { count: number };
  "ipam.kind.prefix": { count: number };
  "ipam.kind.range": { count: number };
  "ipam.kind.site": { count: number };
  "ipam.kind.tenant": { count: number };
  "ipam.kind.vlan": { count: number };
  "ipam.kind.vrf": { count: number };
  "ipam.meter.title": { capacity: string | number; used: string | number };
  "ipam.meter.value": { value: string | number };
  "ipam.move.choose_title": { count: number };
  "ipam.move.dragging": { count: number };
  "ipam.move.step.cleanup": { new_ip: string | number; old_ip: string | number };
  "ipam.move.step.controller_client": { after: string | number; connector: string | number; mac: string | number };
  "ipam.move.step.controller_port": { after: string | number; connector: string | number; device: string | number; port: string | number };
  "ipam.move.step.dhcp": { cidr: string | number; new_ip: string | number };
  "ipam.move.step.intent": { new_ip: string | number; old_ip: string | number };
  "ipam.move.task.device": { cidr: string | number; new_ip: string | number };
  "ipam.move.task.dhcp": { cidr: string | number; new_ip: string | number };
  "ipam.move.task.dns": { name: string | number; new_ip: string | number };
  "ipam.move.task.generic": { cidr: string | number; new_ip: string | number; old_ip: string | number };
  "ipam.move.task.l2": { cidr: string | number };
  "ipam.move.task.l2_client": { connector: string | number; mac: string | number; network: string | number; vid: string | number };
  "ipam.move.task.l2_network": { connector: string | number; vid: string | number };
  "ipam.move.task.l2_port": { connector: string | number; device: string | number; port: string | number; profile: string | number; vid: string | number };
  "ipam.move.task.l2_port_vlan": { connector: string | number; device: string | number; port: string | number; vid: string | number };
  "ipam.move.task.l2_refused": { rule: string | number; vid: string | number };
  "ipam.move.task.l2_shared_port": { count: number; device: string | number; port: string | number; vid: string | number };
  "ipam.move.task.l2_ssid": { device: string | number; ssid: string | number; vid: string | number };
  "ipam.move.task.l2_vlan": { vid: string | number };
  "ipam.move.task.observe": { cidr: string | number; new_ip: string | number; timeout_secs: string | number };
  "ipam.next_free.address": { ip: string | number };
  "ipam.next_free.address_title": { cidr: string | number };
  "ipam.next_free.create": { cidr: string | number };
  "ipam.next_free.length_help": { cidr: string | number; max: string | number; min: string | number };
  "ipam.next_free.length_invalid": { max: string | number; min: string | number };
  "ipam.next_free.prefix": { cidr: string | number };
  "ipam.next_free.prefix_title": { cidr: string | number };
  "ipam.next_free.whole_network": { cidr: string | number };
  "ipam.overview.grid": { vrf: string | number };
  "ipam.overview.sub": { alarms: number; count: number; tenant: string | number };
  "ipam.plan.summary_line": { action: string | number; kind: string | number };
  "ipam.prefix.alarm_value": { crit: string | number; warn: string | number };
  "ipam.prefix.children_grid": { cidr: string | number };
  "ipam.prefix.in_several": { cidr: string | number };
  "ipam.prefix.not_found": { cidr: string | number };
  "ipam.prefix.ranges_grid": { cidr: string | number };
  "ipam.prefix.usage": { capacity: string | number; used: string | number };
  "ipam.reconcile.count": { count: number; more: string };
  "ipam.reconcile.filter.host_chip": { host: string | number };
  "ipam.reconcile.filter.host_unknown": { name: string | number };
  "ipam.reconcile.os_guess": { confidence: string | number; guess: string | number };
  "ipam.reconcile.os_source": { source: string | number; truth: string | number };
  "ipam.reconcile.winner": { truth: string | number };
  "ipam.restore.done": { kind: string | number; label: string | number };
  "ipam.restore.title": { kind: string | number; label: string | number };
  "ipam.scope.option": { tenant: string | number; vrf: string | number };
  "ipam.site.edit_title": { name: string | number };
  "ipam.tenancy.created": { name: string | number };
  "ipam.tenancy.saved": { name: string | number };
  "ipam.tenant.edit_title": { name: string | number };
  "ipam.tree.drop_hint": { cidr: string | number; count: number };
  "ipam.vlan.edit_title": { vid: string | number };
  "ipam.vlan.prefixes.title": { name: string | number; vid: string | number };
  "ipam.vlan.provision.network_name_long": { max: number };
  "ipam.vlan.provision.relay_invalid": { address: string | number };
  "ipam.vlan.provision.relay_too_many": { max: number };
  "ipam.vlan.provision.started": { vid: string | number };
  "ipam.vlan.provision.step.activate": { vid: string | number };
  "ipam.vlan.provision.step.intent_both": { cidr: string | number; name: string | number; vid: string | number };
  "ipam.vlan.provision.step.intent_prefix": { cidr: string | number; name: string | number; vid: string | number };
  "ipam.vlan.provision.step.intent_vlan": { name: string | number; vid: string | number };
  "ipam.vlan.provision.step.manual": { name: string | number; vid: string | number };
  "ipam.vlan.provision.step.network": { connector: string | number; name: string | number; vid: string | number };
  "ipam.vlan.provision.step.network_check": { connector: string | number; name: string | number; vid: string | number };
  "ipam.vlan.provision.title_existing": { vid: string | number };
  "ipam.vlan.provision.warning.controller_read_only": { connector: string | number };
  "ipam.vlan.provision.warning.network_changes": { vid: string | number };
  "ipam.vlan.step.activate": { vid: string | number };
  "ipam.vlan.step.controller": { name: string | number; vid: string | number };
  "ipam.vlan.step.intent": { name: string | number; vid: string | number };
  "ipam.vlan.task.network": { name: string | number; vid: string | number };
  "ipam.vrf.edit_title": { name: string | number };
  "jobs.cancel.note": { when: string | number; who: string | number };
  "jobs.checklist.group": { count: number; name: string | number };
  "jobs.checklist.mark_done": { task: string | number };
  "jobs.checklist.open": { count: number };
  "jobs.complete.done": { n: number };
  "jobs.deadline.in": { time: string | number };
  "jobs.deadline.line": { when: string | number };
  "jobs.duration.d": { value: number };
  "jobs.duration.h": { value: number };
  "jobs.duration.min": { value: number };
  "jobs.duration.s": { value: number };
  "jobs.error.note_too_long": { max: number };
  "jobs.error.query_invalid": { param: string | number; value: string | number };
  "jobs.fact.group_limit": { limit: number };
  "jobs.fact.when_by": { when: string | number; who: string | number };
  "jobs.filter.group": { group: string | number };
  "jobs.filter.kind": { kind: string | number };
  "jobs.filter.remove": { filter: string | number };
  "jobs.filter.target": { target: string | number };
  "jobs.group.heading": { group: string | number };
  "jobs.group.limit": { limit: number };
  "jobs.group.not_moved.count": { count: number };
  "jobs.group.summary": { count: number };
  "jobs.l2.receipt": { count: number; when: string | number };
  "jobs.l2.undo_hint": { before: string | number; path: string | number };
  "jobs.log.change": { from: string | number; to: string | number };
  "jobs.note.counter": { max: number; used: number };
  "jobs.note.over": { over: number };
  "jobs.observe.address_seen": { ip: string | number };
  "jobs.observe.address_seen_mac": { ip: string | number; mac: string | number };
  "jobs.observe.lease": { mac: string | number };
  "jobs.observe.waiting": { what: string | number };
  "jobs.problem.detail": { detail: string | number };
  "jobs.progress": { done: number; total: number };
  "jobs.step.cleanup": { host: string | number };
  "jobs.step.device_manual": { host: string | number; ip: string | number };
  "jobs.step.dhcp_manual": { host: string | number; ip: string | number };
  "jobs.step.dns_manual": { name: string | number; new_ip: string | number };
  "jobs.step.ipam_intent": { host: string | number };
  "jobs.step.l2_move": { host: string | number; vlan: string | number };
  "jobs.step.observe": { host: string | number; ip: string | number };
  "jobs.step_position": { n: number; total: number };
  "jobs.stepmeta.attempts": { count: number };
  "jobs.stepmeta.finished": { when: string | number };
  "jobs.stepmeta.started": { when: string | number };
  "jobs.targets": { count: number };
  "jobs.task.dhcp_release": { host: string | number; ip: string | number };
  "jobs.task.dhcp_reserve": { host: string | number; ip: string | number; mac: string | number; prefix: string | number };
  "jobs.task.dns_revert": { name: string | number; old_ip: string | number };
  "jobs.task.dns_update": { name: string | number; new_ip: string | number; old_ip: string | number };
  "jobs.undo.step": { kind: string | number; step: string | number };
  "jobs.undo.step_named": { name: string | number; step: string | number };
  "languages.action.template_of": { name: string | number };
  "languages.confirm.activate.body": { name: string | number };
  "languages.confirm.activate.ok": { name: string | number };
  "languages.confirm.activate.title": { name: string | number };
  "languages.confirm.discard.title": { name: string | number };
  "languages.confirm.remove.body": { name: string | number };
  "languages.confirm.remove.ok": { name: string | number };
  "languages.confirm.remove.title": { name: string | number };
  "languages.confirm.revert.body": { name: string | number };
  "languages.confirm.revert.ok": { name: string | number };
  "languages.confirm.revert.title": { name: string | number };
  "languages.preview.bar": { name: string | number };
  "languages.report.at_line": { line: number };
  "languages.report.author": { author: string | number };
  "languages.report.complete": { total: number; translated: number };
  "languages.report.extra": { count: number };
  "languages.report.heading": { name: string | number };
  "languages.report.missing": { count: number };
  "languages.report.more": { count: number };
  "languages.report.problems": { count: number; errors: number };
  "languages.report.stale": { count: number };
  "languages.toast.activated": { name: string | number };
  "languages.toast.discarded": { name: string | number };
  "languages.toast.preview": { name: string | number };
  "languages.toast.removed": { name: string | number };
  "languages.toast.reverted": { name: string | number };
  "languages.upload.done": { name: string | number; percent: string | number };
  "languages.version.by": { when: string | number; who: string | number };
  "languages.version.label": { version: string | number };
  "languages.version.percent": { percent: string | number };
  "metrics.bars": { name: string | number; seconds: string | number; values: string | number };
  "metrics.dhcp.active_hint": { abandoned: number };
  "metrics.dhcp.ddns_hint": { dropped: string | number; queue: number; skipped: string | number };
  "metrics.dhcp.pools_hint": { scopes: number };
  "metrics.dns.blocked_hint": { lists: number };
  "metrics.dns.cache_hint": { entries: string | number; stale: string | number };
  "metrics.dns.encrypted_hint": { doh: number; dot: number };
  "metrics.dns.log_dropped": { rate: string | number };
  "metrics.dns.queries_hint": { p50: string | number; p99: string | number };
  "metrics.dns.rate": { rate: string | number };
  "metrics.dns.upstreams_hint": { p99: string | number };
  "metrics.dns.validation_hint": { rate: string | number };
  "metrics.host.disk_hint": { total: string | number };
  "metrics.host.memory_hint": { total: string | number; used: string | number };
  "metrics.raft.lag": { entries: number };
  "metrics.raft.node": { node: string | number };
  "metrics.sparkline": { name: string | number; values: string | number };
  "metrics.tile.ingest_hint": { batches: string | number };
  "metrics.tile.jobs_hint": { waiting: number };
  "metrics.tile.nodes_hint": { drops: number; nodes: number };
  "metrics.tile.nodes_hint_unknown": { nodes: number };
  "metrics.tile.raft_hint": { term: number };
  "metrics.tile.requests_hint": { p50: string | number; p99: string | number };
  "metrics.tile.store_hint": { data: string | number };
  "move.checklist_sum": { count: number };
  "move.group.cleanup": { count: number };
  "move.group.device_manual": { count: number };
  "move.group.dhcp_manual": { count: number };
  "move.group.dns_manual": { count: number };
  "move.group.ipam_intent": { count: number };
  "move.group.l2_move": { count: number };
  "move.group.observe": { count: number };
  "move.heading": { count: number };
  "move.heading_vlan": { vid: string | number };
  "move.include": { name: string | number };
  "move.included": { count: number; total: number };
  "move.l2.action.client_vlan": { device: string | number };
  "move.l2.action.client_vlan_ssid": { device: string | number; ssid: string | number };
  "move.l2.action.port_profile": { device: string | number; port: string | number; profile: string | number };
  "move.l2.action.shared": { ip: string | number };
  "move.l2.action.unchanged": { vid: string | number };
  "move.l2.controller": { name: string | number };
  "move.l2.controller_read_only": { name: string | number };
  "move.l2.diff": { after: string | number; before: string | number };
  "move.l2.note.carry_unknown": { vid: string | number };
  "move.l2.reason.join_ssid": { ssid: string | number; vid: string | number };
  "move.l2.reason.no_network": { vid: string | number };
  "move.l2.reason.no_profile": { vid: string | number };
  "move.l2.reason.no_ssid": { vid: string | number };
  "move.l2.reason.read_only": { connector: string | number };
  "move.l2.reason.refused": { rule: string | number };
  "move.l2.reason.shared_port": { count: number };
  "move.l2.ssids": { ssids: string | number; vid: string | number };
  "move.l2.through": { connector: string | number };
  "move.reason.host_part_outside": { ip: string | number };
  "move.reason.host_part_reserved": { ip: string | number };
  "move.reason.host_part_taken": { ip: string | number };
  "move.show_steps": { name: string | number };
  "move.start": { count: number };
  "move.started": { count: number };
  "move.step.cleanup": { ip: string | number };
  "move.step.device_manual": { host: string | number; ip: string | number; length: string | number };
  "move.step.dhcp_manual": { cidr: string | number; ip: string | number; mac: string | number };
  "move.step.dhcp_manual_no_mac": { cidr: string | number; host: string | number; ip: string | number };
  "move.step.dns_manual": { ip: string | number; name: string | number };
  "move.step.ipam_intent": { new_ip: string | number; old_ip: string | number };
  "move.step.l2_controller": { connector: string | number; host: string | number; vid: string | number };
  "move.step.l2_move": { host: string | number; vid: string | number };
  "move.step.l2_move_novlan": { cidr: string | number; host: string | number };
  "move.step.observe": { host: string | number; ip: string | number };
  "move.tasks": { count: number };
  "move.timeout.default": { timeout: string | number };
  "move.timeout.lease": { lease: string | number; timeout: string | number };
  "move.timeout.request": { timeout: string | number };
  "move.timeout_auto": { timeout: string | number };
  "nodes.cert.days_left": { days: number };
  "nodes.col.major": { major: string | number };
  "nodes.enrol.next": { roles: string | number };
  "nodes.enrol.once": { expires: string | number };
  "nodes.mismatch": { count: number; majors: string | number; names: string | number };
  "nodes.panel.buffer_value": { batches: number; size: string | number };
  "nodes.panel.id": { id: string | number };
  "nodes.panel.mismatch": { at: string | number; ours: string | number; theirs: string | number; version: string | number };
  "nodes.panel.valid_range": { from: string | number; to: string | number };
  "nodes.port_open": { addresses: string | number; majors: string | number };
  "nodes.revoke.confirm_title": { name: string | number };
  "nodes.revoke.done": { name: string | number };
  "nodes.revoke.failed": { name: string | number };
  "nodes.roles.confirm_off": { roles: string | number };
  "nodes.roles.confirm_on": { roles: string | number };
  "nodes.roles.finding.dns_resolver": { file: string | number };
  "nodes.roles.finding.privileges": { capability: string | number; command: string | number; dropins: string | number; roles: string | number };
  "nodes.roles.finding.unprepared": { command: string | number; missing: string | number; roles: string | number };
  "nodes.roles.pinned": { roles: string | number };
  "nodes.roles.restart.back": { roles: string | number };
  "nodes.roles.running": { roles: string | number };
  "nodes.roles.self_hint": { id: string | number };
  "nodes.roles.unprepared": { missing: string | number; role: string | number };
  "nodes.scan.applied.error": { error: string | number };
  "nodes.scan.back": { name: string | number };
  "nodes.scan.devices.error": { column: string | number; error: string | number; n: string | number };
  "nodes.scan.devices.remove": { n: string | number };
  "nodes.scan.devices.row_label": { column: string | number; n: string | number };
  "nodes.scan.error.entries": { count: number; positions: string | number };
  "nodes.scan.error.lines": { count: number; positions: string | number };
  "nodes.scan.lacking": { count: number; devices: string | number };
  "nodes.scan.node_fallback": { id: string | number };
  "nodes.scan.not_probe.body": { name: string | number };
  "nodes.scan.resume.done": { name: string | number };
  "nodes.scan.resume.failed": { name: string | number };
  "nodes.scan.stop.done": { name: string | number };
  "nodes.scan.stop.failed": { name: string | number };
  "nodes.scan.stop.reason_help": { max: string | number };
  "nodes.scan.stop.reason_too_long": { max: string | number };
  "nodes.scan.stop.title": { name: string | number };
  "nodes.summary": { connected: string | number; nodes: number };
  "nodes.token.delete_named": { name: string | number };
  "nodes.version_count": { count: string | number; version: string | number };
  "nodes.versions": { versions: string | number };
  "principal.node": { id: string | number };
  "principal.system": { component: string | number };
  "principal.token": { id: string | number };
  "principal.user": { id: string | number };
  "principal.you": { name: string | number };
  "reconciler.error.invalid": { field: string | number };
  "reconciler.error.range": { max: string | number; min: string | number };
  "reconciler.error.refresh": { retention: string | number };
  "reconciler.limits": { default: string | number; max: string | number; min: string | number };
  "scans.count": { count: number };
  "scans.diff.summary": { changed: string | number; gone: string | number; new: string | number };
  "scans.fact.address": { ip: string | number; mac: string | number };
  "scans.fact.attachment": { device: string | number; mac: string | number };
  "scans.fact.link": { a: string | number; b: string | number; kind: string | number };
  "scans.fact.os": { confidence: string | number; guess: string | number };
  "scans.fact.ports": { ports: string | number };
  "scans.fact.tls": { ports: string | number };
  "scans.now.no_probe.one": { name: string | number };
  "scans.now.started": { probes: number };
  "scans.now.title": { target: string | number };
  "scans.part.ingested": { batches: string | number; ingested: string | number };
  "scans.probe.config_named": { name: string | number };
  "scans.probe.node_unnamed": { id: string | number };
  "scans.probe.scope": { count: number; methods: string | number };
  "scans.progress.label": { target: string | number };
  "scans.progress.percent": { percent: string | number };
  "scans.switch.reason": { reason: string | number };
  "scans.switch.unconfirmed": { state: string | number };
  "scans.toast.resumed": { count: number };
  "scans.toast.stopped": { count: number };
  "scans.view.title": { target: string | number };
  "secrets.action.delete_named": { name: string | number };
  "secrets.action.edit_named": { name: string | number };
  "secrets.action.replace_named": { name: string | number };
  "secrets.action.reveal_named": { name: string | number };
  "secrets.count": { count: number };
  "secrets.count_filtered": { shown: string | number; total: number };
  "secrets.created": { name: string | number };
  "secrets.delete.body": { name: string | number };
  "secrets.delete.in_use_title": { name: string | number };
  "secrets.delete.title": { name: string | number };
  "secrets.deleted": { name: string | number };
  "secrets.detail.label": { name: string | number };
  "secrets.form.edit_title": { name: string | number };
  "secrets.refs.connector": { plugin: string | number; purpose: string | number };
  "secrets.refs.role": { role: string | number };
  "secrets.replace.title": { name: string | number };
  "secrets.replaced": { name: string | number };
  "secrets.reveal.audit": { time: string | number; user: string | number };
  "secrets.reveal.copied": { seconds: number };
  "secrets.reveal.stepup.password_label": { user: string | number };
  "secrets.reveal.title": { name: string | number };
  "secrets.revealed_by": { user: string | number; when: string | number };
  "secrets.saved": { name: string | number };
  "settings.security.consequence.differs": { profile: string | number };
  "settings.security.consequence.matches": { profile: string | number };
  "settings.security.edit_row": { name: string | number };
  "settings.security.edit_title": { name: string | number };
  "settings.security.more": { shown: string | number; total: string | number };
  "settings.security.profile.changes": { count: number };
  "settings.security.profile.deviations": { count: number };
  "settings.security.profile.reset_done": { profile: string | number };
  "settings.security.profile.reset_to": { profile: string | number };
  "settings.security.profile.resets": { profile: string | number };
  "settings.security.profile.resets_same": { profile: string | number };
  "settings.security.profile.switch_done": { profile: string | number };
  "settings.security.profile.switch_to": { profile: string | number };
  "settings.security.profile.weak_body": { count: number; names: string | number };
  "settings.security.profile.weak_warning": { names: string | number };
  "settings.security.reset_done": { name: string | number };
  "settings.security.reset_row": { name: string | number };
  "settings.security.saved": { name: string | number };
  "settings.security.unit.label": { field: string | number };
  "settings.users.action.delete_help": { name: string | number };
  "settings.users.action.disable_help": { name: string | number };
  "settings.users.action.enable_help": { name: string | number };
  "settings.users.action.password_help": { name: string | number };
  "settings.users.action.roles_help": { roles: string | number };
  "settings.users.action.sign_out_help": { name: string | number };
  "settings.users.action.unlock_help": { name: string | number };
  "settings.users.added": { name: string | number };
  "settings.users.break_glass.made": { name: string | number };
  "settings.users.break_glass.make_confirm": { name: string | number };
  "settings.users.break_glass.make_title": { name: string | number };
  "settings.users.break_glass.no_key": { name: string | number };
  "settings.users.break_glass.remove_body": { name: string | number };
  "settings.users.break_glass.remove_confirm": { name: string | number };
  "settings.users.break_glass.remove_title": { name: string | number };
  "settings.users.break_glass.removed": { name: string | number };
  "settings.users.count": { count: number };
  "settings.users.delete.body": { name: string | number };
  "settings.users.delete.confirm": { name: string | number };
  "settings.users.delete.title": { name: string | number };
  "settings.users.deleted": { name: string | number };
  "settings.users.disable.body": { name: string | number };
  "settings.users.disable.confirm": { name: string | number };
  "settings.users.disable.title": { name: string | number };
  "settings.users.disabled": { name: string | number };
  "settings.users.enabled": { name: string | number };
  "settings.users.methods.passkeys": { count: number };
  "settings.users.methods.recovery_codes": { count: number };
  "settings.users.methods.security_keys": { count: number };
  "settings.users.password.lead": { name: string | number };
  "settings.users.saved_details": { name: string | number };
  "settings.users.saved_password": { name: string | number };
  "settings.users.saved_roles": { name: string | number };
  "settings.users.sign_out.body": { name: string | number };
  "settings.users.sign_out.confirm": { name: string | number };
  "settings.users.sign_out.title": { name: string | number };
  "settings.users.signed_out": { name: string | number };
  "settings.users.status.locked": { time: string | number };
  "settings.users.unlocked": { name: string | number };
  "setup.admin.check.breach_off": { profile: string | number };
  "setup.admin.password.help.passphrase": { profile: string | number };
  "setup.admin.password.help.password": { profile: string | number };
  "setup.admin.password.help.pin": { profile: string | number };
  "setup.dhcp.privacy": { days: number };
  "setup.dhcp.summary": { dns: string | number; first: string | number; last: string | number; network: string | number; router: string | number };
  "setup.dhcp.use_network": { iface: string | number; network: string | number };
  "setup.disk.free_aside": { size: string | number };
  "setup.disk.fsync": { time: string | number };
  "setup.disk.media_free": { media: string | number; size: string | number };
  "setup.disk.move": { command: string | number };
  "setup.dns.cache_description": { entries: number };
  "setup.dns.known": { name: string | number; tls: string | number };
  "setup.done.change_item": { item: string | number };
  "setup.done.dhcp_detail": { first: string | number; last: string | number; router: string | number };
  "setup.done.probe_on": { networks: string | number };
  "setup.done.proxies": { count: number };
  "setup.host.placeholder": { name: string | number };
  "setup.profile.lede": { total: string | number };
  "setup.profile.table.aside": { shown: string | number; total: string | number };
  "setup.profile.table.title": { profile: string | number };
  "setup.result.codes.lede": { user: string | number };
  "setup.result.dhcp.failed.options": { reason: string | number };
  "setup.result.dhcp.failed.pool": { reason: string | number };
  "setup.result.dhcp.failed.prefix": { reason: string | number };
  "setup.result.dhcp.failed.scope": { reason: string | number };
  "setup.result.dhcp.saved": { network: string | number };
  "setup.result.dns.failed": { reason: string | number };
  "setup.roles.hint": { amount: string | number };
  "setup.roles.hint_probe": { amount: string | number };
  "setup.roles.memory": { amount: string | number; total: string | number };
  "setup.roles.memory_unknown_total": { amount: string | number };
  "setup.stepno": { step: string | number; total: string | number };
  "setup.steps.dns_meta": { count: number };
  "setup.steps.item": { name: string | number; number: string | number };
  "setup.steps.roles_meta": { count: string | number };
  "setup.tls.proxies.invalid": { count: number; entries: string | number };
  "setup.welcome.cores": { count: number };
  "setup.welcome.fact.address": { count: number };
  "setup.welcome.lede": { count: string | number };
  "setup.welcome.restore": { link: string | number };
  "shell.account.open": { name: string | number };
  "shell.account.who": { method: string | number; role: string | number };
  "shell.keys.goto": { area: string | number };
  "shell.nav.jobs_badge": { count: number };
  "shell.nav.tooltip": { area: string | number; key: string | number };
  "shell.notfound.body": { path: string | number };
  "shell.palette.no_match": { query: string | number };
  "shell.palette.search_all": { query: string | number };
  "shell.placeholder.title": { area: string | number };
  "shell.report.failed": { detail: string | number };
  "shell.search.results": { count: number; query: string | number };
  "shell.status.alarms": { count: number };
  "shell.status.critical": { count: number };
  "shell.status.last_event": { ago: string | number };
  "shell.status.proposals": { count: number };
  "shell.status.running": { count: number };
  "shell.status.selection": { selected: number; total: number };
  "shell.status.update": { version: string | number };
  "shell.status.version": { version: string | number };
  "shell.status.waiting": { count: number };
  "shell.theme.change": { current: string | number };
  "shell.theme.system": { mode: string | number };
  "shell.top.node_title": { lag: number; revision: string | number };
  "shell.top.profile": { profile: string | number };
  "shell.top.profile_title": { profile: string | number };
  "toggles.password_policy.custom": { min: string | number };
  "toggles.secret_reveal.value": { bound: string; step_up: string | number };
  "toggles.session.value": { absolute: string | number; idle: string | number };
  "toggles.token_max_days.days": { days: number };
  "toggles.updates.value": { check: string | number; install: string | number };
  "topology.controller.error_generic": { code: string | number };
  "topology.controller.ok": { count: number };
  "topology.filter.unknown_site": { id: string | number };
  "topology.filter.unknown_vlan": { id: string | number };
  "topology.group.aria": { count: number };
  "topology.group.label": { count: number };
  "topology.legend.too_many": { count: number };
  "topology.neighbour.local": { port: string | number };
  "topology.neighbour.remote": { port: string | number };
  "topology.neighbour.ssid": { ssid: string | number };
  "topology.networks.summary": { count: number };
  "topology.node.aria": { kind: string | number; label: string | number };
  "topology.path.start": { label: string | number };
  "topology.port.connected": { port: string | number };
  "topology.port.count": { count: number };
  "topology.port.hide_aria": { port: string | number };
  "topology.port.open_aria": { port: string | number };
  "topology.summary": { edges: number; nodes: number; total_edges: number; total_nodes: number };
  "updates.attempt.failed": { to: string | number };
  "updates.attempt.rolled_back": { from: string | number; to: string | number };
  "updates.blocked.other": { reason: string | number };
  "updates.blocked.unsupported_platform": { platform: string | number };
  "updates.check.on": { hours: number };
  "updates.code_unknown": { code: string | number };
  "updates.install.button": { version: string | number };
  "updates.install.confirm_body": { seconds: number; version: string | number };
  "updates.install.confirm_ok": { version: string | number };
  "updates.install.confirm_title": { version: string | number };
  "updates.install.confirm_upload": { seconds: number; version: string | number };
  "updates.install.lead": { version: string | number };
  "updates.install.up_to_date": { version: string | number };
  "updates.manifest.fetched": { count: number; when: string | number };
  "updates.manifest.uploaded": { count: number; when: string | number };
  "updates.module.body": { module: string | number };
  "updates.progress.failed": { version: string | number };
  "updates.progress.heading": { version: string | number };
  "updates.release.format": { format: string | number };
  "updates.release.title": { version: string | number };
  "updates.releases.count": { count: number };
  "updates.restart.body": { version: string | number };
  "updates.restart.confirmed": { version: string | number };
  "updates.restart.reason": { reason: string | number };
  "updates.restart.rolled_back": { from: string | number; to: string | number };
  "updates.restart.timeout_body": { seconds: number; version: string | number };
  "updates.restart.title": { version: string | number };
  "updates.sub": { version: string | number };
  "updates.upload.button": { version: string | number };
  "updates.upload.chosen": { name: string | number; size: string | number };
  "updates.upload.expected": { name: string | number; size: string | number };
  "updates.upload.file_label": { platform: string | number };
  "updates.upload.manifest_done": { count: number };
  "updates.whatsnew.empty": { version: string | number };
  "updates.whatsnew.lead": { last: string | number };
  "updates.whatsnew.title": { version: string | number };
  "vault.key.heading": { node: string | number };
  "vault.rotation.unreachable_text": { nodes: string | number };
  "vault.warning.missing": { generations: string | number };
  "vault.warning.rotation_failed": { error: string | number };
}
export const messageKeys: readonly MessageKey[] = [
  "access.col.actions",
  "access.grant.text",
  "access.grants.add",
  "access.grants.add_confirm",
  "access.grants.add_title",
  "access.grants.col.delegable",
  "access.grants.col.granted",
  "access.grants.col.holder",
  "access.grants.col.role",
  "access.grants.col.scope",
  "access.grants.created",
  "access.grants.delegated",
  "access.grants.error.scope",
  "access.grants.error.subject",
  "access.grants.field.delegable",
  "access.grants.field.delegable_help",
  "access.grants.field.role",
  "access.grants.field.subject",
  "access.grants.heading",
  "access.grants.lede",
  "access.grants.lede_user",
  "access.grants.none",
  "access.grants.revoke_body",
  "access.grants.revoke_cascade",
  "access.grants.revoke_named",
  "access.grants.revoke_title",
  "access.grants.revoked",
  "access.lede",
  "access.mfa.optional",
  "access.mfa.optional_help",
  "access.mfa.passkey",
  "access.mfa.passkey_help",
  "access.mfa.profile_help",
  "access.mfa.totp_or_stronger",
  "access.mfa.totp_or_stronger_help",
  "access.picker.choose",
  "access.picker.kind",
  "access.picker.kind_everything",
  "access.picker.kind_prefix",
  "access.picker.kind_site",
  "access.picker.kind_vrf",
  "access.picker.object_prefix",
  "access.picker.object_site",
  "access.picker.object_vrf",
  "access.picker.prefix_option",
  "access.picker.subtree_prefix",
  "access.picker.subtree_site",
  "access.role.admin",
  "access.role.admin_description",
  "access.role.auditor",
  "access.role.auditor_description",
  "access.role.operator",
  "access.role.operator_description",
  "access.role.operator_grant",
  "access.role.viewer",
  "access.role.viewer_description",
  "access.role.viewer_grant",
  "access.roles.col.held",
  "access.roles.col.may",
  "access.roles.col.mfa",
  "access.roles.col.role",
  "access.roles.dialog_title",
  "access.roles.edit",
  "access.roles.edit_named",
  "access.roles.follow_profile",
  "access.roles.follows_profile",
  "access.roles.global_only",
  "access.roles.global_or_grant",
  "access.roles.heading",
  "access.roles.lede",
  "access.roles.saved",
  "access.roles.stored",
  "access.roles.weaker",
  "access.sa.add",
  "access.sa.add_lede",
  "access.sa.add_title",
  "access.sa.created",
  "access.sa.error.name",
  "access.sa.field.display_name",
  "access.sa.field.name",
  "access.sa.field.name_help",
  "access.sa.field.roles",
  "access.sa.field.roles_help",
  "access.sa.grants_only",
  "access.sa.heading",
  "access.sa.lede",
  "access.sa.no_tokens",
  "access.sa.none",
  "access.sa.summary",
  "access.sa.token_revoked",
  "access.sa.tokens",
  "access.sa.tokens_of",
  "access.scope.everything",
  "access.scope.object",
  "access.scope.prefix",
  "access.scope.prefix_subtree",
  "access.scope.site",
  "access.scope.site_subtree",
  "access.scope.tenant",
  "access.scope.vrf",
  "access.subject.option",
  "access.subject.service",
  "access.title",
  "access.token.add_grant",
  "access.token.col.expires",
  "access.token.col.last_used",
  "access.token.col.name",
  "access.token.col.reach",
  "access.token.create",
  "access.token.create_title",
  "access.token.created_body",
  "access.token.created_title",
  "access.token.days",
  "access.token.error.empty",
  "access.token.error.name",
  "access.token.error.scope",
  "access.token.expired",
  "access.token.grants",
  "access.token.grants_help",
  "access.token.kind",
  "access.token.kind_personal",
  "access.token.kind_personal_help",
  "access.token.kind_scoped",
  "access.token.kind_scoped_help",
  "access.token.lifetime",
  "access.token.max_days",
  "access.token.max_none",
  "access.token.name",
  "access.token.name_help",
  "access.token.no_expiry",
  "access.token.personal",
  "access.token.remove_grant",
  "access.token.revoke_body",
  "access.token.revoke_named",
  "access.token.revoke_title",
  "access.token.scopes",
  "access.token.stored",
  "access.token_scope.audit_read",
  "access.token_scope.audit_read_help",
  "access.token_scope.metrics",
  "access.token_scope.metrics_help",
  "access.user.kind",
  "access.user.service",
  "account.codes.lede",
  "account.codes.title",
  "account.copy_failed",
  "account.methods.flag_mfa",
  "account.methods.flag_password",
  "account.methods.reauthenticate",
  "account.methods.requires",
  "account.methods.signed_in_with",
  "account.methods.summary_label",
  "account.nav.label",
  "account.nav.methods",
  "account.nav.sessions",
  "account.nav.tokens",
  "account.passkey.add",
  "account.passkey.add_key",
  "account.passkey.added",
  "account.passkey.added_key",
  "account.passkey.created",
  "account.passkey.kind.device",
  "account.passkey.kind.hardware",
  "account.passkey.kind.synced",
  "account.passkey.label",
  "account.passkey.label_help",
  "account.passkey.last_used",
  "account.passkey.lede",
  "account.passkey.never_used",
  "account.passkey.none",
  "account.passkey.remove_body",
  "account.passkey.remove_named",
  "account.passkey.remove_refused",
  "account.passkey.remove_title",
  "account.passkey.removed",
  "account.passkey.title",
  "account.passkey.waiting_key",
  "account.passkey.waiting_passkey",
  "account.password.changed",
  "account.password.changed_others",
  "account.password.check.breach_clean",
  "account.password.check.breach_off",
  "account.password.check.breach_unavailable",
  "account.password.check.context",
  "account.password.check.trivial",
  "account.password.checks",
  "account.password.confirm",
  "account.password.current",
  "account.password.current_help",
  "account.password.lede",
  "account.password.mismatch",
  "account.password.new",
  "account.password.rule.length",
  "account.password.rule.passphrase",
  "account.password.rule.pattern",
  "account.password.rule.pin",
  "account.password.rule.profile",
  "account.password.show",
  "account.password.state.bad",
  "account.password.state.idle",
  "account.password.state.off",
  "account.password.state.ok",
  "account.password.state.pending",
  "account.password.submit",
  "account.password.title",
  "account.recovery.confirm_body",
  "account.recovery.confirm_title",
  "account.recovery.generate",
  "account.recovery.lede",
  "account.recovery.left",
  "account.recovery.name",
  "account.recovery.needs_factor",
  "account.recovery.title",
  "account.sessions.client",
  "account.sessions.client_unknown",
  "account.sessions.col.actions",
  "account.sessions.col.address",
  "account.sessions.col.client",
  "account.sessions.col.expires",
  "account.sessions.col.last_activity",
  "account.sessions.col.signed_in",
  "account.sessions.col.strength",
  "account.sessions.confirm_body",
  "account.sessions.confirm_button",
  "account.sessions.confirm_title",
  "account.sessions.lede",
  "account.sessions.none_other",
  "account.sessions.revoke_named",
  "account.sessions.revoked",
  "account.sessions.revoked_many",
  "account.sessions.sign_out",
  "account.sessions.sign_out_others",
  "account.sessions.strength.hardware_key",
  "account.sessions.strength.passkey",
  "account.sessions.strength.password",
  "account.sessions.strength.password_totp",
  "account.sessions.strength.pin",
  "account.sessions.this",
  "account.sessions.title",
  "account.title",
  "account.tokens.col.created",
  "account.tokens.col.expires",
  "account.tokens.col.last_used",
  "account.tokens.col.name",
  "account.tokens.col.prefix",
  "account.tokens.create",
  "account.tokens.create_title",
  "account.tokens.created_body",
  "account.tokens.created_title",
  "account.tokens.days",
  "account.tokens.expired",
  "account.tokens.lede",
  "account.tokens.lifetime",
  "account.tokens.max_days",
  "account.tokens.max_none",
  "account.tokens.name",
  "account.tokens.name_help",
  "account.tokens.no_expiry",
  "account.tokens.none",
  "account.tokens.revoke_body",
  "account.tokens.revoke_named",
  "account.tokens.revoke_title",
  "account.tokens.revoked",
  "account.tokens.stored",
  "account.tokens.title",
  "account.totp.code",
  "account.totp.enabled",
  "account.totp.expired",
  "account.totp.key",
  "account.totp.lede",
  "account.totp.name",
  "account.totp.open_link",
  "account.totp.params",
  "account.totp.qr_label",
  "account.totp.remove_body",
  "account.totp.remove_refused",
  "account.totp.remove_title",
  "account.totp.removed",
  "account.totp.scan_or_key",
  "account.totp.setup",
  "account.totp.setup_title",
  "account.totp.status_off",
  "account.totp.status_on",
  "account.totp.title",
  "account.totp.verify",
  "audit.chain.advice",
  "audit.chain.broken",
  "audit.chain.checked",
  "audit.chain.checking",
  "audit.chain.detail",
  "audit.chain.empty",
  "audit.chain.failed",
  "audit.chain.head",
  "audit.chain.intact",
  "audit.chain.label",
  "audit.chain.open_record",
  "audit.chain.reason.other",
  "audit.chain.reason.sys.audit.bad_hash",
  "audit.chain.reason.sys.audit.broken_link",
  "audit.chain.reason.sys.audit.gap",
  "audit.chain.verified_before",
  "audit.chain.verify",
  "audit.chain.verifying",
  "audit.changes.field",
  "audit.changes.new",
  "audit.changes.no_value",
  "audit.changes.none",
  "audit.changes.not_recorded",
  "audit.changes.object",
  "audit.changes.old",
  "audit.changes.table",
  "audit.changes.title",
  "audit.col.action",
  "audit.col.objects",
  "audit.col.outcome",
  "audit.col.principal",
  "audit.col.seq",
  "audit.col.source",
  "audit.col.time",
  "audit.context.key",
  "audit.context.none",
  "audit.context.title",
  "audit.context.value",
  "audit.empty.filtered",
  "audit.empty.filtered_hint",
  "audit.empty.none",
  "audit.filter.action",
  "audit.filter.action_invalid",
  "audit.filter.action_placeholder",
  "audit.filter.clear",
  "audit.filter.from",
  "audit.filter.object",
  "audit.filter.object_invalid",
  "audit.filter.object_placeholder",
  "audit.filter.order",
  "audit.filter.order_asc",
  "audit.filter.order_desc",
  "audit.filter.outcome",
  "audit.filter.outcome_all",
  "audit.filter.principal",
  "audit.filter.principal_invalid",
  "audit.filter.principal_placeholder",
  "audit.filter.range_invalid",
  "audit.filter.time_invalid",
  "audit.filter.to",
  "audit.filter.value_invalid",
  "audit.filters.label",
  "audit.grid.label",
  "audit.hashes.first",
  "audit.hashes.hash",
  "audit.hashes.note",
  "audit.hashes.prev",
  "audit.hashes.title",
  "audit.kind.address",
  "audit.kind.api_token",
  "audit.kind.connector",
  "audit.kind.custom_field",
  "audit.kind.dhcp_class",
  "audit.kind.dhcp_filter",
  "audit.kind.dhcp_option_def",
  "audit.kind.dhcp_policy",
  "audit.kind.dhcp_scope",
  "audit.kind.dns_acl",
  "audit.kind.dns_forwarder",
  "audit.kind.dns_key",
  "audit.kind.dns_list",
  "audit.kind.dns_view",
  "audit.kind.host",
  "audit.kind.import",
  "audit.kind.interface",
  "audit.kind.job",
  "audit.kind.node",
  "audit.kind.observation",
  "audit.kind.prefix",
  "audit.kind.proposal",
  "audit.kind.range",
  "audit.kind.secret",
  "audit.kind.session",
  "audit.kind.settings",
  "audit.kind.site",
  "audit.kind.system",
  "audit.kind.tenant",
  "audit.kind.user",
  "audit.kind.vlan",
  "audit.kind.vrf",
  "audit.kind.zone",
  "audit.live.new",
  "audit.live.new_many",
  "audit.live.show",
  "audit.live.show_latest",
  "audit.outcome.denied",
  "audit.outcome.failed",
  "audit.outcome.success",
  "audit.principal.kind.node",
  "audit.principal.kind.system",
  "audit.principal.kind.token",
  "audit.principal.kind.user",
  "audit.record.back",
  "audit.record.component",
  "audit.record.crumbs",
  "audit.record.loading",
  "audit.record.next",
  "audit.record.not_found",
  "audit.record.not_set",
  "audit.record.object_log",
  "audit.record.objects",
  "audit.record.objects_none",
  "audit.record.on_behalf_of",
  "audit.record.open_newest",
  "audit.record.overview",
  "audit.record.owner",
  "audit.record.previous",
  "audit.record.principal_id",
  "audit.record.principal_kind",
  "audit.record.principal_log",
  "audit.record.request",
  "audit.record.revision",
  "audit.record.session",
  "audit.record.strength",
  "audit.record.title",
  "audit.row",
  "audit.strength.hardware_key",
  "audit.strength.passkey",
  "audit.strength.password",
  "audit.strength.password_totp",
  "audit.strength.pin",
  "audit.sub",
  "audit.title",
  "audit_export.add",
  "audit_export.add_title",
  "audit_export.alert_after_saved",
  "audit_export.checkpoint",
  "audit_export.col.actions",
  "audit_export.col.delivered",
  "audit_export.col.format",
  "audit_export.col.lag",
  "audit_export.col.name",
  "audit_export.col.state",
  "audit_export.col.target",
  "audit_export.delivered",
  "audit_export.edit_title",
  "audit_export.error.alert_after",
  "audit_export.error.client_key",
  "audit_export.error.file",
  "audit_export.error.host",
  "audit_export.error.keep",
  "audit_export.error.max_mib",
  "audit_export.error.name",
  "audit_export.error.port",
  "audit_export.failing.title",
  "audit_export.failing_since",
  "audit_export.field.alert_after",
  "audit_export.field.alert_after_help",
  "audit_export.field.ca_pem",
  "audit_export.field.ca_pem_help",
  "audit_export.field.client_cert_pem",
  "audit_export.field.client_cert_pem_help",
  "audit_export.field.client_key",
  "audit_export.field.client_key_help",
  "audit_export.field.facility",
  "audit_export.field.file",
  "audit_export.field.file_help",
  "audit_export.field.format",
  "audit_export.field.host",
  "audit_export.field.keep",
  "audit_export.field.max_mib",
  "audit_export.field.name",
  "audit_export.field.port",
  "audit_export.field.server_name",
  "audit_export.field.server_name_help",
  "audit_export.field.transport",
  "audit_export.format.cef",
  "audit_export.format.json",
  "audit_export.format.rfc5424",
  "audit_export.lede",
  "audit_export.none",
  "audit_export.pause",
  "audit_export.paused",
  "audit_export.policy.heading",
  "audit_export.policy.met",
  "audit_export.policy.unmet",
  "audit_export.policy.value",
  "audit_export.remove_body",
  "audit_export.remove_last",
  "audit_export.remove_named",
  "audit_export.remove_title",
  "audit_export.removed",
  "audit_export.required.title",
  "audit_export.resume",
  "audit_export.resumed",
  "audit_export.saved",
  "audit_export.sinks.heading",
  "audit_export.state.alarm",
  "audit_export.state.behind",
  "audit_export.state.disabled",
  "audit_export.state.failing",
  "audit_export.state.ok",
  "audit_export.state.pending",
  "audit_export.test",
  "audit_export.test_failed",
  "audit_export.test_ok",
  "audit_export.title",
  "audit_export.transport.file",
  "audit_export.transport.file_help",
  "audit_export.transport.tcp",
  "audit_export.transport.tcp_help",
  "audit_export.transport.tls",
  "audit_export.transport.tls_help",
  "audit_export.transport.udp",
  "audit_export.transport.udp_help",
  "audit_export.udp_warning",
  "audit_export.verify.body",
  "audit_export.verify.heading",
  "audit_export.warning.failing",
  "audit_export.warning.required",
  "auth.signin.back_to_sign_in",
  "auth.signin.break_glass_button",
  "auth.signin.break_glass_lead",
  "auth.signin.break_glass_link",
  "auth.signin.break_glass_title",
  "auth.signin.break_glass_warning",
  "auth.signin.ceremony.cancelled",
  "auth.signin.ceremony.exists",
  "auth.signin.ceremony.failed",
  "auth.signin.ceremony.insecure",
  "auth.signin.ceremony.unsupported",
  "auth.signin.insecure",
  "auth.signin.lead",
  "auth.signin.or",
  "auth.signin.passkey",
  "auth.signin.passkey_insecure",
  "auth.signin.passkey_unsupported",
  "auth.signin.password",
  "auth.signin.product",
  "auth.signin.recovery_code",
  "auth.signin.retry_in",
  "auth.signin.second_lead_recovery",
  "auth.signin.second_lead_totp",
  "auth.signin.second_title",
  "auth.signin.secure",
  "auth.signin.start_over",
  "auth.signin.submit",
  "auth.signin.throttle_explain",
  "auth.signin.title",
  "auth.signin.totp_code",
  "auth.signin.use_passkey",
  "auth.signin.use_password",
  "auth.signin.use_recovery",
  "auth.signin.use_totp",
  "auth.signin.user_name",
  "auth.signin.verify",
  "auth.signin.waiting",
  "auth.signin.waiting_key",
  "auth.strength.hardware_key",
  "auth.strength.passkey",
  "auth.strength.password",
  "auth.strength.password_totp",
  "auth.strength.pin",
  "backup.create.again",
  "backup.create.body",
  "backup.create.done",
  "backup.create.error.mismatch",
  "backup.create.error.short",
  "backup.create.passphrase",
  "backup.create.passphrase_help",
  "backup.create.passphrase_only",
  "backup.create.passphrase_optional",
  "backup.create.title",
  "backup.create.with_recipient",
  "backup.job_link",
  "backup.lede",
  "backup.now",
  "backup.restore.body",
  "backup.restore.note",
  "backup.restore.open",
  "backup.restore.open_named",
  "backup.restore.slots",
  "backup.restore.title",
  "backup.restored.body",
  "backup.restored.nodes",
  "backup.restored.title",
  "backup.run.failed",
  "backup.run.manual",
  "backup.run.scheduled",
  "backup.run.succeeded",
  "backup.running",
  "backup.runs.col.actions",
  "backup.runs.col.file",
  "backup.runs.col.finished",
  "backup.runs.col.node",
  "backup.runs.col.outcome",
  "backup.runs.col.reason",
  "backup.runs.col.size",
  "backup.runs.heading",
  "backup.runs.none",
  "backup.schedule.enabled",
  "backup.schedule.enabled_help",
  "backup.schedule.error.interval",
  "backup.schedule.error.keep",
  "backup.schedule.error.recipient",
  "backup.schedule.error.target_dir",
  "backup.schedule.every",
  "backup.schedule.heading",
  "backup.schedule.include_config",
  "backup.schedule.interval",
  "backup.schedule.interval_help",
  "backup.schedule.keep",
  "backup.schedule.keep_help",
  "backup.schedule.needs_recipient",
  "backup.schedule.off",
  "backup.schedule.recipient",
  "backup.schedule.recipient_help",
  "backup.schedule.saved",
  "backup.schedule.target_dir",
  "backup.schedule.target_dir_help",
  "backup.slot.passphrase",
  "backup.slot.recipient",
  "backup.state.age_label",
  "backup.state.heading",
  "backup.state.last_failed",
  "backup.state.last_good",
  "backup.state.never",
  "backup.state.next",
  "backup.state.not_scheduled",
  "backup.state.recipient",
  "backup.state.recipient_no",
  "backup.state.recipient_yes",
  "backup.state.running",
  "backup.state.running_no",
  "backup.state.running_yes",
  "backup.state.target",
  "backup.step_up.body",
  "backup.step_up.sign_in",
  "backup.step_up.title",
  "backup.title",
  "backup.warning.failed",
  "backup.warning.restored",
  "backup.warning.stale",
  "certificates.accept.label",
  "certificates.accept.off",
  "certificates.accept.on",
  "certificates.accept.where",
  "certificates.ca.heading",
  "certificates.chain",
  "certificates.chain_len",
  "certificates.days",
  "certificates.days_left",
  "certificates.error",
  "certificates.expiry.expired",
  "certificates.expiry.not_yet_valid",
  "certificates.expiry.soon",
  "certificates.fingerprint",
  "certificates.hsts",
  "certificates.imported.cert_path",
  "certificates.imported.heading",
  "certificates.imported.interval",
  "certificates.imported.interval.value",
  "certificates.imported.key_path",
  "certificates.issuer",
  "certificates.lede",
  "certificates.loaded_at",
  "certificates.min_version",
  "certificates.min_version.value",
  "certificates.mode.heading",
  "certificates.mode.imported",
  "certificates.mode.imported.help",
  "certificates.mode.internal_ca",
  "certificates.mode.internal_ca.help",
  "certificates.mode.label",
  "certificates.mode.plain",
  "certificates.mode.plain.help",
  "certificates.mode.reverse_proxy",
  "certificates.mode.reverse_proxy.help",
  "certificates.names",
  "certificates.names.none",
  "certificates.none",
  "certificates.off",
  "certificates.on",
  "certificates.pending.detected",
  "certificates.pending.heading",
  "certificates.pending.notice",
  "certificates.plain.notice",
  "certificates.proxy.heading",
  "certificates.proxy.host",
  "certificates.proxy.note",
  "certificates.proxy.protocol",
  "certificates.proxy.trusted",
  "certificates.read_at",
  "certificates.refresh",
  "certificates.rule.hardened",
  "certificates.rule.home",
  "certificates.rule.lab",
  "certificates.rule.standard",
  "certificates.rule.unknown",
  "certificates.served.heading",
  "certificates.subject",
  "certificates.title",
  "certificates.unknown",
  "certificates.valid_from",
  "certificates.valid_until",
  "cluster.action.add",
  "cluster.action.check_digests",
  "cluster.action.promote",
  "cluster.action.promote_named",
  "cluster.action.queue",
  "cluster.action.remove",
  "cluster.action.remove_named",
  "cluster.action.step_down",
  "cluster.add.intro",
  "cluster.add.next",
  "cluster.add.title",
  "cluster.blocker.changing",
  "cluster.blocker.even_voters",
  "cluster.blocker.last_voter",
  "cluster.blocker.no_successor",
  "cluster.blocker.not_caught_up",
  "cluster.blocker.not_learner",
  "cluster.blocker.not_voter",
  "cluster.blocker.single",
  "cluster.caveat.even_after",
  "cluster.caveat.forced",
  "cluster.caveat.no_tolerance",
  "cluster.caveat.reconnect",
  "cluster.caveat.removes_leader",
  "cluster.caveat.removes_self",
  "cluster.caveat.replaces",
  "cluster.caveat.revokes",
  "cluster.changing",
  "cluster.col.actions",
  "cluster.col.address",
  "cluster.col.compat",
  "cluster.col.contact",
  "cluster.col.format",
  "cluster.col.health",
  "cluster.col.joined",
  "cluster.col.lag",
  "cluster.col.name",
  "cluster.col.role",
  "cluster.col.version",
  "cluster.compat.format_one",
  "cluster.compat.format_range",
  "cluster.compat.tooltip",
  "cluster.digests.agree",
  "cluster.digests.col.digest",
  "cluster.digests.col.entries",
  "cluster.digests.col.member",
  "cluster.digests.col.revision",
  "cluster.digests.col.state",
  "cluster.digests.col.tables",
  "cluster.digests.differ",
  "cluster.digests.intro",
  "cluster.digests.state.agrees",
  "cluster.digests.state.differs",
  "cluster.digests.state.missing",
  "cluster.digests.title",
  "cluster.done.open_job",
  "cluster.done.promoted",
  "cluster.done.removed",
  "cluster.done.stepped_down",
  "cluster.format.advice",
  "cluster.format.binary",
  "cluster.format.blocked",
  "cluster.format.current",
  "cluster.format.knows",
  "cluster.format.not_reported",
  "cluster.format.stored",
  "cluster.format.target",
  "cluster.format.title",
  "cluster.format.waiting",
  "cluster.health.catching_up",
  "cluster.health.caught_up",
  "cluster.health.leader",
  "cluster.health.out_of_contact",
  "cluster.health.unknown",
  "cluster.job.edit",
  "cluster.job.write_preview",
  "cluster.member.leader_marker",
  "cluster.member.unnamed",
  "cluster.members.count",
  "cluster.members.title",
  "cluster.no_quorum.body",
  "cluster.no_quorum.body_since",
  "cluster.no_quorum.not_queueable",
  "cluster.no_quorum.queue",
  "cluster.no_quorum.queueable",
  "cluster.no_quorum.queued",
  "cluster.no_quorum.show_queue",
  "cluster.no_quorum.title",
  "cluster.partition.conflicts",
  "cluster.partition.electing.body",
  "cluster.partition.electing.title",
  "cluster.partition.isolated.body",
  "cluster.partition.isolated.title",
  "cluster.partition.queue_link",
  "cluster.partition.review",
  "cluster.partition.stale",
  "cluster.partition.stale_title",
  "cluster.preview.blockers",
  "cluster.preview.caveats",
  "cluster.preview.change",
  "cluster.preview.forceable",
  "cluster.preview.same",
  "cluster.preview.tolerated",
  "cluster.preview.voters",
  "cluster.promote.confirm",
  "cluster.promote.force",
  "cluster.promote.force_help",
  "cluster.promote.intro",
  "cluster.promote.replace",
  "cluster.promote.replace_help",
  "cluster.promote.replace_none",
  "cluster.promote.title",
  "cluster.queue.action",
  "cluster.queue.cancel_body",
  "cluster.queue.cancel_confirm",
  "cluster.queue.cancel_failed",
  "cluster.queue.cancel_named",
  "cluster.queue.cancel_title",
  "cluster.queue.cancelled",
  "cluster.queue.change_state.applied",
  "cluster.queue.change_state.conflict",
  "cluster.queue.change_state.expired",
  "cluster.queue.changes.empty",
  "cluster.queue.changes.intro",
  "cluster.queue.changes.title",
  "cluster.queue.col.actions",
  "cluster.queue.col.change",
  "cluster.queue.col.expires",
  "cluster.queue.col.queued",
  "cluster.queue.col.request",
  "cluster.queue.col.result",
  "cluster.queue.col.state",
  "cluster.queue.conflict.expired",
  "cluster.queue.conflict.other",
  "cluster.queue.conflict.stale",
  "cluster.queue.count",
  "cluster.queue.discard",
  "cluster.queue.discard_body",
  "cluster.queue.discard_failed",
  "cluster.queue.discard_named",
  "cluster.queue.discard_title",
  "cluster.queue.discarded",
  "cluster.queue.dismiss",
  "cluster.queue.dismiss_named",
  "cluster.queue.dismissed",
  "cluster.queue.keep",
  "cluster.queue.kind",
  "cluster.queue.local.empty",
  "cluster.queue.local.intro",
  "cluster.queue.local.title",
  "cluster.queue.reapplied",
  "cluster.queue.reapply",
  "cluster.queue.reapply_confirm",
  "cluster.queue.reapply_intro",
  "cluster.queue.reapply_named",
  "cluster.queue.reapply_title",
  "cluster.queue.state.applying",
  "cluster.queue.state.expired",
  "cluster.queue.state.queued",
  "cluster.queue.title",
  "cluster.queue.unavailable",
  "cluster.queue.what_unknown",
  "cluster.quorum.electing",
  "cluster.quorum.healthy",
  "cluster.quorum.isolated",
  "cluster.quorum.single",
  "cluster.remove.confirm",
  "cluster.remove.intro",
  "cluster.remove.title",
  "cluster.role.learner",
  "cluster.role.voter",
  "cluster.step_down.confirm",
  "cluster.step_down.intro",
  "cluster.step_down.successor",
  "cluster.step_down.title",
  "cluster.summary.label",
  "cluster.summary.leader",
  "cluster.summary.no_leader",
  "cluster.summary.node",
  "cluster.summary.quorum",
  "cluster.summary.since",
  "cluster.summary.term",
  "cluster.summary.voters",
  "cluster.summary.voters_value",
  "cluster.title",
  "cluster.tolerance",
  "cluster.warning.migration_blocked",
  "common.action.add",
  "common.action.back",
  "common.action.cancel",
  "common.action.close",
  "common.action.continue",
  "common.action.copied",
  "common.action.copy",
  "common.action.create",
  "common.action.delete",
  "common.action.dismiss",
  "common.action.download",
  "common.action.edit",
  "common.action.hide",
  "common.action.print",
  "common.action.remove",
  "common.action.retry",
  "common.action.revoke",
  "common.action.save",
  "common.action.show",
  "common.ca_root.download",
  "common.ca_root.help",
  "common.count.items",
  "common.greeting",
  "common.loading",
  "common.never",
  "common.no",
  "common.none",
  "common.optional",
  "common.recommended",
  "common.required",
  "common.unknown",
  "common.yes",
  "connect.job.edit",
  "connect.job.poll_preview",
  "connect.job.run",
  "connect.job.write_preview",
  "connectors.action.check",
  "connectors.action.create",
  "connectors.action.delete",
  "connectors.action.disable",
  "connectors.action.edit",
  "connectors.action.enable",
  "connectors.action.open",
  "connectors.action.run",
  "connectors.action.toggle",
  "connectors.capability.actuator",
  "connectors.capability.inventory",
  "connectors.capability.migration",
  "connectors.capability.network_controller",
  "connectors.capability.webhook",
  "connectors.col.capabilities",
  "connectors.col.health",
  "connectors.col.last_run",
  "connectors.col.name",
  "connectors.col.plugin",
  "connectors.col.poll",
  "connectors.col.process",
  "connectors.col.writes",
  "connectors.delete.body",
  "connectors.delete.confirm",
  "connectors.delete.title",
  "connectors.detail.all_jobs",
  "connectors.detail.back",
  "connectors.detail.changed",
  "connectors.detail.check_failed",
  "connectors.detail.checked",
  "connectors.detail.config",
  "connectors.detail.created",
  "connectors.detail.detail",
  "connectors.detail.disabled",
  "connectors.detail.error",
  "connectors.detail.failed_runs",
  "connectors.detail.failures",
  "connectors.detail.health",
  "connectors.detail.job",
  "connectors.detail.last_error",
  "connectors.detail.last_run",
  "connectors.detail.last_success",
  "connectors.detail.latency",
  "connectors.detail.ms",
  "connectors.detail.no",
  "connectors.detail.no_check",
  "connectors.detail.no_runs",
  "connectors.detail.observations",
  "connectors.detail.observations_link",
  "connectors.detail.outcome",
  "connectors.detail.pages",
  "connectors.detail.process",
  "connectors.detail.remote",
  "connectors.detail.remote_version",
  "connectors.detail.restarts",
  "connectors.detail.runs",
  "connectors.detail.started",
  "connectors.detail.state",
  "connectors.detail.trigger",
  "connectors.detail.updated",
  "connectors.detail.version",
  "connectors.detail.warnings",
  "connectors.detail.yes",
  "connectors.empty.body",
  "connectors.empty.title",
  "connectors.form.choose",
  "connectors.form.create",
  "connectors.form.default",
  "connectors.form.default_secs",
  "connectors.form.enabled",
  "connectors.form.example",
  "connectors.form.guardrails",
  "connectors.form.interval_range",
  "connectors.form.item_add",
  "connectors.form.item_add_to",
  "connectors.form.item_label",
  "connectors.form.item_remove",
  "connectors.form.items_empty",
  "connectors.form.name",
  "connectors.form.name_help",
  "connectors.form.name_long",
  "connectors.form.name_required",
  "connectors.form.no_plugins",
  "connectors.form.no_settings",
  "connectors.form.on",
  "connectors.form.plugin",
  "connectors.form.plugin_fixed",
  "connectors.form.poll",
  "connectors.form.save",
  "connectors.form.secret_missing",
  "connectors.form.secret_none",
  "connectors.form.secret_other",
  "connectors.form.secret_purpose",
  "connectors.form.secret_tagged",
  "connectors.form.secret_unlisted",
  "connectors.form.secrets",
  "connectors.form.secrets_admin",
  "connectors.form.secrets_help",
  "connectors.form.settings",
  "connectors.form.stale",
  "connectors.form.targets",
  "connectors.form.timeout",
  "connectors.form.title_create",
  "connectors.form.title_edit",
  "connectors.form.unsupported",
  "connectors.form.writes",
  "connectors.form.writes_help",
  "connectors.form.writes_read_only",
  "connectors.form.writes_warning",
  "connectors.health.degraded",
  "connectors.health.failing",
  "connectors.health.healthy",
  "connectors.health.off",
  "connectors.instances",
  "connectors.plugins.capabilities",
  "connectors.plugins.homepage",
  "connectors.plugins.license",
  "connectors.plugins.none",
  "connectors.plugins.platforms",
  "connectors.plugins.reload",
  "connectors.plugins.secrets",
  "connectors.plugins.source.bundled",
  "connectors.plugins.source.installed",
  "connectors.plugins.title",
  "connectors.plugins.unusable",
  "connectors.problem.enum",
  "connectors.problem.format",
  "connectors.problem.items",
  "connectors.problem.items_max",
  "connectors.problem.items_min",
  "connectors.problem.length",
  "connectors.problem.length_max",
  "connectors.problem.length_min",
  "connectors.problem.pattern",
  "connectors.problem.range",
  "connectors.problem.range_max",
  "connectors.problem.range_min",
  "connectors.problem.required",
  "connectors.problem.type",
  "connectors.problem.unique",
  "connectors.problem.unknown",
  "connectors.process.backoff",
  "connectors.process.circuit_open",
  "connectors.process.failed",
  "connectors.process.running",
  "connectors.process.starting",
  "connectors.process.stopped",
  "connectors.process.until",
  "connectors.remote.degraded",
  "connectors.remote.healthy",
  "connectors.remote.unreachable",
  "connectors.run.failed",
  "connectors.run.never",
  "connectors.run.succeeded",
  "connectors.seconds",
  "connectors.seconds_default",
  "connectors.sub",
  "connectors.toast.change_failed",
  "connectors.toast.check_failed",
  "connectors.toast.checked",
  "connectors.toast.delete_failed",
  "connectors.toast.deleted",
  "connectors.toast.disabled",
  "connectors.toast.enabled",
  "connectors.toast.open_job",
  "connectors.toast.run",
  "connectors.toast.run_failed",
  "connectors.trigger.manual",
  "connectors.trigger.schedule",
  "connectors.writes.off",
  "connectors.writes.on",
  "dashboard.action.claim",
  "dashboard.action.claim_where",
  "dashboard.action.import",
  "dashboard.action.prefix",
  "dashboard.alarms.none",
  "dashboard.alarms.title",
  "dashboard.audit.all",
  "dashboard.audit.none",
  "dashboard.audit.title",
  "dashboard.modules.name.dhcp",
  "dashboard.modules.name.discovery",
  "dashboard.modules.name.dns",
  "dashboard.modules.name.ipam",
  "dashboard.modules.none",
  "dashboard.modules.restart_body",
  "dashboard.modules.restart_title",
  "dashboard.palette_hint",
  "dashboard.tile.addresses",
  "dashboard.tile.addresses_of",
  "dashboard.tile.alarms",
  "dashboard.tile.alarms_hint",
  "dashboard.tile.connectors",
  "dashboard.tile.connectors_hint",
  "dashboard.tile.connectors_link",
  "dashboard.tile.nodes",
  "dashboard.tile.nodes_hint",
  "dashboard.tile.nodes_link",
  "dashboard.tile.nodes_none",
  "dashboard.tile.proposals",
  "dashboard.tile.proposals_hint",
  "dashboard.tile.proposals_link",
  "dashboard.tile.waiting_for_you",
  "dashboard.update.action",
  "dashboard.update.body",
  "dashboard.update.open",
  "dashboard.update.security",
  "dashboard.update.title",
  "dashboard.use.empty",
  "dashboard.use.more",
  "dashboard.use.networks",
  "dashboard.use.of",
  "dashboard.use.title",
  "dashboard.use.vrf",
  "dashboard.waiting.all",
  "dashboard.waiting.none",
  "dashboard.waiting.step",
  "dashboard.waiting.title",
  "dhcp.action.ddns_off",
  "dhcp.action.ddns_on",
  "dhcp.action.ddns_on_zone",
  "dhcp.action.lease",
  "dhcp.action.none",
  "dhcp.action.options",
  "dhcp.action.range",
  "dhcp.arch.empty",
  "dhcp.arch.label",
  "dhcp.arch.name.0",
  "dhcp.arch.name.10",
  "dhcp.arch.name.11",
  "dhcp.arch.name.15",
  "dhcp.arch.name.16",
  "dhcp.arch.name.19",
  "dhcp.arch.name.6",
  "dhcp.arch.name.7",
  "dhcp.arch.name.9",
  "dhcp.arch.none",
  "dhcp.arch.option",
  "dhcp.arch.other",
  "dhcp.arch.value_label",
  "dhcp.boot.add_button",
  "dhcp.boot.add_done",
  "dhcp.boot.add_file",
  "dhcp.boot.add_file_help",
  "dhcp.boot.add_kind",
  "dhcp.boot.add_matches",
  "dhcp.boot.add_order_first",
  "dhcp.boot.add_order_last",
  "dhcp.boot.add_order_tie",
  "dhcp.boot.add_partial_class",
  "dhcp.boot.add_partial_policy",
  "dhcp.boot.add_submit",
  "dhcp.boot.add_title",
  "dhcp.boot.check.file_empty",
  "dhcp.boot.check.long",
  "dhcp.boot.col.file",
  "dhcp.boot.field.file",
  "dhcp.boot.field.next_server",
  "dhcp.boot.field.pxe_config",
  "dhcp.boot.field.pxe_prefix",
  "dhcp.boot.field.pxe_reboot",
  "dhcp.boot.field.tftp_name",
  "dhcp.boot.form_help",
  "dhcp.boot.form_title",
  "dhcp.boot.hint.file",
  "dhcp.boot.hint.next_server",
  "dhcp.boot.hint.pxe_config",
  "dhcp.boot.hint.pxe_prefix",
  "dhcp.boot.hint.pxe_reboot",
  "dhcp.boot.hint.tftp_name",
  "dhcp.boot.inherited",
  "dhcp.boot.inherited_none",
  "dhcp.boot.kind.bios",
  "dhcp.boot.kind.http",
  "dhcp.boot.kind.http_x64",
  "dhcp.boot.kind.ipxe",
  "dhcp.boot.kind.uefi_arm64",
  "dhcp.boot.kind.uefi_x64",
  "dhcp.boot.policies_empty",
  "dhcp.boot.policies_help",
  "dhcp.boot.policies_link",
  "dhcp.boot.policies_note",
  "dhcp.boot.policies_title",
  "dhcp.boot.save",
  "dhcp.boot.saved",
  "dhcp.boot.unchanged",
  "dhcp.catalog.managed",
  "dhcp.check.def_code",
  "dhcp.check.exclusion_first",
  "dhcp.check.exclusion_last",
  "dhcp.check.exclusion_order",
  "dhcp.check.exclusion_outside",
  "dhcp.check.hex",
  "dhcp.check.history_days",
  "dhcp.check.lease_number",
  "dhcp.check.lease_order",
  "dhcp.check.lease_year",
  "dhcp.check.mac",
  "dhcp.check.mac_pattern",
  "dhcp.check.match_empty",
  "dhcp.check.match_hex",
  "dhcp.check.match_long",
  "dhcp.check.match_mac",
  "dhcp.check.match_number",
  "dhcp.check.name",
  "dhcp.check.order",
  "dhcp.check.prefix",
  "dhcp.check.range_address",
  "dhcp.check.range_order",
  "dhcp.check.range_outside",
  "dhcp.check.server_id",
  "dhcp.check.server_id_clear",
  "dhcp.check.space",
  "dhcp.check.term_class",
  "dhcp.class.create",
  "dhcp.class.create_title",
  "dhcp.class.created",
  "dhcp.class.delete_body",
  "dhcp.class.delete_confirm",
  "dhcp.class.delete_title",
  "dhcp.class.deleted",
  "dhcp.class.edit_title",
  "dhcp.class.field.matches",
  "dhcp.class.field.matches_help",
  "dhcp.class.field.name",
  "dhcp.class.save",
  "dhcp.class.saved",
  "dhcp.classes.empty",
  "dhcp.classes.empty_body",
  "dhcp.classes.sub",
  "dhcp.classes.title",
  "dhcp.col.action",
  "dhcp.col.address",
  "dhcp.col.classes",
  "dhcp.col.client_id",
  "dhcp.col.client_mac",
  "dhcp.col.code",
  "dhcp.col.condition",
  "dhcp.col.description",
  "dhcp.col.enabled",
  "dhcp.col.ends",
  "dhcp.col.event",
  "dhcp.col.filter_kind",
  "dhcp.col.first",
  "dhcp.col.host_name",
  "dhcp.col.interface",
  "dhcp.col.last",
  "dhcp.col.lease",
  "dhcp.col.leased",
  "dhcp.col.leases",
  "dhcp.col.mac",
  "dhcp.col.matches",
  "dhcp.col.name",
  "dhcp.col.network",
  "dhcp.col.node",
  "dhcp.col.note",
  "dhcp.col.order",
  "dhcp.col.pools",
  "dhcp.col.range",
  "dhcp.col.relay",
  "dhcp.col.reserved",
  "dhcp.col.scope",
  "dhcp.col.scopes",
  "dhcp.col.server_managed",
  "dhcp.col.size",
  "dhcp.col.space",
  "dhcp.col.state",
  "dhcp.col.state_after",
  "dhcp.col.time",
  "dhcp.col.type",
  "dhcp.col.used_by",
  "dhcp.col.utilization",
  "dhcp.col.vendor_class",
  "dhcp.coming.body",
  "dhcp.coming.scopes",
  "dhcp.coming.title",
  "dhcp.ddns.check.ttl",
  "dhcp.ddns.conflict.protect",
  "dhcp.ddns.conflict.replace",
  "dhcp.ddns.field.client_a",
  "dhcp.ddns.field.client_a_help",
  "dhcp.ddns.field.conflict",
  "dhcp.ddns.field.enabled",
  "dhcp.ddns.field.foreign",
  "dhcp.ddns.field.foreign_help",
  "dhcp.ddns.field.legacy",
  "dhcp.ddns.field.legacy_help",
  "dhcp.ddns.field.reverse",
  "dhcp.ddns.field.reverse_help",
  "dhcp.ddns.field.ttl",
  "dhcp.ddns.field.ttl_help",
  "dhcp.ddns.field.zone",
  "dhcp.ddns.follows",
  "dhcp.ddns.hardened_note",
  "dhcp.ddns.help",
  "dhcp.ddns.inherit",
  "dhcp.ddns.inherit_help",
  "dhcp.ddns.legend",
  "dhcp.ddns.needs_dns",
  "dhcp.ddns.profile_open",
  "dhcp.ddns.profile_strict",
  "dhcp.ddns.saved",
  "dhcp.ddns.server_now",
  "dhcp.ddns.title",
  "dhcp.ddns.words.client_a",
  "dhcp.ddns.words.foreign",
  "dhcp.ddns.words.legacy_off",
  "dhcp.ddns.words.legacy_on",
  "dhcp.ddns.words.off",
  "dhcp.ddns.words.on",
  "dhcp.ddns.words.protect",
  "dhcp.ddns.words.replace",
  "dhcp.ddns.words.reverse_off",
  "dhcp.ddns.words.reverse_on",
  "dhcp.ddns.words.ttl",
  "dhcp.ddns.words.ttl_third",
  "dhcp.ddns.words.zone",
  "dhcp.ddns.words.zone_domain",
  "dhcp.ddns.zone_none",
  "dhcp.ddns.zone_state.off",
  "dhcp.ddns.zone_state.on",
  "dhcp.ddns.zone_state.profile_off",
  "dhcp.ddns.zone_state.profile_on",
  "dhcp.ddns.zone_unavailable",
  "dhcp.ddns.zone_unknown",
  "dhcp.def.create",
  "dhcp.def.create_title",
  "dhcp.def.created",
  "dhcp.def.delete_body",
  "dhcp.def.delete_confirm",
  "dhcp.def.delete_title",
  "dhcp.def.deleted",
  "dhcp.def.field.array",
  "dhcp.def.field.code",
  "dhcp.def.field.code_help",
  "dhcp.def.field.kind",
  "dhcp.def.field.name",
  "dhcp.def.field.space",
  "dhcp.def.field.space_help",
  "dhcp.def.field.vendor_class",
  "dhcp.def.field.vendor_class_help",
  "dhcp.def.help",
  "dhcp.defs.empty",
  "dhcp.do.delete",
  "dhcp.do.edit",
  "dhcp.do.history",
  "dhcp.do.open",
  "dhcp.do.refresh",
  "dhcp.effective.architecture",
  "dhcp.effective.classes",
  "dhcp.effective.client_id",
  "dhcp.effective.col.level",
  "dhcp.effective.col.why",
  "dhcp.effective.empty",
  "dhcp.effective.help_facts",
  "dhcp.effective.host_name",
  "dhcp.effective.mac",
  "dhcp.effective.no_classes",
  "dhcp.effective.no_policies",
  "dhcp.effective.note_live",
  "dhcp.effective.policies",
  "dhcp.effective.reservation",
  "dhcp.effective.show",
  "dhcp.effective.title",
  "dhcp.effective.user_class",
  "dhcp.effective.vendor_class",
  "dhcp.effective.why.host",
  "dhcp.effective.why.policy",
  "dhcp.effective.why.pool",
  "dhcp.effective.why.scope",
  "dhcp.effective.why.server",
  "dhcp.effective.why.shared_network",
  "dhcp.event.conflict",
  "dhcp.event.declined",
  "dhcp.event.expired",
  "dhcp.event.granted",
  "dhcp.event.rebound",
  "dhcp.event.reclaimed",
  "dhcp.event.released",
  "dhcp.event.renewed",
  "dhcp.example.addr",
  "dhcp.example.mac",
  "dhcp.example.mac_pattern",
  "dhcp.exclusion.create",
  "dhcp.exclusion.create_title",
  "dhcp.exclusion.created",
  "dhcp.exclusion.delete_body",
  "dhcp.exclusion.delete_confirm",
  "dhcp.exclusion.delete_title",
  "dhcp.exclusion.deleted",
  "dhcp.exclusion.field.first",
  "dhcp.exclusion.field.last",
  "dhcp.exclusion.help",
  "dhcp.exclusions.empty",
  "dhcp.exclusions.empty_body",
  "dhcp.exclusions.title",
  "dhcp.field.description",
  "dhcp.field.name_help",
  "dhcp.filter.create",
  "dhcp.filter.create_title",
  "dhcp.filter.created",
  "dhcp.filter.delete_body",
  "dhcp.filter.delete_confirm",
  "dhcp.filter.delete_title",
  "dhcp.filter.deleted",
  "dhcp.filter.edit_title",
  "dhcp.filter.field.kind",
  "dhcp.filter.field.mac",
  "dhcp.filter.field.mac_help",
  "dhcp.filter.field.note",
  "dhcp.filter.kind.allow",
  "dhcp.filter.kind.deny",
  "dhcp.filter.save",
  "dhcp.filter.saved",
  "dhcp.filters.empty",
  "dhcp.filters.empty_body",
  "dhcp.filters.note",
  "dhcp.filters.sub",
  "dhcp.filters.title",
  "dhcp.history.empty",
  "dhcp.history.empty_body",
  "dhcp.history.empty_filtered",
  "dhcp.history.empty_filtered_body",
  "dhcp.history.filters",
  "dhcp.history.lease_link",
  "dhcp.history.more",
  "dhcp.history.sub",
  "dhcp.history.title",
  "dhcp.join.and",
  "dhcp.join.or",
  "dhcp.lease.default",
  "dhcp.lease.history_link",
  "dhcp.lease.host_missing",
  "dhcp.lease.inherit",
  "dhcp.lease.legend",
  "dhcp.lease.max",
  "dhcp.lease.min",
  "dhcp.lease.open_host",
  "dhcp.lease.reason",
  "dhcp.lease.reason_help",
  "dhcp.lease.release",
  "dhcp.lease.release_body",
  "dhcp.lease.release_confirm",
  "dhcp.lease.release_title",
  "dhcp.lease.released",
  "dhcp.lease.reserve",
  "dhcp.lease.reserved",
  "dhcp.lease.server_now",
  "dhcp.lease.unit",
  "dhcp.lease.words",
  "dhcp.leases.empty",
  "dhcp.leases.empty_body",
  "dhcp.leases.empty_filtered",
  "dhcp.leases.empty_filtered_body",
  "dhcp.leases.filters",
  "dhcp.leases.more",
  "dhcp.leases.state.abandoned",
  "dhcp.leases.state.active",
  "dhcp.leases.state.backup",
  "dhcp.leases.state.expired",
  "dhcp.leases.state.free",
  "dhcp.leases.state.released",
  "dhcp.leases.state.reset",
  "dhcp.leases.sub",
  "dhcp.leases.title",
  "dhcp.level.host",
  "dhcp.level.policy",
  "dhcp.level.pool",
  "dhcp.level.scope",
  "dhcp.level.server",
  "dhcp.level.shared_network",
  "dhcp.lfilter.addr",
  "dhcp.lfilter.addr_exact",
  "dhcp.lfilter.addr_placeholder",
  "dhcp.lfilter.from",
  "dhcp.lfilter.kind",
  "dhcp.lfilter.kind_any",
  "dhcp.lfilter.mac",
  "dhcp.lfilter.mac_invalid",
  "dhcp.lfilter.name",
  "dhcp.lfilter.name_placeholder",
  "dhcp.lfilter.reset",
  "dhcp.lfilter.scope",
  "dhcp.lfilter.scope_any",
  "dhcp.lfilter.state",
  "dhcp.lfilter.state_any",
  "dhcp.lfilter.to",
  "dhcp.live.bars_label",
  "dhcp.live.folded",
  "dhcp.live.hint",
  "dhcp.live.label",
  "dhcp.live.new",
  "dhcp.live.new_capped",
  "dhcp.live.new_label",
  "dhcp.live.new_link",
  "dhcp.live.new_paused",
  "dhcp.live.new_reset",
  "dhcp.live.new_reset_hint",
  "dhcp.live.new_since",
  "dhcp.live.scope_more",
  "dhcp.live.scope_open",
  "dhcp.live.scope_pick",
  "dhcp.live.strip_label",
  "dhcp.match.add",
  "dhcp.match.architecture",
  "dhcp.match.architecture_named",
  "dhcp.match.circuit_id",
  "dhcp.match.client_id",
  "dhcp.match.example.architecture",
  "dhcp.match.example.circuit_id",
  "dhcp.match.example.client_id",
  "dhcp.match.example.host_name",
  "dhcp.match.example.mac",
  "dhcp.match.example.remote_id",
  "dhcp.match.example.user_class",
  "dhcp.match.example.vendor_class",
  "dhcp.match.host_name",
  "dhcp.match.host_name_prefix",
  "dhcp.match.kind.architecture",
  "dhcp.match.kind.circuit_id",
  "dhcp.match.kind.client_id",
  "dhcp.match.kind.host_name",
  "dhcp.match.kind.mac",
  "dhcp.match.kind.remote_id",
  "dhcp.match.kind.user_class",
  "dhcp.match.kind.vendor_class",
  "dhcp.match.kind_label",
  "dhcp.match.mac",
  "dhcp.match.prefix",
  "dhcp.match.remote_id",
  "dhcp.match.remove",
  "dhcp.match.row",
  "dhcp.match.user_class",
  "dhcp.match.value_label",
  "dhcp.match.vendor_class",
  "dhcp.match.vendor_class_prefix",
  "dhcp.nav.classes",
  "dhcp.nav.filters",
  "dhcp.nav.history",
  "dhcp.nav.label",
  "dhcp.nav.leases",
  "dhcp.nav.options",
  "dhcp.nav.policies",
  "dhcp.nav.scopes",
  "dhcp.nav.shared_networks",
  "dhcp.network.create",
  "dhcp.network.create_title",
  "dhcp.network.created",
  "dhcp.network.delete_body",
  "dhcp.network.delete_confirm",
  "dhcp.network.delete_title",
  "dhcp.network.deleted",
  "dhcp.network.edit_title",
  "dhcp.network.empty",
  "dhcp.network.empty_body",
  "dhcp.network.field.interface",
  "dhcp.network.field.interface_help",
  "dhcp.network.field.name",
  "dhcp.network.save",
  "dhcp.network.saved",
  "dhcp.network.sub",
  "dhcp.options.catalog",
  "dhcp.options.catalog_help",
  "dhcp.options.defs",
  "dhcp.options.defs_help",
  "dhcp.options.server",
  "dhcp.options.server_help",
  "dhcp.options.sub",
  "dhcp.options.title",
  "dhcp.optset.add",
  "dhcp.optset.add_code",
  "dhcp.optset.check.bool",
  "dhcp.optset.check.code",
  "dhcp.optset.check.count",
  "dhcp.optset.check.empty",
  "dhcp.optset.check.hex",
  "dhcp.optset.check.ipv4",
  "dhcp.optset.check.ipv6",
  "dhcp.optset.check.managed",
  "dhcp.optset.check.name",
  "dhcp.optset.check.number",
  "dhcp.optset.check.prefix",
  "dhcp.optset.check.range",
  "dhcp.optset.check.raw_hex",
  "dhcp.optset.check.route",
  "dhcp.optset.col.actions",
  "dhcp.optset.col.code",
  "dhcp.optset.col.name",
  "dhcp.optset.col.value",
  "dhcp.optset.empty",
  "dhcp.optset.flag",
  "dhcp.optset.kind.binary",
  "dhcp.optset.kind.bool",
  "dhcp.optset.kind.classless_routes",
  "dhcp.optset.kind.empty",
  "dhcp.optset.kind.fqdn",
  "dhcp.optset.kind.i32",
  "dhcp.optset.kind.ipv4_address",
  "dhcp.optset.kind.ipv6_address",
  "dhcp.optset.kind.ipv6_prefix",
  "dhcp.optset.kind.string",
  "dhcp.optset.kind.u16",
  "dhcp.optset.kind.u32",
  "dhcp.optset.kind.u8",
  "dhcp.optset.kind_list",
  "dhcp.optset.raw",
  "dhcp.optset.remove",
  "dhcp.optset.revert",
  "dhcp.optset.routes_help",
  "dhcp.optset.save",
  "dhcp.optset.saved",
  "dhcp.optset.unknown",
  "dhcp.optset.value_of",
  "dhcp.policies.empty",
  "dhcp.policies.empty_body",
  "dhcp.policies.note_live",
  "dhcp.policies.sub",
  "dhcp.policies.title",
  "dhcp.policy.create",
  "dhcp.policy.create_title",
  "dhcp.policy.created",
  "dhcp.policy.ddns.help",
  "dhcp.policy.ddns.legend",
  "dhcp.policy.ddns.on",
  "dhcp.policy.delete_body",
  "dhcp.policy.delete_confirm",
  "dhcp.policy.delete_title",
  "dhcp.policy.deleted",
  "dhcp.policy.edit_title",
  "dhcp.policy.field.action",
  "dhcp.policy.field.condition",
  "dhcp.policy.field.enabled",
  "dhcp.policy.field.join",
  "dhcp.policy.field.name",
  "dhcp.policy.field.order",
  "dhcp.policy.field.order_help",
  "dhcp.policy.field.range_first",
  "dhcp.policy.field.range_last",
  "dhcp.policy.field.scope",
  "dhcp.policy.field.scope_fixed",
  "dhcp.policy.lease_inherit_help",
  "dhcp.policy.options.help",
  "dhcp.policy.options.label",
  "dhcp.policy.options.new",
  "dhcp.policy.options.title",
  "dhcp.policy.save",
  "dhcp.policy.saved",
  "dhcp.policy.scope_server",
  "dhcp.pool.clear",
  "dhcp.pool.clear_body",
  "dhcp.pool.clear_title",
  "dhcp.pool.cleared",
  "dhcp.pool.edit_title",
  "dhcp.pool.field.classes",
  "dhcp.pool.field.classes_help",
  "dhcp.pool.lease_inherit_help",
  "dhcp.pool.lease_range",
  "dhcp.pool.lease_scope",
  "dhcp.pool.save",
  "dhcp.pool.saved",
  "dhcp.pool.settings",
  "dhcp.pools.empty",
  "dhcp.pools.empty_body",
  "dhcp.pools.ipam_link",
  "dhcp.pools.note",
  "dhcp.pools.title",
  "dhcp.reservations.col_identity",
  "dhcp.reservations.col_lease",
  "dhcp.reservations.col_served",
  "dhcp.reservations.empty",
  "dhcp.reservations.help",
  "dhcp.reservations.identity_client_id",
  "dhcp.reservations.identity_mac",
  "dhcp.reservations.identity_none",
  "dhcp.reservations.ipv6_later",
  "dhcp.reservations.lease_ends",
  "dhcp.reservations.lease_failed",
  "dhcp.reservations.lease_none",
  "dhcp.reservations.lease_other",
  "dhcp.reservations.scope_none",
  "dhcp.reservations.scope_setup",
  "dhcp.reservations.state_not_serving",
  "dhcp.reservations.state_scope_disabled",
  "dhcp.reservations.state_served",
  "dhcp.reservations.title",
  "dhcp.reserve.check.client_id",
  "dhcp.reserve.check.host_name",
  "dhcp.reserve.check.identity",
  "dhcp.reserve.check.interface_name",
  "dhcp.reserve.check.ip",
  "dhcp.reserve.check.mac",
  "dhcp.reserve.field.address",
  "dhcp.reserve.field.address_help",
  "dhcp.reserve.field.client_id",
  "dhcp.reserve.field.client_id_help",
  "dhcp.reserve.field.host",
  "dhcp.reserve.field.interface",
  "dhcp.reserve.field.mac",
  "dhcp.reserve.field.mac_help",
  "dhcp.reserve.field.new_host",
  "dhcp.reserve.field.new_interface",
  "dhcp.reserve.field.status",
  "dhcp.reserve.host_new",
  "dhcp.reserve.host_option",
  "dhcp.reserve.in_pool",
  "dhcp.reserve.in_pool_lease",
  "dhcp.reserve.interface_new",
  "dhcp.reserve.loading",
  "dhcp.reserve.mode.dynamic",
  "dhcp.reserve.mode.reserved",
  "dhcp.reserve.mode.static",
  "dhcp.reserve.mode.unmanaged",
  "dhcp.reserve.no_scope",
  "dhcp.reserve.open_host",
  "dhcp.reserve.outside",
  "dhcp.reserve.preview",
  "dhcp.reserve.save",
  "dhcp.reserve.saved",
  "dhcp.reserve.saved_unchanged",
  "dhcp.reserve.scope_disabled",
  "dhcp.reserve.scope_link",
  "dhcp.reserve.scope_not_serving",
  "dhcp.reserve.scope_served",
  "dhcp.reserve.stale",
  "dhcp.reserve.status.active",
  "dhcp.reserve.status.planned",
  "dhcp.reserve.title",
  "dhcp.reserve.use_free",
  "dhcp.reserve.will.address_bound",
  "dhcp.reserve.will.address_kept",
  "dhcp.reserve.will.address_new",
  "dhcp.reserve.will.address_status",
  "dhcp.reserve.will.host_kept",
  "dhcp.reserve.will.host_mode",
  "dhcp.reserve.will.host_new",
  "dhcp.reserve.will.interface_client_id",
  "dhcp.reserve.will.interface_client_id_cleared",
  "dhcp.reserve.will.interface_mac",
  "dhcp.reserve.will.interface_mac_kept",
  "dhcp.reserve.will.interface_mac_replaced",
  "dhcp.reserve.will.interface_new",
  "dhcp.reserve.will.interface_new_mac",
  "dhcp.reserve.will.keyed_client_id",
  "dhcp.reserve.will.keyed_mac",
  "dhcp.reserve.will.lease_other",
  "dhcp.reserve.will.not_serving",
  "dhcp.reserve.will.nothing",
  "dhcp.reserve.will.scope_disabled",
  "dhcp.reserve.will.scope_served",
  "dhcp.scope.create",
  "dhcp.scope.create_title",
  "dhcp.scope.created",
  "dhcp.scope.ddns_line_off",
  "dhcp.scope.ddns_line_on",
  "dhcp.scope.ddns_link",
  "dhcp.scope.delete_body",
  "dhcp.scope.delete_confirm",
  "dhcp.scope.delete_title",
  "dhcp.scope.deleted",
  "dhcp.scope.disabled",
  "dhcp.scope.enabled",
  "dhcp.scope.field.authoritative",
  "dhcp.scope.field.authoritative_help",
  "dhcp.scope.field.classes",
  "dhcp.scope.field.classes_help",
  "dhcp.scope.field.enabled",
  "dhcp.scope.field.enabled_help",
  "dhcp.scope.field.prefix",
  "dhcp.scope.field.prefix_help",
  "dhcp.scope.field.prefix_pick",
  "dhcp.scope.field.restricted",
  "dhcp.scope.field.restricted_help",
  "dhcp.scope.field.server_id",
  "dhcp.scope.field.server_id_help",
  "dhcp.scope.field.shared_network",
  "dhcp.scope.in_ipam",
  "dhcp.scope.no_classes",
  "dhcp.scope.no_networks",
  "dhcp.scope.options_help",
  "dhcp.scope.options_title",
  "dhcp.scope.save",
  "dhcp.scope.saved",
  "dhcp.scope.settings",
  "dhcp.scope.shared_none",
  "dhcp.scope.tab.boot",
  "dhcp.scope.tab.ddns",
  "dhcp.scope.tab.exclusions",
  "dhcp.scope.tab.options",
  "dhcp.scope.tab.pools",
  "dhcp.scope.tab.settings",
  "dhcp.scope.tabs",
  "dhcp.scope.title",
  "dhcp.scope.unchanged",
  "dhcp.scopes.empty",
  "dhcp.scopes.empty_body",
  "dhcp.scopes.sub",
  "dhcp.scopes.title",
  "dhcp.settings.authoritative",
  "dhcp.settings.authoritative_help",
  "dhcp.settings.conflict",
  "dhcp.settings.conflict_follow",
  "dhcp.settings.conflict_help",
  "dhcp.settings.effective",
  "dhcp.settings.effective_days",
  "dhcp.settings.history_days",
  "dhcp.settings.history_days_help",
  "dhcp.settings.history_follow",
  "dhcp.settings.lease",
  "dhcp.settings.lease_help",
  "dhcp.settings.lede",
  "dhcp.settings.off",
  "dhcp.settings.on",
  "dhcp.settings.save",
  "dhcp.settings.saved",
  "dhcp.settings.server",
  "dhcp.settings.title",
  "dhcp.shared_networks.title",
  "dhcp.state.not_built_body",
  "dhcp.state.not_built_title",
  "dhcp.state.off_body",
  "dhcp.state.off_link",
  "dhcp.state.off_title",
  "dhcp.strip.accepting",
  "dhcp.strip.commit",
  "dhcp.strip.label",
  "dhcp.strip.listeners",
  "dhcp.strip.not_dhcp_body",
  "dhcp.strip.not_dhcp_title",
  "dhcp.strip.not_serving",
  "dhcp.strip.probe_off",
  "dhcp.strip.probe_on",
  "dhcp.strip.refusing",
  "dhcp.strip.revision",
  "dhcp.strip.scopes",
  "dhcp.strip.serving",
  "dhcp.term.add",
  "dhcp.term.class",
  "dhcp.term.class_label",
  "dhcp.term.class_pick",
  "dhcp.term.kind.class",
  "dhcp.term.kind.match",
  "dhcp.term.kind.not_class",
  "dhcp.term.kind.not_match",
  "dhcp.term.kind_label",
  "dhcp.term.not_class",
  "dhcp.term.not_match",
  "dhcp.term.remove",
  "dhcp.term.row",
  "dhcp.title",
  "dhcp.tri.inherit",
  "dhcp.unit.days",
  "dhcp.unit.hours",
  "dhcp.unit.minutes",
  "dhcp.util.abandoned",
  "dhcp.util.at",
  "dhcp.util.free",
  "dhcp.util.label",
  "dhcp.util.leased",
  "dhcp.util.percent",
  "dhcp.util.pool_size",
  "dhcp.util.reserved",
  "dhcp.util.title",
  "discovery.action.approve",
  "discovery.action.dismiss",
  "discovery.action.open",
  "discovery.action.reconcile",
  "discovery.action.reject",
  "discovery.approve.confirm",
  "discovery.approve.title",
  "discovery.batch.approve",
  "discovery.batch.approve_body",
  "discovery.batch.approve_confirm",
  "discovery.batch.approve_title",
  "discovery.batch.done_approved",
  "discovery.batch.done_rejected",
  "discovery.batch.done_skipped",
  "discovery.batch.keep",
  "discovery.batch.kind.address_mismatch",
  "discovery.batch.kind.conflict",
  "discovery.batch.kind.discovered_host",
  "discovery.batch.kind.orphaned_intent",
  "discovery.batch.kind.outside_prefixes",
  "discovery.batch.kind.prefix_vlan_mismatch",
  "discovery.batch.kind.vlan_discovered",
  "discovery.batch.loaded_only",
  "discovery.batch.reject",
  "discovery.batch.reject_body",
  "discovery.batch.reject_title",
  "discovery.batch.skipped_body",
  "discovery.batch.skipped_title",
  "discovery.col.created",
  "discovery.col.first_seen",
  "discovery.col.kind",
  "discovery.col.last_seen",
  "discovery.col.observed",
  "discovery.col.prefix",
  "discovery.col.severity",
  "discovery.col.sightings",
  "discovery.col.source",
  "discovery.col.sources",
  "discovery.col.state",
  "discovery.col.subject",
  "discovery.col.subject_key",
  "discovery.col.summary",
  "discovery.col.type",
  "discovery.col.updated",
  "discovery.count",
  "discovery.count_open",
  "discovery.empty.body",
  "discovery.empty.filtered",
  "discovery.empty.title",
  "discovery.fact.address_mac",
  "discovery.fact.attachment",
  "discovery.fact.attachment_vlan",
  "discovery.fact.current",
  "discovery.fact.expired",
  "discovery.fact.link",
  "discovery.fact.name",
  "discovery.fact.network",
  "discovery.fact.no_ports",
  "discovery.fact.os",
  "discovery.fact.parent",
  "discovery.fact.port",
  "discovery.fact.ports",
  "discovery.fact.ssid",
  "discovery.fact.tls",
  "discovery.fact.vendor",
  "discovery.fact_type.address",
  "discovery.fact_type.attachment",
  "discovery.fact_type.host",
  "discovery.fact_type.link",
  "discovery.fact_type.name",
  "discovery.fact_type.network",
  "discovery.fact_type.os",
  "discovery.fact_type.services",
  "discovery.fact_type.vendor",
  "discovery.filter.all",
  "discovery.filter.label",
  "discovery.filter.placeholder",
  "discovery.filter.prefix",
  "discovery.filter.remove",
  "discovery.filter.remove_prefix",
  "discovery.filter.state",
  "discovery.grid.label",
  "discovery.kind.address_mismatch",
  "discovery.kind.conflict",
  "discovery.kind.discovered_host",
  "discovery.kind.orphaned_intent",
  "discovery.kind.outside_prefixes",
  "discovery.kind.prefix_vlan_mismatch",
  "discovery.kind.vlan_discovered",
  "discovery.lookup.label",
  "discovery.lookup.placeholder",
  "discovery.lookup.submit",
  "discovery.method.arp",
  "discovery.method.arp_sweep",
  "discovery.method.dhcp_snoop",
  "discovery.method.icmp",
  "discovery.method.lldp",
  "discovery.method.llmnr",
  "discovery.method.mdns",
  "discovery.method.nd",
  "discovery.method.os_fingerprint",
  "discovery.method.reverse_dns",
  "discovery.method.snmp",
  "discovery.method.tcp_connect",
  "discovery.method.tcp_syn",
  "discovery.nav.label",
  "discovery.nav.observations",
  "discovery.nav.proposals",
  "discovery.observations.all",
  "discovery.observations.current",
  "discovery.observations.empty",
  "discovery.observations.empty_body",
  "discovery.observations.expired",
  "discovery.observations.filter_label",
  "discovery.observations.filter_placeholder",
  "discovery.observations.grid_label",
  "discovery.observations.sub",
  "discovery.panel.adopted_by",
  "discovery.panel.adoption_failed",
  "discovery.panel.change",
  "discovery.panel.change_conflict",
  "discovery.panel.change_count",
  "discovery.panel.change_none",
  "discovery.panel.conflict_hint",
  "discovery.panel.decided_by",
  "discovery.panel.decision",
  "discovery.panel.evidence",
  "discovery.panel.evidence_count",
  "discovery.panel.first_seen",
  "discovery.panel.intent",
  "discovery.panel.ip",
  "discovery.panel.label",
  "discovery.panel.last_seen",
  "discovery.panel.mac",
  "discovery.panel.name",
  "discovery.panel.network",
  "discovery.panel.newer",
  "discovery.panel.no_evidence",
  "discovery.panel.nothing_hint",
  "discovery.panel.opened",
  "discovery.panel.prefix",
  "discovery.panel.reason",
  "discovery.panel.results",
  "discovery.panel.sightings",
  "discovery.panel.subject",
  "discovery.panel.superseded_by",
  "discovery.reconcile.failed",
  "discovery.reject.body",
  "discovery.reject.body_conflict",
  "discovery.reject.confirm",
  "discovery.reject.confirm_conflict",
  "discovery.reject.reason",
  "discovery.reject.reason_hint",
  "discovery.reject.reason_too_long",
  "discovery.reject.title",
  "discovery.reject.title_conflict",
  "discovery.report.adopted",
  "discovery.report.adoption_failures",
  "discovery.report.at",
  "discovery.report.expired",
  "discovery.report.moves_confirmed",
  "discovery.report.nothing",
  "discovery.report.opened",
  "discovery.report.refreshed",
  "discovery.report.sightings",
  "discovery.report.superseded",
  "discovery.report.suppressed",
  "discovery.report.title",
  "discovery.report.unchanged",
  "discovery.rule.address_mismatch",
  "discovery.rule.address_unrecorded",
  "discovery.rule.conflict_address_taken",
  "discovery.rule.conflict_networks",
  "discovery.rule.conflict_shared_address",
  "discovery.rule.discovered_address",
  "discovery.rule.discovered_mac",
  "discovery.rule.orphaned_address",
  "discovery.rule.outside_prefixes",
  "discovery.rule.prefix_vlan_differs",
  "discovery.rule.prefix_vlan_unset",
  "discovery.rule.vlan_discovered",
  "discovery.severity.critical",
  "discovery.severity.info",
  "discovery.severity.warning",
  "discovery.source.dhcp",
  "discovery.source.dns",
  "discovery.source.inventory",
  "discovery.source.network_controller",
  "discovery.source.probe",
  "discovery.source_short.dhcp_lease",
  "discovery.source_short.dns_record",
  "discovery.source_short.inventory",
  "discovery.source_short.network_controller",
  "discovery.source_short.probe",
  "discovery.state.accepted",
  "discovery.state.expired",
  "discovery.state.open",
  "discovery.state.rejected",
  "discovery.state.superseded",
  "discovery.subject.attachments",
  "discovery.subject.current",
  "discovery.subject.fact_count",
  "discovery.subject.facts",
  "discovery.subject.intent",
  "discovery.subject.ips",
  "discovery.subject.kind_ip",
  "discovery.subject.kind_mac",
  "discovery.subject.kind_name",
  "discovery.subject.macs",
  "discovery.subject.names",
  "discovery.subject.no_intent",
  "discovery.subject.no_proposals",
  "discovery.subject.not_current",
  "discovery.subject.os",
  "discovery.subject.parents",
  "discovery.subject.platforms",
  "discovery.subject.ports",
  "discovery.subject.proposals",
  "discovery.subject.sightings",
  "discovery.subject.sources",
  "discovery.subject.summary",
  "discovery.subject.tags",
  "discovery.subject.tls",
  "discovery.subject.unknown",
  "discovery.subject.vendors",
  "discovery.subject.vlan",
  "discovery.toast.approved",
  "discovery.toast.dismissed",
  "discovery.toast.rejected",
  "dns.acl.col.entries",
  "dns.acl.col.used_by",
  "dns.acl.create",
  "dns.acl.create_title",
  "dns.acl.created",
  "dns.acl.delete_body",
  "dns.acl.delete_confirm",
  "dns.acl.delete_title",
  "dns.acl.delete_used",
  "dns.acl.deleted",
  "dns.acl.edit_title",
  "dns.acl.entry_invalid",
  "dns.acl.field.entries",
  "dns.acl.field.entries_help",
  "dns.acl.field.name",
  "dns.acl.name_invalid",
  "dns.acl.save",
  "dns.acl.saved",
  "dns.acls.empty",
  "dns.acls.sub",
  "dns.acls.title",
  "dns.anchor.add",
  "dns.anchor.add_title",
  "dns.anchor.added",
  "dns.anchor.check.dnskey",
  "dns.anchor.check.ds",
  "dns.anchor.check.zone",
  "dns.anchor.col.algorithm",
  "dns.anchor.col.form",
  "dns.anchor.col.seen",
  "dns.anchor.col.source",
  "dns.anchor.col.state",
  "dns.anchor.col.tag",
  "dns.anchor.field.dnskey",
  "dns.anchor.field.dnskey_help",
  "dns.anchor.field.ds",
  "dns.anchor.field.ds_help",
  "dns.anchor.field.form",
  "dns.anchor.field.form_dnskey",
  "dns.anchor.field.form_ds",
  "dns.anchor.field.replace_root",
  "dns.anchor.field.replace_root_help",
  "dns.anchor.field.zone",
  "dns.anchor.field.zone_help",
  "dns.anchor.form.dnskey",
  "dns.anchor.form.ds",
  "dns.anchor.keys_of",
  "dns.anchor.last_query",
  "dns.anchor.lede",
  "dns.anchor.never",
  "dns.anchor.never_seen",
  "dns.anchor.next_query",
  "dns.anchor.pending",
  "dns.anchor.refresh",
  "dns.anchor.refresh_failed",
  "dns.anchor.refresh_sent",
  "dns.anchor.remove",
  "dns.anchor.remove_body",
  "dns.anchor.remove_confirm",
  "dns.anchor.remove_root_body",
  "dns.anchor.remove_title",
  "dns.anchor.removed",
  "dns.anchor.root",
  "dns.anchor.source.operator",
  "dns.anchor.source.rfc5011",
  "dns.anchor.source.shipped",
  "dns.anchor.state.add_pend",
  "dns.anchor.state.missing",
  "dns.anchor.state.removed",
  "dns.anchor.state.revoked",
  "dns.anchor.state.start",
  "dns.anchor.state.valid",
  "dns.anchor.state_since",
  "dns.batch.add_to",
  "dns.batch.applied",
  "dns.batch.apply",
  "dns.batch.back",
  "dns.batch.col.after",
  "dns.batch.col.before",
  "dns.batch.col.change",
  "dns.batch.count",
  "dns.batch.diff_summary",
  "dns.batch.diff_title",
  "dns.batch.discard",
  "dns.batch.drop",
  "dns.batch.hint",
  "dns.batch.kind.add",
  "dns.batch.kind.change",
  "dns.batch.kind.delete",
  "dns.batch.list_label",
  "dns.batch.mode",
  "dns.batch.pending_tag",
  "dns.batch.review",
  "dns.blocking.allow",
  "dns.blocking.allow.added",
  "dns.blocking.allow.already",
  "dns.blocking.allow.job",
  "dns.blocking.allow_label",
  "dns.blocking.client.withheld",
  "dns.blocking.client.withheld_hint",
  "dns.blocking.clients.empty",
  "dns.blocking.clients.note_hidden",
  "dns.blocking.clients.note_pseudonym",
  "dns.blocking.clients.table",
  "dns.blocking.clients.title",
  "dns.blocking.col.action",
  "dns.blocking.col.blocked",
  "dns.blocking.col.client",
  "dns.blocking.col.ipam",
  "dns.blocking.col.list",
  "dns.blocking.col.name",
  "dns.blocking.col.queries",
  "dns.blocking.col.share",
  "dns.blocking.col.time",
  "dns.blocking.hours.bar",
  "dns.blocking.hours.blocked",
  "dns.blocking.hours.label",
  "dns.blocking.hours.queries",
  "dns.blocking.hours.title",
  "dns.blocking.list_deleted",
  "dns.blocking.lists.empty",
  "dns.blocking.lists.manage",
  "dns.blocking.lists.table",
  "dns.blocking.lists.title",
  "dns.blocking.loading",
  "dns.blocking.log_off.body",
  "dns.blocking.log_off.link",
  "dns.blocking.log_off.title",
  "dns.blocking.next",
  "dns.blocking.pause.btn.15",
  "dns.blocking.pause.btn.5",
  "dns.blocking.pause.btn.60",
  "dns.blocking.pause.btn.open",
  "dns.blocking.pause.for",
  "dns.blocking.pause.hint",
  "dns.blocking.pause.label",
  "dns.blocking.pause.left",
  "dns.blocking.pause.on",
  "dns.blocking.pause.open",
  "dns.blocking.pause.title",
  "dns.blocking.pause.until",
  "dns.blocking.period",
  "dns.blocking.recent.empty",
  "dns.blocking.recent.table",
  "dns.blocking.recent.title",
  "dns.blocking.refresh",
  "dns.blocking.resume",
  "dns.blocking.sample",
  "dns.blocking.short_log",
  "dns.blocking.sub",
  "dns.blocking.tile.blocked",
  "dns.blocking.tile.blocked_hint",
  "dns.blocking.tile.cached",
  "dns.blocking.tile.cached_hint",
  "dns.blocking.tile.clients",
  "dns.blocking.tile.clients_hint",
  "dns.blocking.tile.queries",
  "dns.blocking.tile.queries_hint",
  "dns.blocking.title",
  "dns.blocking.top.empty",
  "dns.blocking.top_blocked.table",
  "dns.blocking.top_blocked.title",
  "dns.blocking.top_names.table",
  "dns.blocking.top_names.title",
  "dns.blocking.truncated",
  "dns.blocking.window.24h",
  "dns.blocking.window.7d",
  "dns.blocking.window.label",
  "dns.cache.capped",
  "dns.cache.col.data",
  "dns.cache.col.hits",
  "dns.cache.col.name",
  "dns.cache.col.stale",
  "dns.cache.col.state",
  "dns.cache.col.ttl",
  "dns.cache.col.type",
  "dns.cache.col.view",
  "dns.cache.data_less",
  "dns.cache.data_more",
  "dns.cache.ede",
  "dns.cache.ede_hint",
  "dns.cache.empty",
  "dns.cache.empty_suffix",
  "dns.cache.flush",
  "dns.cache.flush_body",
  "dns.cache.flush_cancel",
  "dns.cache.flush_confirm",
  "dns.cache.flush_failed",
  "dns.cache.flush_title",
  "dns.cache.flushed",
  "dns.cache.lede",
  "dns.cache.more",
  "dns.cache.next",
  "dns.cache.no_node",
  "dns.cache.not_dns_body",
  "dns.cache.not_dns_title",
  "dns.cache.open_hint",
  "dns.cache.page",
  "dns.cache.previous",
  "dns.cache.reload",
  "dns.cache.root",
  "dns.cache.rows_shown",
  "dns.cache.same_as_parent",
  "dns.cache.show",
  "dns.cache.signature",
  "dns.cache.signature_expiry",
  "dns.cache.signature_hint",
  "dns.cache.stale",
  "dns.cache.stale_hint",
  "dns.cache.sub",
  "dns.cache.suffix",
  "dns.cache.suffix_invalid",
  "dns.cache.suffix_placeholder",
  "dns.cache.title",
  "dns.cache.tree_label",
  "dns.cache.ttl_h",
  "dns.cache.ttl_min",
  "dns.cache.ttl_none",
  "dns.cache.ttl_s",
  "dns.cache.view_default",
  "dns.check.caa",
  "dns.check.empty",
  "dns.check.ipv4",
  "dns.check.ipv6",
  "dns.check.mx",
  "dns.check.name",
  "dns.check.number",
  "dns.check.outside",
  "dns.check.srv",
  "dns.check.target",
  "dns.check.ttl",
  "dns.check.txt",
  "dns.check.type",
  "dns.col.data",
  "dns.col.description",
  "dns.col.kind",
  "dns.col.name",
  "dns.col.origin",
  "dns.col.origins",
  "dns.col.rrsets",
  "dns.col.serial",
  "dns.col.ttl",
  "dns.col.type",
  "dns.col.updated",
  "dns.col.zone",
  "dns.coming.body",
  "dns.coming.title",
  "dns.coming.zones",
  "dns.dnssec.algorithm.ecdsa_p256_sha256",
  "dns.dnssec.algorithm.ed25519",
  "dns.dnssec.algorithm_label",
  "dns.dnssec.csk",
  "dns.dnssec.ds",
  "dns.dnssec.ds_copied",
  "dns.dnssec.ds_copy",
  "dns.dnssec.ds_copy_blocked",
  "dns.dnssec.ds_help",
  "dns.dnssec.ds_none",
  "dns.dnssec.expires",
  "dns.dnssec.finding.clock_skew",
  "dns.dnssec.finding.expired",
  "dns.dnssec.finding.expiring",
  "dns.dnssec.finding.other",
  "dns.dnssec.finding.resign_overdue",
  "dns.dnssec.key.activated",
  "dns.dnssec.key.published",
  "dns.dnssec.key.retired",
  "dns.dnssec.key.role",
  "dns.dnssec.key.state",
  "dns.dnssec.key.tag",
  "dns.dnssec.keys",
  "dns.dnssec.keys_none",
  "dns.dnssec.last_signed",
  "dns.dnssec.mode.imported",
  "dns.dnssec.mode.off",
  "dns.dnssec.mode.online",
  "dns.dnssec.mode_help.imported",
  "dns.dnssec.mode_help.off",
  "dns.dnssec.mode_help.online",
  "dns.dnssec.mode_label",
  "dns.dnssec.next_resign",
  "dns.dnssec.nsec3",
  "dns.dnssec.parent_ds",
  "dns.dnssec.parent_ds_undo",
  "dns.dnssec.policy",
  "dns.dnssec.role.csk",
  "dns.dnssec.role.ksk",
  "dns.dnssec.role.zsk",
  "dns.dnssec.roll.csk",
  "dns.dnssec.roll.ksk",
  "dns.dnssec.roll.zsk",
  "dns.dnssec.rollover",
  "dns.dnssec.rollover_failed",
  "dns.dnssec.rollover_help",
  "dns.dnssec.rollover_open_job",
  "dns.dnssec.rollover_running",
  "dns.dnssec.rollover_started",
  "dns.dnssec.save",
  "dns.dnssec.saved",
  "dns.dnssec.signed_serial",
  "dns.dnssec.state.active",
  "dns.dnssec.state.generated",
  "dns.dnssec.state.published",
  "dns.dnssec.state.removed",
  "dns.dnssec.state.retired",
  "dns.dnssec.status",
  "dns.do.add_records",
  "dns.do.delete",
  "dns.do.delete_rrset",
  "dns.do.edit",
  "dns.do.export",
  "dns.do.import",
  "dns.do.open",
  "dns.do.remove_record",
  "dns.do.take_over",
  "dns.export.failed",
  "dns.fwd.all_views",
  "dns.fwd.check.address",
  "dns.fwd.check.duplicate",
  "dns.fwd.check.none",
  "dns.fwd.check.path",
  "dns.fwd.check.path_transport",
  "dns.fwd.check.port",
  "dns.fwd.check.suffix",
  "dns.fwd.check.taken",
  "dns.fwd.check.tls_name",
  "dns.fwd.check.tls_required",
  "dns.fwd.check.too_many",
  "dns.fwd.check.view",
  "dns.fwd.col.suffix",
  "dns.fwd.col.tls_name",
  "dns.fwd.col.transport",
  "dns.fwd.col.upstreams",
  "dns.fwd.col.view",
  "dns.fwd.create",
  "dns.fwd.create_title",
  "dns.fwd.created",
  "dns.fwd.default",
  "dns.fwd.delete_body",
  "dns.fwd.delete_confirm",
  "dns.fwd.delete_root",
  "dns.fwd.delete_title",
  "dns.fwd.deleted",
  "dns.fwd.edit_title",
  "dns.fwd.empty",
  "dns.fwd.empty_body",
  "dns.fwd.field.all_views",
  "dns.fwd.field.all_views_help",
  "dns.fwd.field.mode",
  "dns.fwd.field.suffix",
  "dns.fwd.field.suffix_help",
  "dns.fwd.field.suffix_placeholder",
  "dns.fwd.field.tls_name",
  "dns.fwd.field.tls_name_help",
  "dns.fwd.field.transport",
  "dns.fwd.field.upstreams",
  "dns.fwd.field.upstreams_help_doh",
  "dns.fwd.field.upstreams_help_dot",
  "dns.fwd.field.upstreams_help_plain",
  "dns.fwd.field.validate",
  "dns.fwd.field.validate_help",
  "dns.fwd.field.validate_off",
  "dns.fwd.known",
  "dns.fwd.mode.forward",
  "dns.fwd.mode.recurse",
  "dns.fwd.mode.recurse_help",
  "dns.fwd.mode.recurse_long",
  "dns.fwd.mode.recurse_upstreams",
  "dns.fwd.no_default_body",
  "dns.fwd.no_default_link",
  "dns.fwd.no_default_title",
  "dns.fwd.preset.dot",
  "dns.fwd.preset.dot_title",
  "dns.fwd.preset.privacy",
  "dns.fwd.problems_title",
  "dns.fwd.recursion.hardened",
  "dns.fwd.recursion.known",
  "dns.fwd.recursion.lab",
  "dns.fwd.recursion.title",
  "dns.fwd.recursion.views",
  "dns.fwd.recursion.views_link",
  "dns.fwd.resolution.choice.default",
  "dns.fwd.resolution.col.resolution",
  "dns.fwd.resolution.col.view",
  "dns.fwd.resolution.default_view",
  "dns.fwd.resolution.failed",
  "dns.fwd.resolution.lede",
  "dns.fwd.resolution.mode.forward",
  "dns.fwd.resolution.mode.recurse",
  "dns.fwd.resolution.mode.refuse",
  "dns.fwd.resolution.of",
  "dns.fwd.resolution.root_rule",
  "dns.fwd.resolution.saved",
  "dns.fwd.resolution.title",
  "dns.fwd.save",
  "dns.fwd.saved",
  "dns.fwd.sub",
  "dns.fwd.title",
  "dns.fwd.transport.doh",
  "dns.fwd.transport.dot",
  "dns.fwd.transport.plain",
  "dns.fwd.unvalidated",
  "dns.fwd.use_dot",
  "dns.history.action",
  "dns.history.changes",
  "dns.history.empty",
  "dns.history.no_audit",
  "dns.history.outcome.denied",
  "dns.history.outcome.failed",
  "dns.history.outcome.success",
  "dns.history.result",
  "dns.history.revision",
  "dns.history.serial",
  "dns.history.serial_title",
  "dns.history.updated",
  "dns.history.when",
  "dns.import.apply.again",
  "dns.import.apply.done",
  "dns.import.apply.failed",
  "dns.import.apply.open_job",
  "dns.import.apply.open_zone",
  "dns.import.apply.progress",
  "dns.import.apply.rolled_back",
  "dns.import.apply.running",
  "dns.import.apply.serial",
  "dns.import.fact.added",
  "dns.import.fact.removed",
  "dns.import.fact.replaced",
  "dns.import.losses.line",
  "dns.import.losses.none",
  "dns.import.losses.title",
  "dns.import.losses.what",
  "dns.import.parse_error",
  "dns.import.preview.apply",
  "dns.import.preview.back",
  "dns.import.preview.title",
  "dns.import.step.apply",
  "dns.import.step.done",
  "dns.import.step.preview",
  "dns.import.step.upload",
  "dns.import.steps",
  "dns.import.title",
  "dns.import.types.caption",
  "dns.import.types.records",
  "dns.import.upload.body",
  "dns.import.upload.choose",
  "dns.import.upload.drop",
  "dns.import.upload.lines",
  "dns.import.upload.paste",
  "dns.import.upload.preview",
  "dns.import.upload.replace",
  "dns.import.upload.replace_help",
  "dns.import.upload.title",
  "dns.import.upload.too_large",
  "dns.infra.capability.down",
  "dns.infra.capability.edns",
  "dns.infra.capability.lame",
  "dns.infra.capability.lower_case",
  "dns.infra.capability.no_edns",
  "dns.infra.capability.tcp_only",
  "dns.infra.col.address",
  "dns.infra.col.capabilities",
  "dns.infra.col.failures",
  "dns.infra.col.origin",
  "dns.infra.col.p99",
  "dns.infra.col.server",
  "dns.infra.col.srtt",
  "dns.infra.ds.bogus",
  "dns.infra.ds.insecure",
  "dns.infra.ds.secure",
  "dns.infra.ds.unknown",
  "dns.infra.empty",
  "dns.infra.empty_suffix",
  "dns.infra.flush_all",
  "dns.infra.flush_body_all",
  "dns.infra.flush_body_suffix",
  "dns.infra.flush_confirm",
  "dns.infra.flush_failed",
  "dns.infra.flush_suffix",
  "dns.infra.flush_title_all",
  "dns.infra.flush_title_suffix",
  "dns.infra.flushed_all",
  "dns.infra.flushed_suffix",
  "dns.infra.lede",
  "dns.infra.ms",
  "dns.infra.no_addresses",
  "dns.infra.off",
  "dns.infra.origin.authoritative",
  "dns.infra.origin.glue",
  "dns.infra.origin.hints",
  "dns.infra.origin.sibling_glue",
  "dns.infra.servers_of",
  "dns.infra.show",
  "dns.infra.srtt_none",
  "dns.infra.suffix",
  "dns.infra.title",
  "dns.job.dnssec_rollover",
  "dns.key.col.algorithm",
  "dns.key.col.created",
  "dns.key.col.name",
  "dns.key.copied",
  "dns.key.copy_blocked",
  "dns.key.create_action",
  "dns.key.create_title",
  "dns.key.created_body",
  "dns.key.created_title",
  "dns.key.delete_body",
  "dns.key.delete_confirm",
  "dns.key.delete_title",
  "dns.key.deleted",
  "dns.key.generate",
  "dns.key.import",
  "dns.key.mode",
  "dns.key.mode_generate",
  "dns.key.mode_import",
  "dns.key.name_help",
  "dns.key.secret",
  "dns.key.secret_help",
  "dns.key.secret_invalid",
  "dns.key.stored",
  "dns.keys.empty",
  "dns.keys.sub",
  "dns.keys.title",
  "dns.kind.forward",
  "dns.kind.primary",
  "dns.kind.rpz",
  "dns.kind.secondary",
  "dns.kind.stub",
  "dns.list.action.nodata",
  "dns.list.action.nxdomain",
  "dns.list.action.redirect",
  "dns.list.check.file",
  "dns.list.check.interval",
  "dns.list.check.name",
  "dns.list.check.redirect",
  "dns.list.check.url",
  "dns.list.col.action",
  "dns.list.col.entries",
  "dns.list.col.etag",
  "dns.list.col.fetched",
  "dns.list.col.format",
  "dns.list.col.interval",
  "dns.list.col.last_error",
  "dns.list.col.source",
  "dns.list.create",
  "dns.list.create_title",
  "dns.list.created",
  "dns.list.delete_body",
  "dns.list.delete_confirm",
  "dns.list.delete_title",
  "dns.list.deleted",
  "dns.list.disabled",
  "dns.list.edit_title",
  "dns.list.every",
  "dns.list.fetch",
  "dns.list.fetch_failed",
  "dns.list.fetch_started",
  "dns.list.field.action",
  "dns.list.field.enabled",
  "dns.list.field.file",
  "dns.list.field.file_help",
  "dns.list.field.format",
  "dns.list.field.interval",
  "dns.list.field.interval_help",
  "dns.list.field.name",
  "dns.list.field.redirect",
  "dns.list.field.redirect_help",
  "dns.list.field.source",
  "dns.list.field.url",
  "dns.list.field.url_help",
  "dns.list.file_chosen",
  "dns.list.format.domains",
  "dns.list.format.domains_help",
  "dns.list.format.hosts",
  "dns.list.format.hosts_help",
  "dns.list.job",
  "dns.list.no_version",
  "dns.list.open_job",
  "dns.list.save",
  "dns.list.saved",
  "dns.list.source.upload",
  "dns.list.source.url",
  "dns.list.upload",
  "dns.list.upload_hint",
  "dns.list.upload_title",
  "dns.list.uploaded",
  "dns.lists.empty",
  "dns.lists.empty_body",
  "dns.lists.sub",
  "dns.lists.title",
  "dns.log.blocked",
  "dns.log.cached",
  "dns.log.client_mode.address",
  "dns.log.client_mode.hidden",
  "dns.log.client_mode.pseudonym",
  "dns.log.client_none",
  "dns.log.col.client",
  "dns.log.col.ede",
  "dns.log.col.flags",
  "dns.log.col.latency",
  "dns.log.col.name",
  "dns.log.col.rcode",
  "dns.log.col.resolution",
  "dns.log.col.subqueries",
  "dns.log.col.time",
  "dns.log.col.transport",
  "dns.log.col.type",
  "dns.log.col.validation",
  "dns.log.ede",
  "dns.log.empty",
  "dns.log.empty_filtered",
  "dns.log.empty_validation",
  "dns.log.figures",
  "dns.log.filter.apply",
  "dns.log.filter.client",
  "dns.log.filter.client_invalid",
  "dns.log.filter.client_placeholder",
  "dns.log.filter.from",
  "dns.log.filter.qname",
  "dns.log.filter.qname_invalid",
  "dns.log.filter.qname_placeholder",
  "dns.log.filter.rcode",
  "dns.log.filter.rcode_any",
  "dns.log.filter.reset",
  "dns.log.filter.until",
  "dns.log.filter.until_invalid",
  "dns.log.filter.validation",
  "dns.log.filter.validation_any",
  "dns.log.filter.validation_help",
  "dns.log.latency",
  "dns.log.newer",
  "dns.log.no_node",
  "dns.log.node",
  "dns.log.node_label",
  "dns.log.not_dns_body",
  "dns.log.not_dns_title",
  "dns.log.off_body",
  "dns.log.off_link",
  "dns.log.off_title",
  "dns.log.older",
  "dns.log.page",
  "dns.log.partial",
  "dns.log.pseudonym_hint",
  "dns.log.refresh",
  "dns.log.resolution.cache",
  "dns.log.resolution.denial",
  "dns.log.resolution.forward",
  "dns.log.resolution.local",
  "dns.log.resolution.policy",
  "dns.log.resolution.recurse",
  "dns.log.resolution.refused",
  "dns.log.resolution.stale",
  "dns.log.resolution.zone",
  "dns.log.start",
  "dns.log.started_toast",
  "dns.log.stop",
  "dns.log.stopped_body",
  "dns.log.stopped_title",
  "dns.log.stopped_toast",
  "dns.log.sub",
  "dns.log.switch_failed",
  "dns.log.table",
  "dns.log.title",
  "dns.log.transport.doh",
  "dns.log.transport.dot",
  "dns.log.transport.tcp",
  "dns.log.transport.udp",
  "dns.log.validation.bogus",
  "dns.log.validation.indeterminate",
  "dns.log.validation.insecure",
  "dns.log.validation.secure",
  "dns.log.validation.unvalidated",
  "dns.loss.directive",
  "dns.loss.origin",
  "dns.loss.outside",
  "dns.loss.soa",
  "dns.loss.unsupported_type",
  "dns.nav.acls",
  "dns.nav.blocking",
  "dns.nav.cache",
  "dns.nav.forwarders",
  "dns.nav.keys",
  "dns.nav.label",
  "dns.nav.lists",
  "dns.nav.log",
  "dns.nav.recursion",
  "dns.nav.views",
  "dns.nav.zones",
  "dns.node.col.address",
  "dns.node.col.key",
  "dns.node.col.transport",
  "dns.node.col.workers",
  "dns.node.doc",
  "dns.node.forwarders_hint",
  "dns.node.forwarders_link",
  "dns.node.group.cache",
  "dns.node.group.listeners",
  "dns.node.group.log",
  "dns.node.group.role",
  "dns.node.group.tcp",
  "dns.node.lede",
  "dns.node.log_off",
  "dns.node.no",
  "dns.node.no_node",
  "dns.node.no_role_body",
  "dns.node.no_role_title",
  "dns.node.not_served",
  "dns.node.off_body",
  "dns.node.problems",
  "dns.node.refresh",
  "dns.node.row.cache_bytes",
  "dns.node.row.cache_entries",
  "dns.node.row.cache_hit_ratio",
  "dns.node.row.cache_hits",
  "dns.node.row.cache_misses",
  "dns.node.row.cache_stale",
  "dns.node.row.lag",
  "dns.node.row.log_client",
  "dns.node.row.log_days",
  "dns.node.row.log_dropped",
  "dns.node.row.log_format",
  "dns.node.row.log_sample",
  "dns.node.row.log_size_mb",
  "dns.node.row.log_state",
  "dns.node.row.log_write_errors",
  "dns.node.row.log_written",
  "dns.node.row.rrsets",
  "dns.node.row.serving",
  "dns.node.row.socket_mode",
  "dns.node.row.started",
  "dns.node.row.tcp_open",
  "dns.node.row.tcp_refused",
  "dns.node.row.workers",
  "dns.node.row.zones",
  "dns.node.served",
  "dns.node.title",
  "dns.node.tls",
  "dns.node.unknown",
  "dns.node.yes",
  "dns.nta.add",
  "dns.nta.add_lede",
  "dns.nta.add_title",
  "dns.nta.check.lifetime",
  "dns.nta.check.reason",
  "dns.nta.check.reason_long",
  "dns.nta.check.root",
  "dns.nta.check.zone",
  "dns.nta.col.actions",
  "dns.nta.col.created",
  "dns.nta.col.expires",
  "dns.nta.col.reason",
  "dns.nta.col.zone",
  "dns.nta.created",
  "dns.nta.delete",
  "dns.nta.delete_body",
  "dns.nta.delete_confirm",
  "dns.nta.delete_title",
  "dns.nta.deleted",
  "dns.nta.expired",
  "dns.nta.field.lifetime",
  "dns.nta.field.lifetime_help",
  "dns.nta.field.reason",
  "dns.nta.field.reason_help",
  "dns.nta.field.zone",
  "dns.nta.lede",
  "dns.nta.none",
  "dns.op.add",
  "dns.op.delete",
  "dns.op.remove",
  "dns.op.set",
  "dns.origin.ad",
  "dns.origin.dhcp",
  "dns.origin.dnssec",
  "dns.origin.dynamic",
  "dns.origin.ipam",
  "dns.origin.manual",
  "dns.origin.transfer",
  "dns.record.line_error",
  "dns.records.any_origin",
  "dns.records.any_type",
  "dns.records.empty",
  "dns.records.filter_label",
  "dns.records.filter_placeholder",
  "dns.records.label",
  "dns.records.origin_filter",
  "dns.records.type_filter",
  "dns.recursion.counter.answered",
  "dns.recursion.counter.budget",
  "dns.recursion.counter.failure_cache_hits",
  "dns.recursion.counter.local",
  "dns.recursion.counter.servfail",
  "dns.recursion.counter.subqueries",
  "dns.recursion.counter.timeout",
  "dns.recursion.counter.unwanted",
  "dns.recursion.counters.title",
  "dns.recursion.facts.title",
  "dns.recursion.hints.date",
  "dns.recursion.hints.shipped",
  "dns.recursion.infra.names",
  "dns.recursion.infra.of",
  "dns.recursion.infra.servers",
  "dns.recursion.infra.title",
  "dns.recursion.infra.zones",
  "dns.recursion.ms",
  "dns.recursion.ntas.title",
  "dns.recursion.prime.button",
  "dns.recursion.prime.failed",
  "dns.recursion.prime.sent",
  "dns.recursion.priming.duration",
  "dns.recursion.priming.expires",
  "dns.recursion.priming.failed",
  "dns.recursion.priming.last",
  "dns.recursion.priming.never",
  "dns.recursion.priming.ok",
  "dns.recursion.problem.priming_failed",
  "dns.recursion.problems.title",
  "dns.recursion.root_hints",
  "dns.recursion.roots.col.address",
  "dns.recursion.roots.col.name",
  "dns.recursion.roots.col.srtt",
  "dns.recursion.roots.srtt_none",
  "dns.recursion.roots.title",
  "dns.recursion.status.loading",
  "dns.recursion.status.no_node",
  "dns.recursion.status.off.body",
  "dns.recursion.status.off.title",
  "dns.recursion.status.running",
  "dns.recursion.status.title",
  "dns.recursion.sub",
  "dns.recursion.title",
  "dns.recursion.trust_anchors.none",
  "dns.recursion.trust_anchors.title",
  "dns.recursion.validation.keys",
  "dns.recursion.validation.no_keys",
  "dns.recursion.validation.title",
  "dns.resolution.default",
  "dns.resolution.forward",
  "dns.resolution.recurse",
  "dns.resolution.refuse",
  "dns.rrset.add_action",
  "dns.rrset.add_records_title",
  "dns.rrset.add_submit",
  "dns.rrset.add_title",
  "dns.rrset.delete_body",
  "dns.rrset.delete_confirm",
  "dns.rrset.delete_title",
  "dns.rrset.edit_data",
  "dns.rrset.edit_hint",
  "dns.rrset.edit_ttl",
  "dns.rrset.failed",
  "dns.rrset.field.data",
  "dns.rrset.field.data_help",
  "dns.rrset.field.name",
  "dns.rrset.field.name_help",
  "dns.rrset.field.ttl",
  "dns.rrset.field.type",
  "dns.rrset.saved",
  "dns.sec.bogus",
  "dns.sec.indeterminate",
  "dns.sec.insecure",
  "dns.sec.secure",
  "dns.sec.unvalidated",
  "dns.serial.counter",
  "dns.serial.counter_help",
  "dns.serial.date_counter",
  "dns.serial.date_counter_help",
  "dns.serial.unixtime",
  "dns.serial.unixtime_help",
  "dns.settings.expire",
  "dns.settings.minimum",
  "dns.settings.ns",
  "dns.settings.ns_required",
  "dns.settings.refresh",
  "dns.settings.retry",
  "dns.settings.rname_help",
  "dns.settings.save",
  "dns.settings.saved",
  "dns.settings.serial",
  "dns.settings.soa",
  "dns.settings.soa_body",
  "dns.settings.source_invalid",
  "dns.settings.source_primaries",
  "dns.settings.source_primaries_body",
  "dns.settings.source_stub",
  "dns.settings.source_stub_body",
  "dns.settings.ttl",
  "dns.state.not_built_body",
  "dns.state.not_built_title",
  "dns.state.off_body",
  "dns.state.off_link",
  "dns.state.off_title",
  "dns.takeover.body",
  "dns.takeover.confirm",
  "dns.takeover.tag",
  "dns.takeover.title",
  "dns.title",
  "dns.transfer.address",
  "dns.transfer.allow",
  "dns.transfer.allow_add",
  "dns.transfer.allow_help",
  "dns.transfer.allow_none",
  "dns.transfer.allow_remove",
  "dns.transfer.body",
  "dns.transfer.catalog",
  "dns.transfer.catalog_help_other",
  "dns.transfer.catalog_help_primary",
  "dns.transfer.catalog_help_secondary",
  "dns.transfer.check.address",
  "dns.transfer.check.key",
  "dns.transfer.check.port",
  "dns.transfer.check.tls_name",
  "dns.transfer.error.failed",
  "dns.transfer.error.refused",
  "dns.transfer.error.tsig",
  "dns.transfer.expires",
  "dns.transfer.from_primary",
  "dns.transfer.key",
  "dns.transfer.last_error",
  "dns.transfer.last_success",
  "dns.transfer.next_refresh",
  "dns.transfer.not_queued",
  "dns.transfer.notify",
  "dns.transfer.notify_add",
  "dns.transfer.notify_none",
  "dns.transfer.notify_remove",
  "dns.transfer.now",
  "dns.transfer.port",
  "dns.transfer.primary",
  "dns.transfer.primary_add",
  "dns.transfer.primary_remove",
  "dns.transfer.queued",
  "dns.transfer.records_readonly",
  "dns.transfer.require_tsig",
  "dns.transfer.require_tsig_help",
  "dns.transfer.serial",
  "dns.transfer.state",
  "dns.transfer.state_idle",
  "dns.transfer.state_running",
  "dns.transfer.status",
  "dns.transfer.title",
  "dns.transfer.tls_name",
  "dns.transfer.unavailable",
  "dns.transfer.xot",
  "dns.transfer.xot_help",
  "dns.transfer.xot_short",
  "dns.update.allow",
  "dns.update.allow_add",
  "dns.update.allow_help",
  "dns.update.allow_none",
  "dns.update.allow_remove",
  "dns.update.body",
  "dns.update.default_hardened",
  "dns.update.default_home",
  "dns.update.default_lab",
  "dns.update.default_standard",
  "dns.update.may_replace_ipam",
  "dns.update.may_replace_ipam_help",
  "dns.update.require_tsig",
  "dns.update.require_tsig_hardened",
  "dns.update.require_tsig_help",
  "dns.update.require_tsig_lab",
  "dns.update.title",
  "dns.upstream.chosen",
  "dns.upstream.chosen_long",
  "dns.upstream.col.answered",
  "dns.upstream.col.error",
  "dns.upstream.col.ewma",
  "dns.upstream.col.failed",
  "dns.upstream.col.last",
  "dns.upstream.col.p50",
  "dns.upstream.col.p99",
  "dns.upstream.col.rule",
  "dns.upstream.col.state",
  "dns.upstream.col.upstream",
  "dns.upstream.counts",
  "dns.upstream.last_error",
  "dns.upstream.ms",
  "dns.upstream.rule.default",
  "dns.upstream.rule.stub",
  "dns.upstream.section.doc",
  "dns.upstream.section.empty",
  "dns.upstream.section.link",
  "dns.upstream.section.title",
  "dns.upstream.state.degraded",
  "dns.upstream.state.down",
  "dns.upstream.state.unknown",
  "dns.upstream.state.up",
  "dns.upstream.times",
  "dns.view.action.down",
  "dns.view.action.up",
  "dns.view.check.address",
  "dns.view.check.description",
  "dns.view.check.name",
  "dns.view.check.name_long",
  "dns.view.check.name_required",
  "dns.view.check.no_acl",
  "dns.view.check.no_scope",
  "dns.view.check.no_zone",
  "dns.view.check.prefix",
  "dns.view.check.rule_empty",
  "dns.view.check.rule_too_many",
  "dns.view.check.scope_twice",
  "dns.view.check.scope_weight",
  "dns.view.check.scope_zone",
  "dns.view.check.taken",
  "dns.view.check.time",
  "dns.view.check.too_many_rules",
  "dns.view.check.too_many_scopes",
  "dns.view.check.type",
  "dns.view.col.name",
  "dns.view.col.order",
  "dns.view.col.recursion",
  "dns.view.col.rules",
  "dns.view.col.scopes",
  "dns.view.create",
  "dns.view.create_title",
  "dns.view.created",
  "dns.view.default.body",
  "dns.view.default.title",
  "dns.view.default_scopes",
  "dns.view.delete_body",
  "dns.view.delete_confirm",
  "dns.view.delete_title",
  "dns.view.deleted",
  "dns.view.drag",
  "dns.view.edit_title",
  "dns.view.empty",
  "dns.view.empty_body",
  "dns.view.every_query",
  "dns.view.field.name",
  "dns.view.field.order",
  "dns.view.field.order_at",
  "dns.view.field.order_help",
  "dns.view.field.order_last",
  "dns.view.field.recursion",
  "dns.view.field.recursion_help",
  "dns.view.field.rules",
  "dns.view.field.rules_help",
  "dns.view.field.rules_none",
  "dns.view.field.scope",
  "dns.view.field.scopes",
  "dns.view.field.scopes_help",
  "dns.view.field.weight",
  "dns.view.field.zone",
  "dns.view.in_use",
  "dns.view.move_down",
  "dns.view.move_up",
  "dns.view.moved",
  "dns.view.recursion.default",
  "dns.view.recursion.missing",
  "dns.view.rule.add",
  "dns.view.rule.from",
  "dns.view.rule.help.client_subnet",
  "dns.view.rule.help.interface",
  "dns.view.rule.help.qname",
  "dns.view.rule.help.qtype",
  "dns.view.rule.help.time_of_day",
  "dns.view.rule.help.transport",
  "dns.view.rule.kind.client_subnet",
  "dns.view.rule.kind.interface",
  "dns.view.rule.kind.qname",
  "dns.view.rule.kind.qtype",
  "dns.view.rule.kind.time_of_day",
  "dns.view.rule.kind.transport",
  "dns.view.rule.kind_label",
  "dns.view.rule.remove",
  "dns.view.rule.to",
  "dns.view.rule.words.client_subnet",
  "dns.view.rule.words.interface",
  "dns.view.rule.words.qname",
  "dns.view.rule.words.qtype",
  "dns.view.rule.words.time_of_day",
  "dns.view.rule.words.transport",
  "dns.view.save",
  "dns.view.saved",
  "dns.view.scope.add",
  "dns.view.scope.no_zones",
  "dns.view.scope.remove",
  "dns.view.scope_chip",
  "dns.view.share",
  "dns.view.sub",
  "dns.view.title",
  "dns.view.transport.doh",
  "dns.view.transport.dot",
  "dns.view.transport.tcp",
  "dns.view.transport.udp",
  "dns.zone.create.action",
  "dns.zone.create.done",
  "dns.zone.create.primaries_required",
  "dns.zone.create.reverse_notice",
  "dns.zone.create.submit",
  "dns.zone.create.title",
  "dns.zone.delete.body",
  "dns.zone.delete.confirm",
  "dns.zone.delete.done",
  "dns.zone.delete.title",
  "dns.zone.field.description",
  "dns.zone.field.kind",
  "dns.zone.field.mname",
  "dns.zone.field.name",
  "dns.zone.field.name_help",
  "dns.zone.field.name_servers",
  "dns.zone.field.name_servers_help",
  "dns.zone.field.primaries",
  "dns.zone.field.primaries_help",
  "dns.zone.field.rname",
  "dns.zone.field.serial",
  "dns.zone.field.ttl",
  "dns.zone.not_served",
  "dns.zone.not_served_hint",
  "dns.zone.reverse",
  "dns.zone.serial",
  "dns.zone.stub",
  "dns.zone.stub_hint",
  "dns.zone.tab.dnssec",
  "dns.zone.tab.history",
  "dns.zone.tab.records",
  "dns.zone.tab.settings",
  "dns.zone.tabs",
  "dns.zones.empty",
  "dns.zones.empty_body",
  "dns.zones.filter_label",
  "dns.zones.filter_placeholder",
  "dns.zones.sub",
  "dns.zones.title",
  "errors.audit.export.client_key",
  "errors.audit.export.conflict",
  "errors.audit.export.duplicate",
  "errors.audit.export.file",
  "errors.audit.export.host",
  "errors.audit.export.invalid",
  "errors.audit.export.name",
  "errors.audit.export.not_found",
  "errors.audit.export.pem",
  "errors.audit.export.port",
  "errors.audit.export.range",
  "errors.audit.export.required",
  "errors.audit.export.test_target",
  "errors.audit.export.tls_unused",
  "errors.audit.export.too_many",
  "errors.audit.export.unknown_sink",
  "errors.auth.break_glass.hardware_key_only",
  "errors.auth.challenge_invalid",
  "errors.auth.conflict",
  "errors.auth.forbidden",
  "errors.auth.invalid_credentials",
  "errors.auth.password.breached",
  "errors.auth.password.context_specific",
  "errors.auth.password.incorrect",
  "errors.auth.password.invalid_characters",
  "errors.auth.password.pattern_mismatch",
  "errors.auth.password.pin_digits_only",
  "errors.auth.password.policy",
  "errors.auth.password.too_long",
  "errors.auth.password.too_short",
  "errors.auth.password.trivial",
  "errors.auth.session_expired",
  "errors.auth.setup.closed",
  "errors.auth.setup.invalid_host_name",
  "errors.auth.setup.token_invalid",
  "errors.auth.step_up_required",
  "errors.auth.throttled",
  "errors.auth.token.lifetime_exceeded",
  "errors.auth.totp.already_enrolled",
  "errors.auth.totp.code_mismatch",
  "errors.auth.totp.not_enrolled",
  "errors.auth.unauthenticated",
  "errors.auth.webauthn.attestation_required",
  "errors.auth.webauthn.backup_eligible_refused",
  "errors.auth.webauthn.credential_exists",
  "errors.auth.webauthn.origin_mismatch",
  "errors.auth.webauthn.rp_id_mismatch",
  "errors.auth.webauthn.user_verification",
  "errors.client.aborted",
  "errors.client.bad_response",
  "errors.client.network",
  "errors.cluster.enrolment.lifetime",
  "errors.cluster.enrolment.not_found",
  "errors.cluster.enrolment.random",
  "errors.cluster.enrolment.roles",
  "errors.cluster.member.changing",
  "errors.cluster.member.even_voters",
  "errors.cluster.member.last_voter",
  "errors.cluster.member.no_successor",
  "errors.cluster.member.not_caught_up",
  "errors.cluster.member.not_found",
  "errors.cluster.member.not_learner",
  "errors.cluster.no_quorum",
  "errors.cluster.node.conflict",
  "errors.cluster.node.name",
  "errors.cluster.node.name_taken",
  "errors.cluster.node.not_found",
  "errors.cluster.single",
  "errors.connect.guardrail.management_client",
  "errors.connect.guardrail.management_port",
  "errors.connect.guardrail.protected_client",
  "errors.connect.guardrail.protected_network",
  "errors.connect.guardrail.protected_port",
  "errors.connect.guardrail.protected_vlan",
  "errors.connect.guardrail.uplink",
  "errors.connect.instance.call_timeout",
  "errors.connect.instance.conflict",
  "errors.connect.instance.disabled",
  "errors.connect.instance.name",
  "errors.connect.instance.name_taken",
  "errors.connect.instance.not_found",
  "errors.connect.instance.nothing_to_run",
  "errors.connect.instance.poll_interval",
  "errors.connect.plugin.exited",
  "errors.connect.plugin.unavailable",
  "errors.connect.plugin.unknown",
  "errors.connect.plugin.unusable",
  "errors.connect.run.failed",
  "errors.connect.secret.missing",
  "errors.connect.secret.not_found",
  "errors.connect.secret.not_operator",
  "errors.connect.secret.undeclared",
  "errors.connect.settings.invalid",
  "errors.connect.timeout",
  "errors.connect.unreachable",
  "errors.connect.verify_mismatch",
  "errors.connect.writes_disabled",
  "errors.dhcp.class.in_use",
  "errors.dhcp.class.invalid",
  "errors.dhcp.class.not_found",
  "errors.dhcp.ddns.invalid",
  "errors.dhcp.exclusion.invalid",
  "errors.dhcp.exclusion.not_found",
  "errors.dhcp.export.format",
  "errors.dhcp.filter.exists",
  "errors.dhcp.filter.invalid",
  "errors.dhcp.filter.not_found",
  "errors.dhcp.lease.not_found",
  "errors.dhcp.lease.state",
  "errors.dhcp.lease_times.invalid",
  "errors.dhcp.module.disabled",
  "errors.dhcp.node.not_dhcp",
  "errors.dhcp.option.code_reserved",
  "errors.dhcp.option.invalid",
  "errors.dhcp.option.unknown",
  "errors.dhcp.option_def.exists",
  "errors.dhcp.option_def.in_use",
  "errors.dhcp.option_def.not_found",
  "errors.dhcp.policy.invalid",
  "errors.dhcp.policy.not_found",
  "errors.dhcp.pool.not_found",
  "errors.dhcp.pool.not_pool",
  "errors.dhcp.pool.outside",
  "errors.dhcp.reservation.conflict",
  "errors.dhcp.reservation.no_identity",
  "errors.dhcp.scope.attached",
  "errors.dhcp.scope.exists",
  "errors.dhcp.scope.invalid",
  "errors.dhcp.scope.not_found",
  "errors.dhcp.scope.not_network",
  "errors.dhcp.settings.invalid",
  "errors.dhcp.shared_network.in_use",
  "errors.dhcp.shared_network.invalid",
  "errors.dhcp.shared_network.not_found",
  "errors.dhcp.store_refused",
  "errors.dns.acl.in_use",
  "errors.dns.acl.not_found",
  "errors.dns.blocking.log_off",
  "errors.dns.default_zone.invalid",
  "errors.dns.forwarder.invalid",
  "errors.dns.forwarder.not_found",
  "errors.dns.key.exists",
  "errors.dns.key.not_found",
  "errors.dns.list.invalid",
  "errors.dns.list.not_found",
  "errors.dns.module.disabled",
  "errors.dns.node.not_dns",
  "errors.dns.nta.invalid",
  "errors.dns.nta.not_found",
  "errors.dns.record.conflict",
  "errors.dns.record.invalid",
  "errors.dns.record.origin",
  "errors.dns.recursion.disabled",
  "errors.dns.transfer.refused",
  "errors.dns.trust_anchor.invalid",
  "errors.dns.trust_anchor.not_found",
  "errors.dns.trust_anchor.root_protected",
  "errors.dns.update.refused",
  "errors.dns.view.in_use",
  "errors.dns.view.invalid",
  "errors.dns.view.not_found",
  "errors.dns.zone.exists",
  "errors.dns.zone.invalid",
  "errors.dns.zone.not_found",
  "errors.dns.zone.secondary",
  "errors.dns.zonefile.invalid",
  "errors.generic.client",
  "errors.generic.field",
  "errors.generic.not_implemented",
  "errors.generic.server",
  "errors.generic.unexpected",
  "errors.i18n.pack.argument",
  "errors.i18n.pack.bidi",
  "errors.i18n.pack.control",
  "errors.i18n.pack.default_language",
  "errors.i18n.pack.duplicate",
  "errors.i18n.pack.empty",
  "errors.i18n.pack.icu",
  "errors.i18n.pack.invalid",
  "errors.i18n.pack.key",
  "errors.i18n.pack.markup",
  "errors.i18n.pack.metadata",
  "errors.i18n.pack.no_candidate",
  "errors.i18n.pack.not_found",
  "errors.i18n.pack.not_previewed",
  "errors.i18n.pack.root",
  "errors.i18n.pack.src_lang",
  "errors.i18n.pack.structure",
  "errors.i18n.pack.tag",
  "errors.i18n.pack.too_large",
  "errors.i18n.pack.too_many_units",
  "errors.i18n.pack.trg_lang",
  "errors.i18n.pack.version",
  "errors.i18n.pack.xml",
  "errors.i18n.unavailable",
  "errors.i18n.upload.empty",
  "errors.i18n.upload.malformed",
  "errors.import.apply.failed",
  "errors.import.conflict.kept",
  "errors.import.credentials.vault_required",
  "errors.import.expired",
  "errors.import.mapping.invalid",
  "errors.import.not_found",
  "errors.import.plan.blocked",
  "errors.import.preview.stale",
  "errors.import.state.conflict",
  "errors.import.unavailable",
  "errors.import.upload.empty",
  "errors.import.upload.lost",
  "errors.import.upload.malformed",
  "errors.import.upload.too_large",
  "errors.import.upload.unreadable",
  "errors.import.upload.unsupported",
  "errors.ipam.address.duplicate",
  "errors.ipam.address.full",
  "errors.ipam.address.in_dhcp_pool",
  "errors.ipam.address.in_range",
  "errors.ipam.address.in_supernet",
  "errors.ipam.address.network_or_broadcast",
  "errors.ipam.address.no_prefix",
  "errors.ipam.adoption.invalid",
  "errors.ipam.bulk.too_large",
  "errors.ipam.bulk.wrong_collection",
  "errors.ipam.contended",
  "errors.ipam.host.lock_manual_only",
  "errors.ipam.host.locked",
  "errors.ipam.host.reservation_identifier",
  "errors.ipam.id_taken",
  "errors.ipam.idempotency_mismatch",
  "errors.ipam.immutable",
  "errors.ipam.in_use",
  "errors.ipam.interface.duplicate_mac",
  "errors.ipam.invalid_cursor",
  "errors.ipam.invalid_filter",
  "errors.ipam.job.failed",
  "errors.ipam.move.controller_unavailable",
  "errors.ipam.move.host_part_taken",
  "errors.ipam.move.l2_changed",
  "errors.ipam.move.l2_refused",
  "errors.ipam.move.plan_changed",
  "errors.ipam.move.unmanaged",
  "errors.ipam.name_taken",
  "errors.ipam.not_deleted",
  "errors.ipam.not_found",
  "errors.ipam.object_deleted",
  "errors.ipam.parent_status",
  "errors.ipam.plan.stale",
  "errors.ipam.plan.unacknowledged",
  "errors.ipam.prefix.becomes_supernet",
  "errors.ipam.prefix.full",
  "errors.ipam.prefix.has_children",
  "errors.ipam.prefix.has_ranges",
  "errors.ipam.prefix.host_bits",
  "errors.ipam.prefix.nibble_boundary",
  "errors.ipam.prefix.overlap",
  "errors.ipam.prefix.overlaps_range",
  "errors.ipam.prefix.resize_orphans",
  "errors.ipam.proposal.batch_empty",
  "errors.ipam.proposal.batch_too_large",
  "errors.ipam.proposal.not_found",
  "errors.ipam.proposal.not_open",
  "errors.ipam.proposal.nothing_to_apply",
  "errors.ipam.proposal.revision_mismatch",
  "errors.ipam.range.covers_reservation",
  "errors.ipam.range.not_in_network",
  "errors.ipam.range.outside_prefix",
  "errors.ipam.range.overlap",
  "errors.ipam.reconciler.unavailable",
  "errors.ipam.reference_missing",
  "errors.ipam.revision_mismatch",
  "errors.ipam.site.cycle",
  "errors.ipam.status.transition",
  "errors.ipam.topology.not_found",
  "errors.ipam.topology.unavailable",
  "errors.ipam.unavailable",
  "errors.ipam.validation",
  "errors.ipam.vlan.controller_changed",
  "errors.ipam.vlan.controller_disabled",
  "errors.ipam.vlan.controller_unknown",
  "errors.ipam.vlan.controllers_unavailable",
  "errors.ipam.vlan.duplicate",
  "errors.ipam.vlan.invalid_request",
  "errors.modules.conflict",
  "errors.modules.pinned",
  "errors.modules.store",
  "errors.modules.unavailable",
  "errors.node.config.invalid",
  "errors.node.config.not_a_probe",
  "errors.node.config.revision_mismatch",
  "errors.node.config.secret",
  "errors.node.config.vault_unavailable",
  "errors.node.roles.controller",
  "errors.node.roles.empty",
  "errors.node.roles.last_controller",
  "errors.node.roles.pinned",
  "errors.node.roles.revision_mismatch",
  "errors.node.roles.store",
  "errors.node.roles.unsupported",
  "errors.queue.changed",
  "errors.queue.full",
  "errors.queue.io",
  "errors.queue.not_a_person",
  "errors.queue.not_found",
  "errors.queue.not_isolated",
  "errors.queue.not_queueable",
  "errors.queue.too_large",
  "errors.queue.unavailable",
  "errors.remote.address_unknown",
  "errors.remote.interface_unknown",
  "errors.scan.job.invalid",
  "errors.scan.job.no_probe",
  "errors.scan.job.not_found",
  "errors.scan.job.target",
  "errors.scan.stopped",
  "errors.settings.pin_coupling",
  "errors.sys.csrf_rejected",
  "errors.sys.internal",
  "errors.sys.invalid_request",
  "errors.sys.not_implemented",
  "errors.sys.not_ready",
  "errors.sys.rate_limited",
  "errors.sys.shutting_down",
  "errors.sys.store.no_quorum",
  "errors.sys.store.precondition_failed",
  "errors.update.check_failed",
  "errors.update.check_off",
  "errors.update.check_refused",
  "errors.update.check_timeout",
  "errors.update.check_unavailable",
  "errors.update.checksum_mismatch",
  "errors.update.fetch_failed",
  "errors.update.install_blocked",
  "errors.update.io",
  "errors.update.job",
  "errors.update.job_failed",
  "errors.update.manifest.invalid",
  "errors.update.manifest.json",
  "errors.update.manifest.project",
  "errors.update.manifest.schema",
  "errors.update.manifest.too_large",
  "errors.update.not_executable",
  "errors.update.not_newer",
  "errors.update.signature_unverified",
  "errors.update.size_mismatch",
  "errors.update.source_mismatch",
  "errors.update.store",
  "errors.update.unavailable",
  "errors.update.upload_failed",
  "errors.update.version_mismatch",
  "errors.update.version_unknown",
  "errors.upgrade.attempt_unreadable",
  "errors.upgrade.copy_target",
  "errors.upgrade.crashed",
  "errors.upgrade.format_mismatch",
  "errors.upgrade.format_newer",
  "errors.upgrade.in_use",
  "errors.upgrade.io",
  "errors.upgrade.marker_invalid",
  "errors.upgrade.migration_failed",
  "errors.upgrade.migration_missing",
  "errors.upgrade.no_store",
  "errors.upgrade.not_confirmed",
  "errors.upgrade.not_ready",
  "errors.upgrade.open_failed",
  "errors.upgrade.refused",
  "errors.upgrade.store",
  "errors.users.last_administrator",
  "errors.users.name_taken",
  "errors.users.not_found",
  "errors.vault.host_credentials.conflict",
  "errors.vault.host_credentials.secret_missing",
  "errors.vault.pin_coupling",
  "errors.vault.reveal.host_required",
  "errors.vault.reveal.not_bound",
  "errors.vault.reveal.rate_limited",
  "errors.vault.secret.conflict",
  "errors.vault.secret.in_use",
  "errors.vault.secret.invalid",
  "errors.vault.secret.not_found",
  "errors.vault.secret.not_revealable",
  "errors.vault.secret.not_text",
  "errors.vault.secret.too_large",
  "grid.actionbar.label",
  "grid.actionbar.selected",
  "grid.actions",
  "grid.columns.button",
  "grid.columns.move_down",
  "grid.columns.move_up",
  "grid.columns.reset",
  "grid.columns.title",
  "grid.deleted.exclude",
  "grid.deleted.include",
  "grid.deleted.label",
  "grid.deleted.only",
  "grid.density.comfortable",
  "grid.density.compact",
  "grid.density.dense",
  "grid.density.label",
  "grid.empty.filtered",
  "grid.empty.title",
  "grid.filter.invalid",
  "grid.loading",
  "grid.loading_more",
  "grid.more",
  "grid.row_actions",
  "grid.rows",
  "grid.saving",
  "grid.select_all",
  "grid.select_row",
  "grid.selected",
  "grid.selection.clear",
  "guardrails.add",
  "guardrails.col.actions",
  "guardrails.col.kind",
  "guardrails.col.path",
  "guardrails.dialog.body",
  "guardrails.dialog.submit",
  "guardrails.dialog.title",
  "guardrails.error.duplicate",
  "guardrails.error.invalid",
  "guardrails.error.mac",
  "guardrails.error.parallel",
  "guardrails.error.port",
  "guardrails.error.reference",
  "guardrails.error.vid",
  "guardrails.field.device",
  "guardrails.field.kind",
  "guardrails.field.mac",
  "guardrails.field.network",
  "guardrails.field.port",
  "guardrails.field.vid",
  "guardrails.help.device",
  "guardrails.help.mac",
  "guardrails.help.network",
  "guardrails.help.port",
  "guardrails.help.vid",
  "guardrails.kind.client",
  "guardrails.kind.network",
  "guardrails.kind.port",
  "guardrails.kind.vlan",
  "guardrails.lede",
  "guardrails.note",
  "guardrails.parallel.help",
  "guardrails.parallel.label",
  "guardrails.parallel.limits",
  "guardrails.path.port",
  "guardrails.path.vlan",
  "guardrails.paths.heading",
  "guardrails.paths.none",
  "guardrails.reloaded",
  "guardrails.remove",
  "guardrails.remove_label",
  "guardrails.saved",
  "guardrails.title",
  "hosts.addresses.none",
  "hosts.addresses.title",
  "hosts.bulk.lock_title",
  "hosts.bulk.mode_title",
  "hosts.bulk.unlock_title",
  "hosts.col.addresses",
  "hosts.col.client_id",
  "hosts.col.duid",
  "hosts.col.interface",
  "hosts.connect.failed",
  "hosts.connect.hint",
  "hosts.connect.rdp",
  "hosts.connect.rdp_port",
  "hosts.connect.ssh",
  "hosts.connect.ssh_port",
  "hosts.connect.target",
  "hosts.connect.title",
  "hosts.connect.user",
  "hosts.connect.user_placeholder",
  "hosts.credentials.audit_hint",
  "hosts.credentials.bind",
  "hosts.credentials.bind_title",
  "hosts.credentials.bound",
  "hosts.credentials.col.actions",
  "hosts.credentials.col.name",
  "hosts.credentials.col.revealed",
  "hosts.credentials.col.role",
  "hosts.credentials.col.user",
  "hosts.credentials.copy",
  "hosts.credentials.empty",
  "hosts.credentials.field.role",
  "hosts.credentials.field.secret",
  "hosts.credentials.manage",
  "hosts.credentials.never_revealed",
  "hosts.credentials.none_free",
  "hosts.credentials.option",
  "hosts.credentials.revealed_by",
  "hosts.credentials.role.admin",
  "hosts.credentials.role.other",
  "hosts.credentials.role.rdp",
  "hosts.credentials.role.ssh",
  "hosts.credentials.role.web",
  "hosts.credentials.title",
  "hosts.credentials.unbind",
  "hosts.credentials.unbind_body",
  "hosts.credentials.unbind_failed",
  "hosts.credentials.unbind_label",
  "hosts.credentials.unbind_title",
  "hosts.credentials.unbound",
  "hosts.crumbs",
  "hosts.dns.col.address",
  "hosts.dns.col.forward",
  "hosts.dns.col.reverse",
  "hosts.dns.no_records",
  "hosts.dns.no_zone",
  "hosts.dns.origin.ad",
  "hosts.dns.origin.dhcp",
  "hosts.dns.origin.dnssec",
  "hosts.dns.origin.dynamic",
  "hosts.dns.origin.ipam",
  "hosts.dns.origin.manual",
  "hosts.dns.origin.transfer",
  "hosts.dns.title",
  "hosts.do.create",
  "hosts.do.lock",
  "hosts.do.set_mode",
  "hosts.do.toggle_lock",
  "hosts.do.unlock",
  "hosts.empty",
  "hosts.facts.title",
  "hosts.filter.label",
  "hosts.filter.locked",
  "hosts.filter.placeholder",
  "hosts.form.create",
  "hosts.form.create_title",
  "hosts.form.created",
  "hosts.form.default_tenant",
  "hosts.form.duid_invalid",
  "hosts.form.edit_title",
  "hosts.form.first_interface",
  "hosts.form.hex_invalid",
  "hosts.form.iface_create",
  "hosts.form.iface_create_title",
  "hosts.form.iface_edit_title",
  "hosts.form.iface_name_required",
  "hosts.form.iface_saved",
  "hosts.form.lock",
  "hosts.form.mac_invalid",
  "hosts.form.name_invalid",
  "hosts.form.none",
  "hosts.form.save",
  "hosts.form.saved",
  "hosts.in_several",
  "hosts.interfaces.add",
  "hosts.interfaces.empty",
  "hosts.interfaces.title",
  "hosts.jobs.all",
  "hosts.jobs.none",
  "hosts.jobs.title",
  "hosts.lock_failed",
  "hosts.locked",
  "hosts.mac.none",
  "hosts.mac.several",
  "hosts.mode.change",
  "hosts.mode.change_title",
  "hosts.mode.changed",
  "hosts.mode.current",
  "hosts.mode.locked_note",
  "hosts.mode.title",
  "hosts.not_found",
  "hosts.observations.empty",
  "hosts.observations.open",
  "hosts.observations.title",
  "hosts.undo",
  "hosts.unlocked",
  "hosts.warn.both",
  "hosts.warn.duid",
  "hosts.warn.identifier_title",
  "hosts.warn.mac",
  "import.action.create",
  "import.action.kept",
  "import.action.unchanged",
  "import.action.update",
  "import.changes.first_rows",
  "import.changes.group",
  "import.changes.title",
  "import.columns.column",
  "import.columns.credential_option",
  "import.columns.header",
  "import.columns.interface",
  "import.columns.interface_placeholder",
  "import.columns.label",
  "import.columns.samples",
  "import.columns.shapes",
  "import.columns.suggested",
  "import.columns.target",
  "import.columns.target_of",
  "import.columns.vault",
  "import.conflict.fail",
  "import.conflict.skip",
  "import.conflict.update",
  "import.credentials.not_allowed",
  "import.credentials.pin_enrol",
  "import.credentials.reason.forbidden",
  "import.credentials.reason.pin_coupling",
  "import.credentials.reason.step_up_required",
  "import.credentials.reason.unauthenticated",
  "import.credentials.reason.vault_unavailable",
  "import.credentials.statement",
  "import.credentials.title",
  "import.discard",
  "import.export.addresses",
  "import.export.body",
  "import.export.hosts",
  "import.export.prefixes",
  "import.export.title",
  "import.issue.header_row",
  "import.issue.network_cidr",
  "import.issue.no_address",
  "import.kind.host",
  "import.kind.index",
  "import.kind.list",
  "import.kind.network",
  "import.kind.skip",
  "import.loss.address.duplicate",
  "import.loss.address.is_broadcast",
  "import.loss.address.is_network",
  "import.loss.address.missing",
  "import.loss.address.no_prefix",
  "import.loss.address.range_too_large",
  "import.loss.address.unparsable",
  "import.loss.column.unmapped",
  "import.loss.conflict.kept",
  "import.loss.counts",
  "import.loss.credential.duplicate",
  "import.loss.credential.no_host",
  "import.loss.credential.numeric",
  "import.loss.credential.skipped",
  "import.loss.credential.suspicious",
  "import.loss.custom.undefined",
  "import.loss.detail",
  "import.loss.download",
  "import.loss.host.conflict",
  "import.loss.host.locked",
  "import.loss.name.invalid",
  "import.loss.name.missing",
  "import.loss.name.normalized",
  "import.loss.none",
  "import.loss.prefix.host_bits",
  "import.loss.prefix.in_network",
  "import.loss.prefix.proposed",
  "import.loss.prefix.unlisted",
  "import.loss.prefix.unparsable",
  "import.loss.severity",
  "import.loss.sheet.empty",
  "import.loss.sheet.skipped",
  "import.loss.title",
  "import.loss.value.invalid",
  "import.loss.what",
  "import.loss.where",
  "import.loss.whole",
  "import.mapping.files",
  "import.mapping.preview",
  "import.mapping.tab",
  "import.mapping.text",
  "import.mask.addresses",
  "import.mask.index",
  "import.mask.name",
  "import.mask.row_count",
  "import.mask.user",
  "import.options.conflict",
  "import.options.credentials",
  "import.options.credentials_help",
  "import.options.credentials_import",
  "import.options.tenant",
  "import.options.tenant_default",
  "import.options.title",
  "import.options.vrf",
  "import.options.vrf_default",
  "import.preview.apply",
  "import.preview.back",
  "import.preview.blocked",
  "import.preview.counts",
  "import.preview.credentials_kind",
  "import.preview.kind",
  "import.preview.rows_free",
  "import.preview.rows_imported",
  "import.preview.rows_skipped",
  "import.preview.rows_total",
  "import.preview.steps",
  "import.preview.summary",
  "import.preview.supernet_step",
  "import.preview.warnings",
  "import.proposals.body",
  "import.proposals.holds",
  "import.proposals.title",
  "import.result.again",
  "import.result.back",
  "import.result.count",
  "import.result.created",
  "import.result.done",
  "import.result.failed",
  "import.result.more",
  "import.result.progress",
  "import.result.rolled_back",
  "import.result.running",
  "import.result.show_all",
  "import.rows.count",
  "import.rows.items",
  "import.rows.more",
  "import.rows.none",
  "import.rows.nothing",
  "import.rows.status",
  "import.rows.status_free",
  "import.rows.status_imported",
  "import.rows.status_skipped",
  "import.rows.title",
  "import.rows.where",
  "import.severity.error",
  "import.severity.info",
  "import.severity.warning",
  "import.shape.address",
  "import.shape.cidr",
  "import.shape.count",
  "import.shape.duid",
  "import.shape.empty",
  "import.shape.mac",
  "import.shape.number",
  "import.shape.range",
  "import.shape.text",
  "import.sheet.cidr",
  "import.sheet.header_row",
  "import.sheet.kind",
  "import.sheet.listed",
  "import.sheet.no_header",
  "import.sheet.roles_from",
  "import.sheet.summary",
  "import.sheets.errors",
  "import.sheets.free",
  "import.sheets.imported",
  "import.sheets.kind",
  "import.sheets.notes",
  "import.sheets.rows",
  "import.sheets.sheet",
  "import.sheets.skipped",
  "import.sheets.title",
  "import.sheets.warnings",
  "import.step.apply",
  "import.step.done",
  "import.step.mapping",
  "import.step.preview",
  "import.step.upload",
  "import.steps",
  "import.sub",
  "import.target.address",
  "import.target.alarm_crit",
  "import.target.alarm_warn",
  "import.target.alloc",
  "import.target.client_id",
  "import.target.description",
  "import.target.dns_name",
  "import.target.duid",
  "import.target.host",
  "import.target.ignore",
  "import.target.interface",
  "import.target.interfaces",
  "import.target.lock",
  "import.target.login",
  "import.target.mac",
  "import.target.mask",
  "import.target.mode",
  "import.target.password",
  "import.target.prefix",
  "import.target.role",
  "import.target.site",
  "import.target.status",
  "import.target.tags",
  "import.target.tenant",
  "import.target.vlan",
  "import.target.vlan_name",
  "import.target.vrf",
  "import.title",
  "import.upload.body",
  "import.upload.choose",
  "import.upload.drop",
  "import.upload.files",
  "import.upload.remove",
  "import.upload.size",
  "import.upload.start",
  "import.upload.title",
  "import.upload.too_large",
  "import.upload.unsupported",
  "ipam.action.create",
  "ipam.action.delete",
  "ipam.action.lock",
  "ipam.action.remove",
  "ipam.action.restore",
  "ipam.action.unlock",
  "ipam.action.update",
  "ipam.address.claim_failed",
  "ipam.address.claimed",
  "ipam.address.facts",
  "ipam.address.in_several",
  "ipam.address.interface",
  "ipam.address.not_found",
  "ipam.address.renamed",
  "ipam.address.unassigned",
  "ipam.addresses.claim",
  "ipam.addresses.dns_hint",
  "ipam.addresses.empty",
  "ipam.addresses.filter_label",
  "ipam.addresses.filter_placeholder",
  "ipam.addresses.filter_terms",
  "ipam.addresses.free",
  "ipam.addresses.grid",
  "ipam.addresses.none",
  "ipam.addresses.show_free",
  "ipam.adoption.clear",
  "ipam.adoption.cleared",
  "ipam.adoption.edit",
  "ipam.adoption.error.sightings",
  "ipam.adoption.error.vendor_length",
  "ipam.adoption.error.vendors_count",
  "ipam.adoption.host_mode",
  "ipam.adoption.host_mode_help",
  "ipam.adoption.host_mode_on",
  "ipam.adoption.min_sightings",
  "ipam.adoption.min_sightings_help",
  "ipam.adoption.mode.adopt_all",
  "ipam.adoption.mode.adopt_hosts",
  "ipam.adoption.mode.manual",
  "ipam.adoption.mode_hint.adopt_all",
  "ipam.adoption.mode_hint.adopt_hosts",
  "ipam.adoption.mode_hint.manual",
  "ipam.adoption.mode_label",
  "ipam.adoption.never",
  "ipam.adoption.only_pools",
  "ipam.adoption.only_pools_on",
  "ipam.adoption.proposals",
  "ipam.adoption.save",
  "ipam.adoption.saved",
  "ipam.adoption.set",
  "ipam.adoption.sightings_on",
  "ipam.adoption.source_default",
  "ipam.adoption.source_inherited",
  "ipam.adoption.source_own",
  "ipam.adoption.stale",
  "ipam.adoption.title",
  "ipam.adoption.updated_by",
  "ipam.adoption.vendors",
  "ipam.adoption.vendors_help",
  "ipam.adoption.vendors_on",
  "ipam.alarm.critical",
  "ipam.alarm.normal",
  "ipam.alarm.warning",
  "ipam.cfdef.applies_required",
  "ipam.cfdef.applies_to",
  "ipam.cfdef.create",
  "ipam.cfdef.create_title",
  "ipam.cfdef.delete_title",
  "ipam.cfdef.deleted",
  "ipam.cfdef.edit_title",
  "ipam.cfdef.empty",
  "ipam.cfdef.key",
  "ipam.cfdef.key_help",
  "ipam.cfdef.key_invalid",
  "ipam.cfdef.no",
  "ipam.cfdef.options",
  "ipam.cfdef.options_help",
  "ipam.cfdef.options_required",
  "ipam.cfdef.required",
  "ipam.cfdef.required_col",
  "ipam.cfdef.type",
  "ipam.cfdef.yes",
  "ipam.col.address",
  "ipam.col.created",
  "ipam.col.description",
  "ipam.col.dns_name",
  "ipam.col.host",
  "ipam.col.lease",
  "ipam.col.mac",
  "ipam.col.mode",
  "ipam.col.name",
  "ipam.col.prefix",
  "ipam.col.range",
  "ipam.col.role",
  "ipam.col.site",
  "ipam.col.status",
  "ipam.col.tag",
  "ipam.col.tags",
  "ipam.col.tenant",
  "ipam.col.updated",
  "ipam.col.utilization",
  "ipam.col.vid",
  "ipam.col.vlan",
  "ipam.col.vni",
  "ipam.col.vrf",
  "ipam.command.focus_tree",
  "ipam.custom_kind.boolean",
  "ipam.custom_kind.date",
  "ipam.custom_kind.integer",
  "ipam.custom_kind.select",
  "ipam.custom_kind.text",
  "ipam.custom_kind.url",
  "ipam.delete.cascade",
  "ipam.delete.done",
  "ipam.delete.title",
  "ipam.delete.undo",
  "ipam.delete.undo_failed",
  "ipam.do.delete",
  "ipam.do.edit",
  "ipam.do.export_csv",
  "ipam.do.history",
  "ipam.do.move",
  "ipam.do.next_free_address",
  "ipam.do.next_free_prefix",
  "ipam.do.open",
  "ipam.do.reserve",
  "ipam.do.restore",
  "ipam.field.alarm_both",
  "ipam.field.alarm_crit",
  "ipam.field.alarm_help",
  "ipam.field.alarm_order",
  "ipam.field.alarm_range",
  "ipam.field.alarm_warn",
  "ipam.field.choose",
  "ipam.field.cidr",
  "ipam.field.cidr_help",
  "ipam.field.cidr_invalid",
  "ipam.field.cidr_required",
  "ipam.field.custom",
  "ipam.field.dns_help",
  "ipam.field.dns_invalid",
  "ipam.field.first",
  "ipam.field.inside_prefix",
  "ipam.field.integer_invalid",
  "ipam.field.ip",
  "ipam.field.ip_invalid",
  "ipam.field.ip_renumber_help",
  "ipam.field.ip_required",
  "ipam.field.last",
  "ipam.field.last_before_first",
  "ipam.field.lease_help",
  "ipam.field.lease_number",
  "ipam.field.lease_range",
  "ipam.field.lease_unit",
  "ipam.field.none",
  "ipam.field.option_invalid",
  "ipam.field.required",
  "ipam.field.tag_invalid",
  "ipam.field.tag_remove",
  "ipam.field.tags_help",
  "ipam.field.unit_days",
  "ipam.field.unit_hours",
  "ipam.field.unit_minutes",
  "ipam.field.url_invalid",
  "ipam.flag.deleted",
  "ipam.flag.locked",
  "ipam.flag.locked_hint",
  "ipam.form.create_kind",
  "ipam.form.create_title",
  "ipam.form.created",
  "ipam.form.edit_title",
  "ipam.form.role_auto",
  "ipam.form.role_help",
  "ipam.form.save_changes",
  "ipam.form.save_title",
  "ipam.form.saved",
  "ipam.form.use_network",
  "ipam.history.empty",
  "ipam.history.label",
  "ipam.history.more",
  "ipam.history.title",
  "ipam.kind.address",
  "ipam.kind.custom_field",
  "ipam.kind.host",
  "ipam.kind.interface",
  "ipam.kind.prefix",
  "ipam.kind.range",
  "ipam.kind.site",
  "ipam.kind.tenant",
  "ipam.kind.vlan",
  "ipam.kind.vrf",
  "ipam.kind_title.address",
  "ipam.kind_title.custom_field",
  "ipam.kind_title.host",
  "ipam.kind_title.interface",
  "ipam.kind_title.prefix",
  "ipam.kind_title.range",
  "ipam.kind_title.site",
  "ipam.kind_title.tenant",
  "ipam.kind_title.vlan",
  "ipam.kind_title.vrf",
  "ipam.meter.title",
  "ipam.meter.value",
  "ipam.mode.dynamic",
  "ipam.mode.reserved",
  "ipam.mode.static",
  "ipam.mode.unmanaged",
  "ipam.mode_hint.dynamic",
  "ipam.mode_hint.reserved",
  "ipam.mode_hint.static",
  "ipam.mode_hint.unmanaged",
  "ipam.move.choose_body",
  "ipam.move.choose_title",
  "ipam.move.dragging",
  "ipam.move.no_target",
  "ipam.move.step.cleanup",
  "ipam.move.step.controller_client",
  "ipam.move.step.controller_port",
  "ipam.move.step.dhcp",
  "ipam.move.step.intent",
  "ipam.move.task.device",
  "ipam.move.task.dhcp",
  "ipam.move.task.dns",
  "ipam.move.task.generic",
  "ipam.move.task.l2",
  "ipam.move.task.l2_client",
  "ipam.move.task.l2_network",
  "ipam.move.task.l2_port",
  "ipam.move.task.l2_port_vlan",
  "ipam.move.task.l2_refused",
  "ipam.move.task.l2_shared_port",
  "ipam.move.task.l2_ssid",
  "ipam.move.task.l2_vlan",
  "ipam.move.task.observe",
  "ipam.move.title",
  "ipam.nav.addresses",
  "ipam.nav.custom_fields",
  "ipam.nav.hosts",
  "ipam.nav.import",
  "ipam.nav.label",
  "ipam.nav.networks",
  "ipam.nav.reconcile",
  "ipam.nav.sites",
  "ipam.nav.tags",
  "ipam.nav.tenancy",
  "ipam.nav.vlans",
  "ipam.next_free.address",
  "ipam.next_free.address_title",
  "ipam.next_free.create",
  "ipam.next_free.find_address",
  "ipam.next_free.find_prefix",
  "ipam.next_free.from",
  "ipam.next_free.length",
  "ipam.next_free.length_help",
  "ipam.next_free.length_invalid",
  "ipam.next_free.length_required",
  "ipam.next_free.prefix",
  "ipam.next_free.prefix_title",
  "ipam.next_free.suggest",
  "ipam.next_free.whole_network",
  "ipam.overview.empty_hint",
  "ipam.overview.grid",
  "ipam.overview.label",
  "ipam.overview.sub",
  "ipam.plan.ack",
  "ipam.plan.ack_needed",
  "ipam.plan.change.create",
  "ipam.plan.change.delete",
  "ipam.plan.change.lock",
  "ipam.plan.change.remove",
  "ipam.plan.change.restore",
  "ipam.plan.change.unlock",
  "ipam.plan.change.update",
  "ipam.plan.changes",
  "ipam.plan.col.action",
  "ipam.plan.col.fields",
  "ipam.plan.col.object",
  "ipam.plan.derived",
  "ipam.plan.heading",
  "ipam.plan.nothing",
  "ipam.plan.open_job",
  "ipam.plan.previewing",
  "ipam.plan.stale",
  "ipam.plan.summary_line",
  "ipam.prefix.alarm",
  "ipam.prefix.alarm_value",
  "ipam.prefix.alloc",
  "ipam.prefix.alloc_highest",
  "ipam.prefix.alloc_lowest",
  "ipam.prefix.children_grid",
  "ipam.prefix.crumbs",
  "ipam.prefix.dns_reverse",
  "ipam.prefix.dns_reverse_default",
  "ipam.prefix.dns_reverse_help",
  "ipam.prefix.dns_reverse_managed",
  "ipam.prefix.dns_reverse_off",
  "ipam.prefix.in_several",
  "ipam.prefix.no_children",
  "ipam.prefix.not_found",
  "ipam.prefix.ranges_grid",
  "ipam.prefix.tab.addresses",
  "ipam.prefix.tab.adoption",
  "ipam.prefix.tab.children",
  "ipam.prefix.tab.history",
  "ipam.prefix.tab.ranges",
  "ipam.prefix.tabs",
  "ipam.prefix.usage",
  "ipam.prefix_role.network",
  "ipam.prefix_role.supernet",
  "ipam.range.add",
  "ipam.range.empty",
  "ipam.range_role.dhcp_pool",
  "ipam.range_role.infrastructure",
  "ipam.range_role.reserved",
  "ipam.reconcile.col.address",
  "ipam.reconcile.col.details",
  "ipam.reconcile.col.winner",
  "ipam.reconcile.count",
  "ipam.reconcile.dns_forward",
  "ipam.reconcile.dns_ptr",
  "ipam.reconcile.empty",
  "ipam.reconcile.filter.all_kinds",
  "ipam.reconcile.filter.all_prefixes",
  "ipam.reconcile.filter.host",
  "ipam.reconcile.filter.host_apply",
  "ipam.reconcile.filter.host_chip",
  "ipam.reconcile.filter.host_placeholder",
  "ipam.reconcile.filter.host_unknown",
  "ipam.reconcile.filter.kind",
  "ipam.reconcile.filter.label",
  "ipam.reconcile.filter.prefix",
  "ipam.reconcile.filter.remove_host",
  "ipam.reconcile.host_open",
  "ipam.reconcile.host_unavailable",
  "ipam.reconcile.kind.conflict",
  "ipam.reconcile.kind.ghost",
  "ipam.reconcile.kind.orphan",
  "ipam.reconcile.kind.ptr_mismatch",
  "ipam.reconcile.kind.rogue",
  "ipam.reconcile.kind_help.conflict",
  "ipam.reconcile.kind_help.ghost",
  "ipam.reconcile.kind_help.orphan",
  "ipam.reconcile.kind_help.ptr_mismatch",
  "ipam.reconcile.kind_help.rogue",
  "ipam.reconcile.last_seen",
  "ipam.reconcile.more",
  "ipam.reconcile.no_winner",
  "ipam.reconcile.os",
  "ipam.reconcile.os_guess",
  "ipam.reconcile.os_source",
  "ipam.reconcile.proposal",
  "ipam.reconcile.retry",
  "ipam.reconcile.rule.forward_record",
  "ipam.reconcile.rule.intent_managed",
  "ipam.reconcile.rule.lease_dynamic",
  "ipam.reconcile.rule.manual_record",
  "ipam.reconcile.rule.never_automatic",
  "ipam.reconcile.rule.newest_sighting",
  "ipam.reconcile.rule.orphan_rule",
  "ipam.reconcile.sub",
  "ipam.reconcile.title",
  "ipam.reconcile.truth.dns",
  "ipam.reconcile.truth.intent",
  "ipam.reconcile.truth.lease",
  "ipam.reconcile.truth.scan",
  "ipam.reconcile.vendors",
  "ipam.reconcile.winner",
  "ipam.reconcile.wins",
  "ipam.restore.done",
  "ipam.restore.title",
  "ipam.scope.label",
  "ipam.scope.option",
  "ipam.site.ad_site",
  "ipam.site.ad_site_help",
  "ipam.site.create",
  "ipam.site.create_title",
  "ipam.site.edit_title",
  "ipam.site.empty",
  "ipam.site.filter_label",
  "ipam.site.filter_placeholder",
  "ipam.site.parent",
  "ipam.status.active",
  "ipam.status.deprecated",
  "ipam.status.planned",
  "ipam.status.reserved",
  "ipam.tags.by_kind",
  "ipam.tags.count",
  "ipam.tags.empty",
  "ipam.tags.show",
  "ipam.tags.sub",
  "ipam.tenancy.created",
  "ipam.tenancy.filter_placeholder",
  "ipam.tenancy.name_required",
  "ipam.tenancy.none",
  "ipam.tenancy.save",
  "ipam.tenancy.saved",
  "ipam.tenant.create",
  "ipam.tenant.create_title",
  "ipam.tenant.default_zone",
  "ipam.tenant.default_zone_help",
  "ipam.tenant.default_zone_none",
  "ipam.tenant.edit_title",
  "ipam.tenant.empty",
  "ipam.tenant.filter_label",
  "ipam.tenant.title",
  "ipam.tree.add",
  "ipam.tree.drag_hint",
  "ipam.tree.drop_hint",
  "ipam.tree.drop_refused",
  "ipam.tree.empty",
  "ipam.tree.filter",
  "ipam.tree.key_grid",
  "ipam.tree.key_tree",
  "ipam.tree.label",
  "ipam.tree.supernet",
  "ipam.vlan.create",
  "ipam.vlan.create_title",
  "ipam.vlan.edit_title",
  "ipam.vlan.empty",
  "ipam.vlan.filter_label",
  "ipam.vlan.filter_placeholder",
  "ipam.vlan.job.title",
  "ipam.vlan.prefixes.empty",
  "ipam.vlan.prefixes.intro",
  "ipam.vlan.prefixes.list_label",
  "ipam.vlan.prefixes.loading",
  "ipam.vlan.prefixes.row_action",
  "ipam.vlan.prefixes.title",
  "ipam.vlan.provision.action",
  "ipam.vlan.provision.connector",
  "ipam.vlan.provision.connector_any",
  "ipam.vlan.provision.connector_help",
  "ipam.vlan.provision.controller_auto",
  "ipam.vlan.provision.controller_auto_help",
  "ipam.vlan.provision.controller_label",
  "ipam.vlan.provision.controller_manual",
  "ipam.vlan.provision.controller_manual_help",
  "ipam.vlan.provision.controller_none",
  "ipam.vlan.provision.dhcp_off",
  "ipam.vlan.provision.dhcp_relay",
  "ipam.vlan.provision.dhcp_relay_help",
  "ipam.vlan.provision.diff.absent",
  "ipam.vlan.provision.diff.now",
  "ipam.vlan.provision.diff.planned",
  "ipam.vlan.provision.diff.removed",
  "ipam.vlan.provision.diff.setting",
  "ipam.vlan.provision.diff_heading",
  "ipam.vlan.provision.diff_none",
  "ipam.vlan.provision.hint.by_hand",
  "ipam.vlan.provision.intro_existing",
  "ipam.vlan.provision.intro_new",
  "ipam.vlan.provision.mode.automatic",
  "ipam.vlan.provision.mode.manual",
  "ipam.vlan.provision.mode.unchanged",
  "ipam.vlan.provision.mode_hint.automatic",
  "ipam.vlan.provision.mode_hint.manual",
  "ipam.vlan.provision.mode_hint.unchanged",
  "ipam.vlan.provision.network_legend",
  "ipam.vlan.provision.network_name",
  "ipam.vlan.provision.network_name_help",
  "ipam.vlan.provision.network_name_long",
  "ipam.vlan.provision.network_name_placeholder",
  "ipam.vlan.provision.notes_heading",
  "ipam.vlan.provision.preview",
  "ipam.vlan.provision.preview_intro",
  "ipam.vlan.provision.read_at",
  "ipam.vlan.provision.read_only",
  "ipam.vlan.provision.reason.controller_ambiguous",
  "ipam.vlan.provision.reason.controller_read_only",
  "ipam.vlan.provision.reason.manual_requested",
  "ipam.vlan.provision.reason.no_controller",
  "ipam.vlan.provision.reason.unknown",
  "ipam.vlan.provision.relay_invalid",
  "ipam.vlan.provision.relay_too_many",
  "ipam.vlan.provision.row_action",
  "ipam.vlan.provision.start",
  "ipam.vlan.provision.started",
  "ipam.vlan.provision.step.activate",
  "ipam.vlan.provision.step.intent_both",
  "ipam.vlan.provision.step.intent_prefix",
  "ipam.vlan.provision.step.intent_vlan",
  "ipam.vlan.provision.step.manual",
  "ipam.vlan.provision.step.network",
  "ipam.vlan.provision.step.network_check",
  "ipam.vlan.provision.steps_heading",
  "ipam.vlan.provision.title_existing",
  "ipam.vlan.provision.title_new",
  "ipam.vlan.provision.vlan_existing",
  "ipam.vlan.provision.vlan_new",
  "ipam.vlan.provision.vrf_default",
  "ipam.vlan.provision.warning.controller_ambiguous",
  "ipam.vlan.provision.warning.controller_read_only",
  "ipam.vlan.provision.warning.network_changes",
  "ipam.vlan.provision.will_exist",
  "ipam.vlan.provision.with_prefix",
  "ipam.vlan.provision.with_prefix_help",
  "ipam.vlan.step.activate",
  "ipam.vlan.step.controller",
  "ipam.vlan.step.intent",
  "ipam.vlan.task.network",
  "ipam.vlan.vid_invalid",
  "ipam.vlan.vni_help",
  "ipam.vlan.vni_invalid",
  "ipam.vrf.create",
  "ipam.vrf.create_title",
  "ipam.vrf.default_tenant",
  "ipam.vrf.edit_title",
  "ipam.vrf.empty",
  "ipam.vrf.filter_label",
  "ipam.vrf.rd",
  "ipam.vrf.rd_help",
  "ipam.vrf.title",
  "jobs.action.cancel",
  "jobs.action.complete",
  "jobs.action.fail",
  "jobs.action.finish_cancel",
  "jobs.action.finish_rollback",
  "jobs.action.resume",
  "jobs.action.roll_back",
  "jobs.action.start",
  "jobs.action.wait",
  "jobs.cancel.body_active",
  "jobs.cancel.body_queued",
  "jobs.cancel.button",
  "jobs.cancel.confirm",
  "jobs.cancel.done",
  "jobs.cancel.keep",
  "jobs.cancel.note",
  "jobs.cancel.requested",
  "jobs.cancel.title",
  "jobs.checklist.empty",
  "jobs.checklist.group",
  "jobs.checklist.heading",
  "jobs.checklist.hint",
  "jobs.checklist.loading",
  "jobs.checklist.mark_done",
  "jobs.checklist.open",
  "jobs.col.by",
  "jobs.col.created",
  "jobs.col.finished",
  "jobs.col.job",
  "jobs.col.kind",
  "jobs.col.progress",
  "jobs.col.state",
  "jobs.col.step",
  "jobs.complete.button",
  "jobs.complete.done",
  "jobs.crumbs",
  "jobs.deadline.in",
  "jobs.deadline.line",
  "jobs.deadline.passed",
  "jobs.duration.d",
  "jobs.duration.h",
  "jobs.duration.min",
  "jobs.duration.s",
  "jobs.empty.body",
  "jobs.empty.filtered",
  "jobs.empty.title",
  "jobs.error.cancelled",
  "jobs.error.invalid_transition",
  "jobs.error.not_found",
  "jobs.error.note_too_long",
  "jobs.error.query_invalid",
  "jobs.error.step_deadline_passed",
  "jobs.error.step_failed",
  "jobs.error.step_interrupted",
  "jobs.error.step_invalid_params",
  "jobs.error.step_not_compensable",
  "jobs.error.step_not_found",
  "jobs.error.step_panicked",
  "jobs.error.step_timeout",
  "jobs.error.timeout",
  "jobs.error.unknown_step_kind",
  "jobs.event.cancel_requested",
  "jobs.event.claimed",
  "jobs.event.step",
  "jobs.event.submitted",
  "jobs.fact.created",
  "jobs.fact.finished",
  "jobs.fact.group",
  "jobs.fact.group_limit",
  "jobs.fact.group_link",
  "jobs.fact.id",
  "jobs.fact.not_yet",
  "jobs.fact.started",
  "jobs.fact.targets",
  "jobs.fact.timeout",
  "jobs.fact.timeout_hint",
  "jobs.fact.when_by",
  "jobs.filter.group",
  "jobs.filter.kind",
  "jobs.filter.label",
  "jobs.filter.placeholder",
  "jobs.filter.remove",
  "jobs.filter.target",
  "jobs.flag.cancel_requested",
  "jobs.group.heading",
  "jobs.group.limit",
  "jobs.group.not_moved.count",
  "jobs.group.not_moved.heading",
  "jobs.group.not_moved.hint",
  "jobs.group.not_moved.no_reason",
  "jobs.group.summary",
  "jobs.kind.address",
  "jobs.kind.custom_field",
  "jobs.kind.host",
  "jobs.kind.import",
  "jobs.kind.interface",
  "jobs.kind.prefix",
  "jobs.kind.range",
  "jobs.kind.site",
  "jobs.kind.tenant",
  "jobs.kind.vlan",
  "jobs.kind.vrf",
  "jobs.l2.absent",
  "jobs.l2.col.after",
  "jobs.l2.col.before",
  "jobs.l2.col.path",
  "jobs.l2.diff",
  "jobs.l2.no_undo",
  "jobs.l2.planned",
  "jobs.l2.receipt",
  "jobs.l2.reverted",
  "jobs.l2.title",
  "jobs.l2.unchanged",
  "jobs.l2.undo_hint",
  "jobs.l2.unknown_write",
  "jobs.l2.warnings",
  "jobs.log.change",
  "jobs.log.col.by",
  "jobs.log.col.change",
  "jobs.log.col.event",
  "jobs.log.col.note",
  "jobs.log.col.step",
  "jobs.log.col.time",
  "jobs.log.heading",
  "jobs.log.label",
  "jobs.needs_you",
  "jobs.no_right",
  "jobs.note.counter",
  "jobs.note.help",
  "jobs.note.label",
  "jobs.note.over",
  "jobs.observe.address_seen",
  "jobs.observe.address_seen_mac",
  "jobs.observe.lease",
  "jobs.observe.other",
  "jobs.observe.waiting",
  "jobs.problem.detail",
  "jobs.problem.title",
  "jobs.progress",
  "jobs.state.cancelled",
  "jobs.state.cancelled_rolled_back",
  "jobs.state.failed",
  "jobs.state.queued",
  "jobs.state.rolled_back",
  "jobs.state.rolling_back",
  "jobs.state.running",
  "jobs.state.succeeded",
  "jobs.state.waiting",
  "jobs.step.cleanup",
  "jobs.step.device_manual",
  "jobs.step.dhcp_manual",
  "jobs.step.dns_import_apply",
  "jobs.step.dns_import_parse",
  "jobs.step.dns_list_compile",
  "jobs.step.dns_list_fetch",
  "jobs.step.dns_list_read",
  "jobs.step.dns_manual",
  "jobs.step.import_apply_chunk",
  "jobs.step.import_parse",
  "jobs.step.import_plan",
  "jobs.step.ipam_apply",
  "jobs.step.ipam_intent",
  "jobs.step.l2_move",
  "jobs.step.observe",
  "jobs.step.sys_update_check",
  "jobs.step.sys_update_fetch",
  "jobs.step.sys_update_switch",
  "jobs.step.sys_update_verify",
  "jobs.step_position",
  "jobs.step_state.compensated",
  "jobs.step_state.compensating",
  "jobs.step_state.compensation_failed",
  "jobs.step_state.done",
  "jobs.step_state.failed",
  "jobs.step_state.pending",
  "jobs.step_state.running",
  "jobs.step_state.skipped",
  "jobs.step_state.waiting_for_manual",
  "jobs.step_state.waiting_for_observation",
  "jobs.stepmeta.attempts",
  "jobs.stepmeta.finished",
  "jobs.stepmeta.started",
  "jobs.stepname.cleanup",
  "jobs.stepname.device_manual",
  "jobs.stepname.dhcp_manual",
  "jobs.stepname.dns_manual",
  "jobs.stepname.ipam_intent",
  "jobs.stepname.ipam_move_cleanup",
  "jobs.stepname.ipam_move_controller",
  "jobs.stepname.ipam_move_device",
  "jobs.stepname.ipam_move_dhcp",
  "jobs.stepname.ipam_move_dns",
  "jobs.stepname.ipam_move_intent",
  "jobs.stepname.ipam_move_l2",
  "jobs.stepname.ipam_move_observe",
  "jobs.stepname.ipam_vlan_activate",
  "jobs.stepname.ipam_vlan_controller",
  "jobs.stepname.ipam_vlan_intent",
  "jobs.stepname.ipam_vlan_manual",
  "jobs.stepname.l2_move",
  "jobs.stepname.observe",
  "jobs.stepname.sys_update_check",
  "jobs.stepname.sys_update_fetch",
  "jobs.stepname.sys_update_switch",
  "jobs.stepname.sys_update_verify",
  "jobs.steps.heading",
  "jobs.steps.label",
  "jobs.sub",
  "jobs.tag.undo",
  "jobs.targets",
  "jobs.task.dhcp_release",
  "jobs.task.dhcp_reserve",
  "jobs.task.dns_revert",
  "jobs.task.dns_update",
  "jobs.title",
  "jobs.title.dns_import",
  "jobs.title.dns_list_fetch",
  "jobs.title.dns_list_upload",
  "jobs.title.import_apply",
  "jobs.title.ipam_apply",
  "jobs.title.move",
  "jobs.title.update_install",
  "jobs.undo.step",
  "jobs.undo.step_named",
  "jobs.view.active",
  "jobs.view.all",
  "jobs.view.failed",
  "jobs.view.finished",
  "languages.action.activate",
  "languages.action.discard",
  "languages.action.preview",
  "languages.action.remove",
  "languages.action.report",
  "languages.action.revert",
  "languages.action.template",
  "languages.action.template_of",
  "languages.action.template_short",
  "languages.activate.hint",
  "languages.built_in_texts",
  "languages.col.actions",
  "languages.col.active",
  "languages.col.candidate",
  "languages.col.language",
  "languages.col.status",
  "languages.confirm.activate.body",
  "languages.confirm.activate.ok",
  "languages.confirm.activate.title",
  "languages.confirm.discard.body",
  "languages.confirm.discard.ok",
  "languages.confirm.discard.title",
  "languages.confirm.remove.body",
  "languages.confirm.remove.ok",
  "languages.confirm.remove.title",
  "languages.confirm.revert.body",
  "languages.confirm.revert.ok",
  "languages.confirm.revert.title",
  "languages.lead",
  "languages.list.heading",
  "languages.none",
  "languages.origin.data_dir",
  "languages.preview.bar",
  "languages.preview.end",
  "languages.preview.open",
  "languages.report.at_line",
  "languages.report.author",
  "languages.report.col.key",
  "languages.report.col.line",
  "languages.report.col.problem",
  "languages.report.col.severity",
  "languages.report.complete",
  "languages.report.extra",
  "languages.report.heading",
  "languages.report.missing",
  "languages.report.more",
  "languages.report.none",
  "languages.report.problems",
  "languages.report.problems_label",
  "languages.report.stale",
  "languages.severity.error",
  "languages.severity.warning",
  "languages.status.active",
  "languages.status.built_in",
  "languages.status.previewed",
  "languages.status.uploaded",
  "languages.sub",
  "languages.title",
  "languages.toast.activated",
  "languages.toast.discarded",
  "languages.toast.preview",
  "languages.toast.removed",
  "languages.toast.reverted",
  "languages.upload.done",
  "languages.upload.file",
  "languages.upload.heading",
  "languages.upload.help",
  "languages.upload.submit",
  "languages.version.by",
  "languages.version.label",
  "languages.version.not_previewed",
  "languages.version.percent",
  "languages.version.previewed",
  "metrics.bars",
  "metrics.dhcp.ack",
  "metrics.dhcp.ack_hint",
  "metrics.dhcp.ack_idle",
  "metrics.dhcp.active",
  "metrics.dhcp.active_hint",
  "metrics.dhcp.ddns",
  "metrics.dhcp.ddns_hint",
  "metrics.dhcp.ddns_outcome.failed",
  "metrics.dhcp.ddns_outcome.refused",
  "metrics.dhcp.ddns_outcome.removed",
  "metrics.dhcp.ddns_outcome.written",
  "metrics.dhcp.decline_row",
  "metrics.dhcp.leases",
  "metrics.dhcp.leases_hint",
  "metrics.dhcp.nak_row",
  "metrics.dhcp.naks",
  "metrics.dhcp.naks_hint",
  "metrics.dhcp.pools",
  "metrics.dhcp.pools_hint",
  "metrics.dhcp.pools_none",
  "metrics.dns.answers",
  "metrics.dns.answers_hint",
  "metrics.dns.blocked",
  "metrics.dns.blocked_hint",
  "metrics.dns.blocked_none",
  "metrics.dns.cache",
  "metrics.dns.cache_hint",
  "metrics.dns.cache_window",
  "metrics.dns.encrypted",
  "metrics.dns.encrypted_hint",
  "metrics.dns.encrypted_none",
  "metrics.dns.log_dropped",
  "metrics.dns.queries",
  "metrics.dns.queries_hint",
  "metrics.dns.queries_idle",
  "metrics.dns.rate",
  "metrics.dns.rcode_other",
  "metrics.dns.subqueries",
  "metrics.dns.subqueries_hint",
  "metrics.dns.upstreams",
  "metrics.dns.upstreams_hint",
  "metrics.dns.upstreams_idle",
  "metrics.dns.validation",
  "metrics.dns.validation_bogus",
  "metrics.dns.validation_hint",
  "metrics.dns.validation_insecure",
  "metrics.dns.validation_secure",
  "metrics.group.controller",
  "metrics.group.dhcp",
  "metrics.group.dns",
  "metrics.group.host",
  "metrics.host.cpu",
  "metrics.host.cpu_hint",
  "metrics.host.cpu_none",
  "metrics.host.disk",
  "metrics.host.disk_hint",
  "metrics.host.disk_low",
  "metrics.host.disk_none",
  "metrics.host.memory",
  "metrics.host.memory_hint",
  "metrics.host.memory_none",
  "metrics.host.unit_gib",
  "metrics.raft.lag",
  "metrics.raft.node",
  "metrics.raft.stale",
  "metrics.raft.unsupported",
  "metrics.sparkline",
  "metrics.sub",
  "metrics.tile.commit",
  "metrics.tile.commit_hint",
  "metrics.tile.commit_idle",
  "metrics.tile.ingest",
  "metrics.tile.ingest_hint",
  "metrics.tile.jobs",
  "metrics.tile.jobs_hint",
  "metrics.tile.nodes",
  "metrics.tile.nodes_hint",
  "metrics.tile.nodes_hint_unknown",
  "metrics.tile.raft",
  "metrics.tile.raft_hint",
  "metrics.tile.requests",
  "metrics.tile.requests_hint",
  "metrics.tile.requests_idle",
  "metrics.tile.sse",
  "metrics.tile.sse_hint",
  "metrics.tile.store",
  "metrics.tile.store_hint",
  "metrics.tile.store_memory",
  "metrics.title",
  "metrics.unit.bytes",
  "metrics.unit.ms",
  "metrics.unit.per_second",
  "metrics.unit.percent",
  "metrics.waiting",
  "move.checklist",
  "move.checklist_foot",
  "move.checklist_sum",
  "move.col.device",
  "move.col.dns",
  "move.col.include",
  "move.col.ip",
  "move.col.l2",
  "move.col.manual",
  "move.confirm",
  "move.devices",
  "move.group.cleanup",
  "move.group.device_manual",
  "move.group.dhcp_manual",
  "move.group.dns_manual",
  "move.group.ipam_intent",
  "move.group.l2_move",
  "move.group.observe",
  "move.heading",
  "move.heading_vlan",
  "move.include",
  "move.included",
  "move.keys.include",
  "move.keys.move",
  "move.keys.steps",
  "move.l2.action.client_vlan",
  "move.l2.action.client_vlan_ssid",
  "move.l2.action.manual",
  "move.l2.action.port_profile",
  "move.l2.action.refused",
  "move.l2.action.shared",
  "move.l2.action.unchanged",
  "move.l2.controller",
  "move.l2.controller_read_only",
  "move.l2.diff",
  "move.l2.no_controller",
  "move.l2.note.carry_unknown",
  "move.l2.note.link_flap",
  "move.l2.note.no_undo",
  "move.l2.note.reconnect",
  "move.l2.note.tagged",
  "move.l2.reason.already_there",
  "move.l2.reason.controller_ambiguous",
  "move.l2.reason.controller_unavailable",
  "move.l2.reason.join_ssid",
  "move.l2.reason.no_controller",
  "move.l2.reason.no_mac",
  "move.l2.reason.no_network",
  "move.l2.reason.no_port",
  "move.l2.reason.no_profile",
  "move.l2.reason.no_ssid",
  "move.l2.reason.no_vlan",
  "move.l2.reason.not_seen",
  "move.l2.reason.read_only",
  "move.l2.reason.refused",
  "move.l2.reason.same_interface",
  "move.l2.reason.shared_port",
  "move.l2.ssids",
  "move.l2.through",
  "move.legend.auto",
  "move.legend.manual",
  "move.nothing",
  "move.open_jobs",
  "move.other_host_part",
  "move.parallelism",
  "move.parallelism_help",
  "move.phase1_body",
  "move.phase1_title",
  "move.plan_changed",
  "move.preview_only",
  "move.reason.host_part_outside",
  "move.reason.host_part_reserved",
  "move.reason.host_part_taken",
  "move.rollback_note",
  "move.show_all_steps",
  "move.show_steps",
  "move.start",
  "move.started",
  "move.step.cleanup",
  "move.step.device_manual",
  "move.step.dhcp_manual",
  "move.step.dhcp_manual_no_mac",
  "move.step.dns_manual",
  "move.step.ipam_intent",
  "move.step.l2_controller",
  "move.step.l2_move",
  "move.step.l2_move_novlan",
  "move.step.observe",
  "move.tasks",
  "move.tickets",
  "move.tickets_hint",
  "move.timeout",
  "move.timeout.default",
  "move.timeout.lease",
  "move.timeout.request",
  "move.timeout_auto",
  "move.title",
  "node.role.controller",
  "node.role.dhcp",
  "node.role.dns",
  "node.role.probe",
  "nodes.action.enrol",
  "nodes.cert.days_left",
  "nodes.cert.expired",
  "nodes.col.address",
  "nodes.col.certificate",
  "nodes.col.connected",
  "nodes.col.id",
  "nodes.col.last_seen",
  "nodes.col.major",
  "nodes.col.name",
  "nodes.col.roles",
  "nodes.col.version",
  "nodes.empty.body",
  "nodes.empty.title",
  "nodes.enrol.command",
  "nodes.enrol.copied_command",
  "nodes.enrol.copied_token",
  "nodes.enrol.copy_blocked",
  "nodes.enrol.copy_command",
  "nodes.enrol.copy_token",
  "nodes.enrol.create",
  "nodes.enrol.created_title",
  "nodes.enrol.done",
  "nodes.enrol.fingerprint",
  "nodes.enrol.fingerprint_help",
  "nodes.enrol.intro",
  "nodes.enrol.lifetime",
  "nodes.enrol.lifetime_help",
  "nodes.enrol.name",
  "nodes.enrol.name_help",
  "nodes.enrol.name_rule",
  "nodes.enrol.next",
  "nodes.enrol.once",
  "nodes.enrol.role_hint.dhcp",
  "nodes.enrol.role_hint.dns",
  "nodes.enrol.role_hint.probe",
  "nodes.enrol.roles",
  "nodes.enrol.roles_required",
  "nodes.enrol.title",
  "nodes.enrol.token",
  "nodes.enrol.vrf",
  "nodes.enrol.vrf_default",
  "nodes.enrol.vrf_help",
  "nodes.grid.label",
  "nodes.lifetime.s3600",
  "nodes.lifetime.s604800",
  "nodes.lifetime.s86400",
  "nodes.lifetime.s900",
  "nodes.link.connected",
  "nodes.link.disconnected",
  "nodes.link.mismatch",
  "nodes.mismatch",
  "nodes.panel.about",
  "nodes.panel.buffer",
  "nodes.panel.buffer_value",
  "nodes.panel.certificate",
  "nodes.panel.connection",
  "nodes.panel.dropped",
  "nodes.panel.enrolled",
  "nodes.panel.id",
  "nodes.panel.label",
  "nodes.panel.last_beat",
  "nodes.panel.major",
  "nodes.panel.mismatch",
  "nodes.panel.not_connected",
  "nodes.panel.peer",
  "nodes.panel.renewal_due",
  "nodes.panel.renewed",
  "nodes.panel.serial",
  "nodes.panel.since",
  "nodes.panel.valid",
  "nodes.panel.valid_range",
  "nodes.port_closed",
  "nodes.port_open",
  "nodes.revoke.action",
  "nodes.revoke.confirm",
  "nodes.revoke.confirm_body",
  "nodes.revoke.confirm_title",
  "nodes.revoke.done",
  "nodes.revoke.failed",
  "nodes.revoke.hint",
  "nodes.revoke.title",
  "nodes.roles.confirm",
  "nodes.roles.confirm_off",
  "nodes.roles.confirm_on",
  "nodes.roles.confirm_on_node",
  "nodes.roles.confirm_restart",
  "nodes.roles.confirm_title",
  "nodes.roles.finding.dns_resolver",
  "nodes.roles.finding.privileges",
  "nodes.roles.finding.unprepared",
  "nodes.roles.hint.controller",
  "nodes.roles.hint.dhcp",
  "nodes.roles.hint.dns",
  "nodes.roles.hint.probe",
  "nodes.roles.legend",
  "nodes.roles.lock.controller_only",
  "nodes.roles.lock.membership",
  "nodes.roles.lock.pinned",
  "nodes.roles.pinned",
  "nodes.roles.prepared.no",
  "nodes.roles.prepared.yes",
  "nodes.roles.reset",
  "nodes.roles.restart.back",
  "nodes.roles.restart.down",
  "nodes.roles.restart.late",
  "nodes.roles.restart.on_node",
  "nodes.roles.restart.required",
  "nodes.roles.restart.waiting",
  "nodes.roles.running",
  "nodes.roles.save",
  "nodes.roles.save_failed",
  "nodes.roles.saved",
  "nodes.roles.self_hint",
  "nodes.roles.self_title",
  "nodes.roles.title",
  "nodes.roles.unprepared",
  "nodes.scan.applied.active",
  "nodes.scan.applied.applied_at",
  "nodes.scan.applied.error",
  "nodes.scan.applied.exclude",
  "nodes.scan.applied.methods",
  "nodes.scan.applied.none",
  "nodes.scan.applied.origin",
  "nodes.scan.applied.origin_local",
  "nodes.scan.applied.origin_synced",
  "nodes.scan.applied.prefixes",
  "nodes.scan.applied.reported_at",
  "nodes.scan.applied.revision",
  "nodes.scan.applied.title",
  "nodes.scan.back",
  "nodes.scan.devices.actions",
  "nodes.scan.devices.add",
  "nodes.scan.devices.address",
  "nodes.scan.devices.auth",
  "nodes.scan.devices.auth_secret",
  "nodes.scan.devices.empty",
  "nodes.scan.devices.error",
  "nodes.scan.devices.help",
  "nodes.scan.devices.lacking",
  "nodes.scan.devices.name",
  "nodes.scan.devices.no_auth",
  "nodes.scan.devices.no_privacy",
  "nodes.scan.devices.no_secret",
  "nodes.scan.devices.port",
  "nodes.scan.devices.privacy",
  "nodes.scan.devices.privacy_secret",
  "nodes.scan.devices.remove",
  "nodes.scan.devices.row_label",
  "nodes.scan.devices.title",
  "nodes.scan.devices.user",
  "nodes.scan.dns.servers",
  "nodes.scan.dns.servers_help",
  "nodes.scan.error.cidr",
  "nodes.scan.error.entries",
  "nodes.scan.error.general",
  "nodes.scan.error.invalid",
  "nodes.scan.error.lines",
  "nodes.scan.error.min",
  "nodes.scan.error.port",
  "nodes.scan.error.type",
  "nodes.scan.error.unknown",
  "nodes.scan.field.active",
  "nodes.scan.field.active_help",
  "nodes.scan.field.blackout",
  "nodes.scan.field.blackout_help",
  "nodes.scan.field.concurrency",
  "nodes.scan.field.concurrency_help",
  "nodes.scan.field.enabled",
  "nodes.scan.field.enabled_help",
  "nodes.scan.field.exclude",
  "nodes.scan.field.exclude_help",
  "nodes.scan.field.max_hosts",
  "nodes.scan.field.max_hosts_help",
  "nodes.scan.field.per_host",
  "nodes.scan.field.per_host_help",
  "nodes.scan.field.pps",
  "nodes.scan.field.pps_help",
  "nodes.scan.field.prefixes",
  "nodes.scan.field.prefixes_help",
  "nodes.scan.field.rate",
  "nodes.scan.field.rate_help",
  "nodes.scan.field.timezone",
  "nodes.scan.field.timezone_help",
  "nodes.scan.field.vrf",
  "nodes.scan.field.vrf_help",
  "nodes.scan.form.failed",
  "nodes.scan.form.label",
  "nodes.scan.form.readonly",
  "nodes.scan.form.reload",
  "nodes.scan.form.remote",
  "nodes.scan.form.revert",
  "nodes.scan.form.saved",
  "nodes.scan.form.stale",
  "nodes.scan.form.title",
  "nodes.scan.group.general",
  "nodes.scan.group.methods",
  "nodes.scan.group.scope",
  "nodes.scan.ks.at",
  "nodes.scan.ks.by",
  "nodes.scan.ks.confirmed",
  "nodes.scan.ks.confirmed_no",
  "nodes.scan.ks.confirmed_yes",
  "nodes.scan.ks.reason",
  "nodes.scan.ks.resume",
  "nodes.scan.ks.running",
  "nodes.scan.ks.stop",
  "nodes.scan.ks.stopped",
  "nodes.scan.ks.title",
  "nodes.scan.lacking",
  "nodes.scan.lldp.cdp",
  "nodes.scan.lldp.cdp_help",
  "nodes.scan.llmnr.port",
  "nodes.scan.mdns.group",
  "nodes.scan.mdns.group_help",
  "nodes.scan.mdns.listen",
  "nodes.scan.mdns.listen_help",
  "nodes.scan.mdns.passive",
  "nodes.scan.mdns.passive_help",
  "nodes.scan.mdns.unicast_port",
  "nodes.scan.mdns.unicast_port_help",
  "nodes.scan.method.arp.help",
  "nodes.scan.method.arp.name",
  "nodes.scan.method.arp_sweep.help",
  "nodes.scan.method.arp_sweep.name",
  "nodes.scan.method.dhcp_snoop.help",
  "nodes.scan.method.dhcp_snoop.name",
  "nodes.scan.method.enabled",
  "nodes.scan.method.icmp.help",
  "nodes.scan.method.icmp.name",
  "nodes.scan.method.interval",
  "nodes.scan.method.interval_help",
  "nodes.scan.method.lldp.help",
  "nodes.scan.method.lldp.name",
  "nodes.scan.method.llmnr.help",
  "nodes.scan.method.llmnr.name",
  "nodes.scan.method.mdns.help",
  "nodes.scan.method.mdns.name",
  "nodes.scan.method.nd.help",
  "nodes.scan.method.nd.name",
  "nodes.scan.method.os_fingerprint.help",
  "nodes.scan.method.os_fingerprint.name",
  "nodes.scan.method.raw",
  "nodes.scan.method.reverse_dns.help",
  "nodes.scan.method.reverse_dns.name",
  "nodes.scan.method.snmp.help",
  "nodes.scan.method.snmp.name",
  "nodes.scan.method.tcp_connect.help",
  "nodes.scan.method.tcp_connect.name",
  "nodes.scan.method.tcp_syn.help",
  "nodes.scan.method.tcp_syn.name",
  "nodes.scan.method.timeout",
  "nodes.scan.method.timeout_help",
  "nodes.scan.method.ttl",
  "nodes.scan.method.ttl_help",
  "nodes.scan.node_fallback",
  "nodes.scan.not_probe.body",
  "nodes.scan.not_probe.missing",
  "nodes.scan.not_probe.title",
  "nodes.scan.panel.hint",
  "nodes.scan.panel.link",
  "nodes.scan.panel.title",
  "nodes.scan.rate.normal",
  "nodes.scan.rate.slow",
  "nodes.scan.rate.slowest",
  "nodes.scan.rate.unlimited",
  "nodes.scan.raw.interface",
  "nodes.scan.raw.interface_help",
  "nodes.scan.raw.listen",
  "nodes.scan.raw.listen_help",
  "nodes.scan.resume.done",
  "nodes.scan.resume.failed",
  "nodes.scan.self_off",
  "nodes.scan.snmp.lldp_ports",
  "nodes.scan.snmp.lldp_ports_help",
  "nodes.scan.snmp.retries",
  "nodes.scan.snmp.retries_help",
  "nodes.scan.stop.body",
  "nodes.scan.stop.done",
  "nodes.scan.stop.failed",
  "nodes.scan.stop.reason",
  "nodes.scan.stop.reason_help",
  "nodes.scan.stop.reason_too_long",
  "nodes.scan.stop.submit",
  "nodes.scan.stop.title",
  "nodes.scan.sync.in_sync",
  "nodes.scan.sync.not_in_sync",
  "nodes.scan.sync.not_stored",
  "nodes.scan.sync.origin",
  "nodes.scan.sync.origin_api",
  "nodes.scan.sync.origin_offer",
  "nodes.scan.sync.revision",
  "nodes.scan.sync.title",
  "nodes.scan.sync.updated_at",
  "nodes.scan.sync.updated_by",
  "nodes.scan.tcp.ports",
  "nodes.scan.tcp.ports_help",
  "nodes.scan.tcp.targets",
  "nodes.scan.tcp.targets_all",
  "nodes.scan.tcp.targets_help",
  "nodes.scan.tcp.targets_known",
  "nodes.scan.tcp.tls_hint",
  "nodes.scan.tcp.tls_hint_help",
  "nodes.scan.title",
  "nodes.scan.vrf.default",
  "nodes.summary",
  "nodes.token.any_name",
  "nodes.token.col.actions",
  "nodes.token.col.created",
  "nodes.token.col.expires",
  "nodes.token.col.name",
  "nodes.token.col.roles",
  "nodes.token.col.state",
  "nodes.token.col.used",
  "nodes.token.delete",
  "nodes.token.delete_done",
  "nodes.token.delete_failed",
  "nodes.token.delete_named",
  "nodes.token.delete_pending",
  "nodes.token.delete_title",
  "nodes.token.deleted",
  "nodes.token.hint",
  "nodes.token.none",
  "nodes.token.state.expired",
  "nodes.token.state.pending",
  "nodes.token.state.used",
  "nodes.token.title",
  "nodes.version_count",
  "nodes.versions",
  "prefs.density.comfortable",
  "prefs.density.compact",
  "prefs.density.dense",
  "prefs.theme.dark",
  "prefs.theme.light",
  "prefs.theme.system",
  "principal.node",
  "principal.system",
  "principal.token",
  "principal.user",
  "principal.you",
  "profile.hardened.description",
  "profile.hardened.name",
  "profile.home.description",
  "profile.home.name",
  "profile.lab.description",
  "profile.lab.name",
  "profile.standard.description",
  "profile.standard.name",
  "reconciler.error.invalid",
  "reconciler.error.range",
  "reconciler.error.refresh",
  "reconciler.field.adopt",
  "reconciler.field.debounce",
  "reconciler.field.interval",
  "reconciler.field.orphan",
  "reconciler.field.purge",
  "reconciler.field.refresh",
  "reconciler.field.retention",
  "reconciler.help.adopt",
  "reconciler.help.debounce",
  "reconciler.help.interval",
  "reconciler.help.orphan",
  "reconciler.help.purge",
  "reconciler.help.refresh",
  "reconciler.help.retention",
  "reconciler.lede",
  "reconciler.limits",
  "reconciler.reloaded",
  "reconciler.saved",
  "reconciler.title",
  "reconciler.unit.day",
  "reconciler.unit.hour",
  "reconciler.unit.minute",
  "reconciler.unit.second",
  "recovery.copied",
  "recovery.copy_failed",
  "recovery.download",
  "recovery.list_label",
  "recovery.print",
  "recovery.saved",
  "role.admin.description",
  "role.admin.name",
  "role.auditor.description",
  "role.auditor.name",
  "role.operator.description",
  "role.operator.name",
  "role.viewer.description",
  "role.viewer.name",
  "scans.action.back",
  "scans.action.resume_all",
  "scans.action.stop_all",
  "scans.change.changed",
  "scans.change.gone",
  "scans.change.new",
  "scans.change.unchanged",
  "scans.col.changes",
  "scans.col.created",
  "scans.col.finished",
  "scans.col.kinds",
  "scans.col.progress",
  "scans.col.requested_by",
  "scans.col.state",
  "scans.col.target",
  "scans.count",
  "scans.diff.col.after",
  "scans.diff.col.before",
  "scans.diff.col.change",
  "scans.diff.col.subject",
  "scans.diff.col.type",
  "scans.diff.empty",
  "scans.diff.heading",
  "scans.diff.items_label",
  "scans.diff.pending",
  "scans.diff.summary",
  "scans.diff.total",
  "scans.diff.totals_label",
  "scans.diff.truncated",
  "scans.diff.waiting",
  "scans.empty.body",
  "scans.empty.title",
  "scans.fact.address",
  "scans.fact.attachment",
  "scans.fact.link",
  "scans.fact.none",
  "scans.fact.os",
  "scans.fact.ports",
  "scans.fact.tls",
  "scans.fact_type.address",
  "scans.fact_type.attachment",
  "scans.fact_type.host",
  "scans.fact_type.link",
  "scans.fact_type.name",
  "scans.fact_type.os",
  "scans.fact_type.services",
  "scans.fact_type.vendor",
  "scans.kind.os_fingerprint",
  "scans.kind.passive_refresh",
  "scans.kind.port_scan",
  "scans.kind.snmp_poll",
  "scans.list.label",
  "scans.now.action",
  "scans.now.deadline",
  "scans.now.deadline_hint",
  "scans.now.follow",
  "scans.now.intro",
  "scans.now.kind.os_fingerprint",
  "scans.now.kind.passive_refresh",
  "scans.now.kind.port_scan",
  "scans.now.kind.snmp_poll",
  "scans.now.kinds",
  "scans.now.kinds_required",
  "scans.now.no_probe.many",
  "scans.now.no_probe.none",
  "scans.now.no_probe.one",
  "scans.now.refused_title",
  "scans.now.start",
  "scans.now.started",
  "scans.now.started_title",
  "scans.now.starting",
  "scans.now.title",
  "scans.part.col.command",
  "scans.part.col.detail",
  "scans.part.col.ingested",
  "scans.part.col.node",
  "scans.part.ingested",
  "scans.part.state.accepted",
  "scans.part.state.cancelled",
  "scans.part.state.done",
  "scans.part.state.expired",
  "scans.part.state.failed",
  "scans.part.state.pending",
  "scans.part.state.rejected",
  "scans.part.state.running",
  "scans.probe.col.config",
  "scans.probe.col.name",
  "scans.probe.col.scope",
  "scans.probe.col.switch",
  "scans.probe.col.sync",
  "scans.probe.config",
  "scans.probe.config_named",
  "scans.probe.in_process",
  "scans.probe.in_sync",
  "scans.probe.methods_none",
  "scans.probe.node_unnamed",
  "scans.probe.out_of_sync",
  "scans.probe.scope",
  "scans.probe.scope_none",
  "scans.probes.label",
  "scans.progress.label",
  "scans.progress.percent",
  "scans.section.jobs",
  "scans.section.probes",
  "scans.state.cancelled",
  "scans.state.done",
  "scans.state.failed",
  "scans.state.partial",
  "scans.state.queued",
  "scans.state.running",
  "scans.stop.body",
  "scans.stop.confirm",
  "scans.stop.reason",
  "scans.stop.reason_hint",
  "scans.stop.title",
  "scans.switch.active",
  "scans.switch.reason",
  "scans.switch.stopped",
  "scans.switch.unconfirmed",
  "scans.target.address",
  "scans.target.host",
  "scans.target.network",
  "scans.target.prefix",
  "scans.title",
  "scans.toast.resumed",
  "scans.toast.stopped",
  "scans.view.deadline",
  "scans.view.error",
  "scans.view.facts",
  "scans.view.loading",
  "scans.view.networks",
  "scans.view.not_found",
  "scans.view.not_found_title",
  "scans.view.probes",
  "scans.view.probes_label",
  "scans.view.tab",
  "scans.view.title",
  "secrets.action.create",
  "secrets.action.delete",
  "secrets.action.delete_named",
  "secrets.action.edit",
  "secrets.action.edit_named",
  "secrets.action.replace",
  "secrets.action.replace_named",
  "secrets.action.reveal",
  "secrets.action.reveal_named",
  "secrets.col.actions",
  "secrets.col.hosts",
  "secrets.col.kind",
  "secrets.col.name",
  "secrets.col.revealed",
  "secrets.col.tags",
  "secrets.col.updated",
  "secrets.col.user",
  "secrets.count",
  "secrets.count_filtered",
  "secrets.created",
  "secrets.delete.body",
  "secrets.delete.check_failed",
  "secrets.delete.confirm",
  "secrets.delete.in_use_hint",
  "secrets.delete.in_use_lead",
  "secrets.delete.in_use_title",
  "secrets.delete.title",
  "secrets.deleted",
  "secrets.detail.back",
  "secrets.detail.close",
  "secrets.detail.label",
  "secrets.empty",
  "secrets.empty_admin",
  "secrets.field.created",
  "secrets.field.notes",
  "secrets.field.origin",
  "secrets.field.value_updated",
  "secrets.filter.kind",
  "secrets.filter.kind_all",
  "secrets.filter.label",
  "secrets.filter.placeholder",
  "secrets.form.create_submit",
  "secrets.form.create_title",
  "secrets.form.edit_submit",
  "secrets.form.edit_title",
  "secrets.form.error.name_required",
  "secrets.form.error.value_required",
  "secrets.form.kind",
  "secrets.form.name",
  "secrets.form.name_help",
  "secrets.form.notes",
  "secrets.form.notes_help",
  "secrets.form.pin_enrol",
  "secrets.form.pin_title",
  "secrets.form.reload",
  "secrets.form.reloaded",
  "secrets.form.tags",
  "secrets.form.tags_help",
  "secrets.form.username",
  "secrets.form.username_help",
  "secrets.form.value",
  "secrets.form.value_cleared",
  "secrets.form.value_help",
  "secrets.form.value_key_help",
  "secrets.kind.api_key",
  "secrets.kind.other",
  "secrets.kind.password",
  "secrets.kind.ssh_key",
  "secrets.kind.token",
  "secrets.no_access.body",
  "secrets.no_access.title",
  "secrets.no_match",
  "secrets.no_user",
  "secrets.origin.import",
  "secrets.origin.manual",
  "secrets.refs.connector",
  "secrets.refs.connectors",
  "secrets.refs.deleted",
  "secrets.refs.hosts",
  "secrets.refs.none",
  "secrets.refs.role",
  "secrets.refs.title",
  "secrets.refs.unknown_host",
  "secrets.replace.field",
  "secrets.replace.lead",
  "secrets.replace.submit",
  "secrets.replace.title",
  "secrets.replaced",
  "secrets.reveal.audit",
  "secrets.reveal.clear_failed",
  "secrets.reveal.cleared",
  "secrets.reveal.copied",
  "secrets.reveal.copy",
  "secrets.reveal.copy_blocked",
  "secrets.reveal.hidden",
  "secrets.reveal.hide",
  "secrets.reveal.left",
  "secrets.reveal.show",
  "secrets.reveal.stepup.code_label",
  "secrets.reveal.stepup.continue",
  "secrets.reveal.stepup.fresh",
  "secrets.reveal.stepup.passkey",
  "secrets.reveal.stepup.password",
  "secrets.reveal.stepup.password_label",
  "secrets.reveal.stepup.title",
  "secrets.reveal.stepup.with_passkey",
  "secrets.reveal.title",
  "secrets.reveal.username",
  "secrets.reveal.value",
  "secrets.reveal.working",
  "secrets.revealed_by",
  "secrets.role.admin",
  "secrets.role.other",
  "secrets.role.rdp",
  "secrets.role.ssh",
  "secrets.role.web",
  "secrets.saved",
  "secrets.title",
  "settings.nav.access",
  "settings.nav.audit_export",
  "settings.nav.backup",
  "settings.nav.certificates",
  "settings.nav.dhcp",
  "settings.nav.dns",
  "settings.nav.guardrails",
  "settings.nav.label",
  "settings.nav.languages",
  "settings.nav.reconciler",
  "settings.nav.secrets",
  "settings.nav.security",
  "settings.nav.updates",
  "settings.nav.users",
  "settings.nav.vault",
  "settings.reloaded",
  "settings.security.audit_export.local",
  "settings.security.audit_export.local_help",
  "settings.security.audit_export.mode",
  "settings.security.audit_export.optional",
  "settings.security.audit_export.optional_help",
  "settings.security.audit_export.required",
  "settings.security.audit_export.required_help",
  "settings.security.col.actions",
  "settings.security.col.id",
  "settings.security.col.profile",
  "settings.security.col.setting",
  "settings.security.col.status",
  "settings.security.col.value",
  "settings.security.consequence.differs",
  "settings.security.consequence.matches",
  "settings.security.consequence.none",
  "settings.security.consequence.raised_clears",
  "settings.security.consequence.raised_lab",
  "settings.security.consequence.raised_others",
  "settings.security.consequence.weak_new",
  "settings.security.consequence.weak_stays",
  "settings.security.edit_row",
  "settings.security.edit_title",
  "settings.security.marker.differs",
  "settings.security.marker.follows",
  "settings.security.marker.weak",
  "settings.security.more",
  "settings.security.passkey.hint",
  "settings.security.policy.custom",
  "settings.security.policy.max",
  "settings.security.policy.max_error",
  "settings.security.policy.max_help",
  "settings.security.policy.min",
  "settings.security.policy.min_error",
  "settings.security.policy.min_help",
  "settings.security.policy.pattern",
  "settings.security.policy.pattern_error",
  "settings.security.policy.pattern_help",
  "settings.security.policy.preset",
  "settings.security.profile.change",
  "settings.security.profile.changes",
  "settings.security.profile.changes_table",
  "settings.security.profile.col_after",
  "settings.security.profile.col_now",
  "settings.security.profile.current",
  "settings.security.profile.deviations",
  "settings.security.profile.dialog_title",
  "settings.security.profile.heading",
  "settings.security.profile.lab_ack",
  "settings.security.profile.lab_body",
  "settings.security.profile.lab_tag",
  "settings.security.profile.lab_title",
  "settings.security.profile.lab_warning",
  "settings.security.profile.no_changes",
  "settings.security.profile.reset_done",
  "settings.security.profile.reset_to",
  "settings.security.profile.resets",
  "settings.security.profile.resets_same",
  "settings.security.profile.switch_done",
  "settings.security.profile.switch_to",
  "settings.security.profile.weak_body",
  "settings.security.profile.weak_warning",
  "settings.security.reset",
  "settings.security.reset_done",
  "settings.security.reset_row",
  "settings.security.save",
  "settings.security.saved",
  "settings.security.secret_reveal.bound_host",
  "settings.security.secret_reveal.bound_host_hint",
  "settings.security.secret_reveal.pin_rule",
  "settings.security.secret_reveal.step_up",
  "settings.security.secret_reveal.step_up_fresh",
  "settings.security.secret_reveal.step_up_fresh_help",
  "settings.security.secret_reveal.step_up_passkey",
  "settings.security.secret_reveal.step_up_passkey_help",
  "settings.security.secret_reveal.step_up_session",
  "settings.security.secret_reveal.step_up_session_help",
  "settings.security.session.absolute",
  "settings.security.session.absolute_help",
  "settings.security.session.idle",
  "settings.security.session.idle_help",
  "settings.security.session.number_error",
  "settings.security.session.order_error",
  "settings.security.toggles.heading",
  "settings.security.toggles.range",
  "settings.security.toggles.table",
  "settings.security.token.days",
  "settings.security.token.days_error",
  "settings.security.token.days_help",
  "settings.security.token.limited",
  "settings.security.token.unlimited_hint",
  "settings.security.unit.days",
  "settings.security.unit.hours",
  "settings.security.unit.label",
  "settings.security.unit.minutes",
  "settings.security.updates.check",
  "settings.security.updates.check_hint",
  "settings.security.updates.install",
  "settings.security.updates.install_ui",
  "settings.security.updates.install_ui_help",
  "settings.security.updates.install_ui_step_up",
  "settings.security.updates.install_ui_step_up_help",
  "settings.security.updates.install_upload_only",
  "settings.security.updates.install_upload_only_help",
  "settings.security.vault.body",
  "settings.security.vault.title",
  "settings.title",
  "settings.users.action.access",
  "settings.users.action.break_glass_make",
  "settings.users.action.break_glass_off",
  "settings.users.action.break_glass_on",
  "settings.users.action.break_glass_remove",
  "settings.users.action.delete",
  "settings.users.action.delete_help",
  "settings.users.action.details",
  "settings.users.action.details_help",
  "settings.users.action.disable",
  "settings.users.action.disable_help",
  "settings.users.action.edit",
  "settings.users.action.enable",
  "settings.users.action.enable_help",
  "settings.users.action.lock",
  "settings.users.action.own_delete",
  "settings.users.action.own_disable",
  "settings.users.action.password",
  "settings.users.action.password_break_glass",
  "settings.users.action.password_help",
  "settings.users.action.remove",
  "settings.users.action.roles",
  "settings.users.action.roles_break_glass",
  "settings.users.action.roles_help",
  "settings.users.action.sessions",
  "settings.users.action.sign_out",
  "settings.users.action.sign_out_help",
  "settings.users.action.unlock",
  "settings.users.action.unlock_help",
  "settings.users.actions",
  "settings.users.add.submit",
  "settings.users.add.title",
  "settings.users.add_button",
  "settings.users.added",
  "settings.users.back",
  "settings.users.break_glass.made",
  "settings.users.break_glass.make_body",
  "settings.users.break_glass.make_confirm",
  "settings.users.break_glass.make_title",
  "settings.users.break_glass.no_key",
  "settings.users.break_glass.remove_body",
  "settings.users.break_glass.remove_confirm",
  "settings.users.break_glass.remove_title",
  "settings.users.break_glass.removed",
  "settings.users.col.display_name",
  "settings.users.col.last_login",
  "settings.users.col.methods",
  "settings.users.col.name",
  "settings.users.col.roles",
  "settings.users.col.status",
  "settings.users.count",
  "settings.users.created",
  "settings.users.crumbs",
  "settings.users.delete.body",
  "settings.users.delete.confirm",
  "settings.users.delete.note",
  "settings.users.delete.title",
  "settings.users.deleted",
  "settings.users.disable.body",
  "settings.users.disable.confirm",
  "settings.users.disable.title",
  "settings.users.disabled",
  "settings.users.edit.submit",
  "settings.users.edit.title",
  "settings.users.enabled",
  "settings.users.error.display_required",
  "settings.users.error.name_length",
  "settings.users.error.name_required",
  "settings.users.error.name_spaces",
  "settings.users.error.password_required",
  "settings.users.error.roles_required",
  "settings.users.field.display_help",
  "settings.users.field.display_name",
  "settings.users.field.language",
  "settings.users.field.name",
  "settings.users.field.name_help",
  "settings.users.field.new_password",
  "settings.users.field.password",
  "settings.users.field.password_help",
  "settings.users.field.roles",
  "settings.users.methods.authenticator",
  "settings.users.methods.passkeys",
  "settings.users.methods.password",
  "settings.users.methods.recovery_codes",
  "settings.users.methods.security_keys",
  "settings.users.open",
  "settings.users.password.help",
  "settings.users.password.lead",
  "settings.users.password.submit",
  "settings.users.password.title",
  "settings.users.roles.own_admin",
  "settings.users.roles.submit",
  "settings.users.roles.title",
  "settings.users.saved_details",
  "settings.users.saved_password",
  "settings.users.saved_roles",
  "settings.users.sign_out.body",
  "settings.users.sign_out.confirm",
  "settings.users.sign_out.title",
  "settings.users.signed_out",
  "settings.users.status.active",
  "settings.users.status.break_glass",
  "settings.users.status.disabled",
  "settings.users.status.locked",
  "settings.users.status.locked_manual",
  "settings.users.status.password_change",
  "settings.users.table",
  "settings.users.unlocked",
  "settings.users.you",
  "setup.admin.check.breach",
  "setup.admin.check.breach_found",
  "setup.admin.check.breach_off",
  "setup.admin.check.breach_pending",
  "setup.admin.check.breach_pin",
  "setup.admin.check.breach_unavailable",
  "setup.admin.check.context",
  "setup.admin.check.state.bad",
  "setup.admin.check.state.idle",
  "setup.admin.check.state.off",
  "setup.admin.check.state.ok",
  "setup.admin.check.state.pending",
  "setup.admin.check.trivial",
  "setup.admin.codes_note",
  "setup.admin.lede",
  "setup.admin.name.help",
  "setup.admin.name.label",
  "setup.admin.passkey.help.hardened",
  "setup.admin.passkey.help.home",
  "setup.admin.passkey.help.lab",
  "setup.admin.passkey.help.standard",
  "setup.admin.passkey.title",
  "setup.admin.password.generate",
  "setup.admin.password.help.passphrase",
  "setup.admin.password.help.password",
  "setup.admin.password.help.pin",
  "setup.admin.password.help_generated",
  "setup.admin.password.hide",
  "setup.admin.password.label.passphrase",
  "setup.admin.password.label.password",
  "setup.admin.password.label.pin",
  "setup.admin.password.placeholder.passphrase",
  "setup.admin.password.placeholder.password",
  "setup.admin.password.placeholder.pin",
  "setup.admin.password.show",
  "setup.admin.user.help",
  "setup.admin.user.invalid",
  "setup.admin.user.label",
  "setup.admin.vault.body",
  "setup.admin.vault.title",
  "setup.banner.body",
  "setup.banner.review",
  "setup.banner.title",
  "setup.cluster.join",
  "setup.cluster.join_description",
  "setup.cluster.later",
  "setup.cluster.new",
  "setup.cluster.new_description",
  "setup.cluster.title",
  "setup.dhcp.address",
  "setup.dhcp.address_direct_help",
  "setup.dhcp.address_relay_help",
  "setup.dhcp.dns",
  "setup.dhcp.dns_help",
  "setup.dhcp.dns_placeholder",
  "setup.dhcp.hardened",
  "setup.dhcp.iface",
  "setup.dhcp.lease",
  "setup.dhcp.lease_unit",
  "setup.dhcp.lede",
  "setup.dhcp.listen",
  "setup.dhcp.listen.direct",
  "setup.dhcp.listen.direct_description",
  "setup.dhcp.listen.relay",
  "setup.dhcp.listen.relay_description",
  "setup.dhcp.mode",
  "setup.dhcp.mode.later",
  "setup.dhcp.mode.later_description",
  "setup.dhcp.mode.now",
  "setup.dhcp.mode.now_description",
  "setup.dhcp.network",
  "setup.dhcp.network_help",
  "setup.dhcp.node_networks",
  "setup.dhcp.others_off",
  "setup.dhcp.others_off_description",
  "setup.dhcp.pool_first",
  "setup.dhcp.pool_help",
  "setup.dhcp.pool_last",
  "setup.dhcp.privacy",
  "setup.dhcp.router",
  "setup.dhcp.router_help",
  "setup.dhcp.safety",
  "setup.dhcp.scope",
  "setup.dhcp.skipped",
  "setup.dhcp.summary",
  "setup.dhcp.unit.days",
  "setup.dhcp.unit.hours",
  "setup.dhcp.use_network",
  "setup.disk.contents",
  "setup.disk.detected",
  "setup.disk.free_aside",
  "setup.disk.fsync",
  "setup.disk.item.audit",
  "setup.disk.item.audit_contains",
  "setup.disk.item.audit_size",
  "setup.disk.item.keys",
  "setup.disk.item.keys_contains",
  "setup.disk.item.keys_size",
  "setup.disk.item.leases",
  "setup.disk.item.leases_contains",
  "setup.disk.item.leases_size",
  "setup.disk.item.store",
  "setup.disk.item.store_contains",
  "setup.disk.item.store_size",
  "setup.disk.lede",
  "setup.disk.media.hdd",
  "setup.disk.media.nvme",
  "setup.disk.media.smr",
  "setup.disk.media.ssd",
  "setup.disk.media.unknown",
  "setup.disk.media_free",
  "setup.disk.move",
  "setup.disk.move_path",
  "setup.disk.on",
  "setup.disk.override",
  "setup.disk.table.contains",
  "setup.disk.table.item",
  "setup.disk.table.label",
  "setup.disk.table.size",
  "setup.disk.tag.rotating",
  "setup.disk.tag.slow",
  "setup.disk.total_note",
  "setup.disk.total_size",
  "setup.disk.unknown",
  "setup.disk.warn.rotating_body",
  "setup.disk.warn.rotating_title",
  "setup.disk.warn.slow_body",
  "setup.disk.warn.slow_title",
  "setup.dns.cache",
  "setup.dns.cache_description",
  "setup.dns.check.capability",
  "setup.dns.check.firewall",
  "setup.dns.check.port",
  "setup.dns.check.role",
  "setup.dns.check.tls_ports",
  "setup.dns.checklist",
  "setup.dns.doh",
  "setup.dns.doh_description",
  "setup.dns.dot",
  "setup.dns.dot_description",
  "setup.dns.entries",
  "setup.dns.known",
  "setup.dns.lede",
  "setup.dns.log",
  "setup.dns.log_description",
  "setup.dns.preset",
  "setup.dns.preset_apply",
  "setup.dns.preset_help",
  "setup.dns.preset_on",
  "setup.dns.privacy",
  "setup.dns.resolve",
  "setup.dns.resolve.forward",
  "setup.dns.resolve.forward_description",
  "setup.dns.resolve.recurse",
  "setup.dns.resolve.recurse_description",
  "setup.dns.skipped",
  "setup.dns.tls_name",
  "setup.dns.tls_name_help",
  "setup.dns.transport",
  "setup.dns.transport.doh",
  "setup.dns.transport.doh_description",
  "setup.dns.transport.dot",
  "setup.dns.transport.dot_description",
  "setup.dns.transport.plain",
  "setup.dns.transport.plain_description",
  "setup.dns.upstreams",
  "setup.dns.upstreams_help",
  "setup.dns.upstreams_none",
  "setup.dns.use_dot",
  "setup.done.admin",
  "setup.done.change",
  "setup.done.change_item",
  "setup.done.choices",
  "setup.done.cluster",
  "setup.done.dhcp",
  "setup.done.dhcp_detail",
  "setup.done.dhcp_later",
  "setup.done.disk",
  "setup.done.disk_override",
  "setup.done.disk_unknown",
  "setup.done.dns",
  "setup.done.dns_none",
  "setup.done.dns_recurse",
  "setup.done.host",
  "setup.done.lab_note",
  "setup.done.lede",
  "setup.done.not_production",
  "setup.done.passkey",
  "setup.done.passkey_optional",
  "setup.done.passkey_required",
  "setup.done.probe_none",
  "setup.done.probe_on",
  "setup.done.profile",
  "setup.done.proxies",
  "setup.done.roles",
  "setup.footer.finish",
  "setup.footer.finishing",
  "setup.footer.open",
  "setup.gate.codes_ack",
  "setup.gate.codes_loading",
  "setup.gate.dhcp.address",
  "setup.gate.dhcp.dns",
  "setup.gate.dhcp.iface",
  "setup.gate.dhcp.lease",
  "setup.gate.dhcp.network",
  "setup.gate.dhcp.others_off",
  "setup.gate.dhcp.pool_first",
  "setup.gate.dhcp.pool_last",
  "setup.gate.dhcp.pool_order",
  "setup.gate.dhcp.router",
  "setup.gate.dhcp.router_in_pool",
  "setup.gate.disk",
  "setup.gate.display_name",
  "setup.gate.dns_entries",
  "setup.gate.dns_tls_name",
  "setup.gate.dns_upstreams",
  "setup.gate.host_empty",
  "setup.gate.host_invalid",
  "setup.gate.lab_ack",
  "setup.gate.modules_none",
  "setup.gate.passkey_required",
  "setup.gate.passkey_waiting",
  "setup.gate.password.passphrase",
  "setup.gate.password.password",
  "setup.gate.password.pin",
  "setup.gate.password_error",
  "setup.gate.password_pending",
  "setup.gate.password_policy",
  "setup.gate.probe_networks",
  "setup.gate.proxies_empty",
  "setup.gate.proxies_invalid",
  "setup.gate.roles_controller",
  "setup.gate.roles_none",
  "setup.gate.tls_plain",
  "setup.gate.token",
  "setup.gate.user_name",
  "setup.host.error.address",
  "setup.host.error.chars",
  "setup.host.error.empty",
  "setup.host.error.length",
  "setup.host.help",
  "setup.host.label",
  "setup.host.lede",
  "setup.host.placeholder",
  "setup.lab.ack",
  "setup.lab.enforced",
  "setup.lab.enforced.attribution",
  "setup.lab.enforced.audit",
  "setup.lab.enforced.secrets",
  "setup.lab.never_body",
  "setup.lab.never_title",
  "setup.lab.relax.breach",
  "setup.lab.relax.ddns",
  "setup.lab.relax.http",
  "setup.lab.relax.lockout",
  "setup.lab.relax.recursion",
  "setup.lab.relax.scan",
  "setup.lab.relax.tokens",
  "setup.lab.relaxes",
  "setup.lab.title",
  "setup.modules.aside",
  "setup.modules.dhcp.description",
  "setup.modules.dhcp.name",
  "setup.modules.discovery.description",
  "setup.modules.discovery.name",
  "setup.modules.dns.description",
  "setup.modules.dns.name",
  "setup.modules.ipam.description",
  "setup.modules.ipam.name",
  "setup.modules.later",
  "setup.modules.save_failed",
  "setup.modules.title",
  "setup.profile.group",
  "setup.profile.hint.hardened",
  "setup.profile.hint.home",
  "setup.profile.hint.lab",
  "setup.profile.hint.standard",
  "setup.profile.lede",
  "setup.profile.table.aside",
  "setup.profile.table.id",
  "setup.profile.table.label",
  "setup.profile.table.note",
  "setup.profile.table.setting",
  "setup.profile.table.title",
  "setup.profile.table.value",
  "setup.profile.weaker",
  "setup.result.ca.compare",
  "setup.result.ca.copied",
  "setup.result.ca.copy",
  "setup.result.ca.copy_failed",
  "setup.result.ca.help",
  "setup.result.ca.title",
  "setup.result.codes.deferred",
  "setup.result.codes.lede",
  "setup.result.codes.loading",
  "setup.result.codes.title",
  "setup.result.dhcp.config_help",
  "setup.result.dhcp.copied",
  "setup.result.dhcp.copy",
  "setup.result.dhcp.failed.options",
  "setup.result.dhcp.failed.pool",
  "setup.result.dhcp.failed.prefix",
  "setup.result.dhcp.failed.scope",
  "setup.result.dhcp.none",
  "setup.result.dhcp.open_scope",
  "setup.result.dhcp.saved",
  "setup.result.dhcp.title",
  "setup.result.dns.config_help",
  "setup.result.dns.copied",
  "setup.result.dns.copy",
  "setup.result.dns.copy_failed",
  "setup.result.dns.failed",
  "setup.result.dns.none",
  "setup.result.dns.recurse",
  "setup.result.dns.saved",
  "setup.result.dns.title",
  "setup.result.lede",
  "setup.result.next.connector_later",
  "setup.result.next.import",
  "setup.result.next.import_description",
  "setup.result.next.ipam",
  "setup.result.next.ipam_description",
  "setup.result.next.passkey_first",
  "setup.result.next.passkey_first_proxmox",
  "setup.result.next.passkey_first_unifi",
  "setup.result.next.proxmox",
  "setup.result.next.proxmox_description",
  "setup.result.next.title",
  "setup.result.next.unifi",
  "setup.result.next.unifi_description",
  "setup.result.passkey.add",
  "setup.result.passkey.added",
  "setup.result.passkey.help.hardened",
  "setup.result.passkey.help.home",
  "setup.result.passkey.help.lab",
  "setup.result.passkey.help.standard",
  "setup.result.passkey.title",
  "setup.result.passkey.unavailable",
  "setup.result.passkey.waiting",
  "setup.result.passkey_label",
  "setup.result.title",
  "setup.roles.controller.description",
  "setup.roles.dhcp.description",
  "setup.roles.dmz.note",
  "setup.roles.dmz.ticked",
  "setup.roles.dns.description",
  "setup.roles.group",
  "setup.roles.hint",
  "setup.roles.hint.hardened",
  "setup.roles.hint.home",
  "setup.roles.hint.lab",
  "setup.roles.hint.standard",
  "setup.roles.hint_probe",
  "setup.roles.lede",
  "setup.roles.memory",
  "setup.roles.memory_none",
  "setup.roles.memory_unknown_total",
  "setup.roles.probe.aside",
  "setup.roles.probe.description",
  "setup.roles.probe.none",
  "setup.roles.probe.title",
  "setup.step.admin.name",
  "setup.step.admin.title",
  "setup.step.dhcp.name",
  "setup.step.dhcp.title",
  "setup.step.disk.name",
  "setup.step.disk.title",
  "setup.step.dns.name",
  "setup.step.dns.title",
  "setup.step.done.name",
  "setup.step.done.title",
  "setup.step.host.name",
  "setup.step.host.title",
  "setup.step.profile.name",
  "setup.step.profile.title",
  "setup.step.roles.name",
  "setup.step.roles.title",
  "setup.step.welcome.name",
  "setup.step.welcome.title",
  "setup.stepno",
  "setup.steps.completed",
  "setup.steps.dhcp_later",
  "setup.steps.dhcp_skipped",
  "setup.steps.dns_meta",
  "setup.steps.dns_skipped",
  "setup.steps.item",
  "setup.steps.label",
  "setup.steps.roles_meta",
  "setup.title",
  "setup.tls.default",
  "setup.tls.imported.description",
  "setup.tls.imported.name",
  "setup.tls.internal_ca.description",
  "setup.tls.internal_ca.name",
  "setup.tls.passkey_note",
  "setup.tls.passkey_note_plain",
  "setup.tls.plain.description",
  "setup.tls.plain.disabled",
  "setup.tls.plain.name",
  "setup.tls.proxies.help",
  "setup.tls.proxies.invalid",
  "setup.tls.proxies.label",
  "setup.tls.reverse_proxy.description",
  "setup.tls.reverse_proxy.name",
  "setup.tls.title",
  "setup.welcome.cores",
  "setup.welcome.fact.address",
  "setup.welcome.fact.cpu",
  "setup.welcome.fact.memory",
  "setup.welcome.fact.node",
  "setup.welcome.fact.os",
  "setup.welcome.found",
  "setup.welcome.found_none",
  "setup.welcome.handy",
  "setup.welcome.handy.disk",
  "setup.welcome.handy.host",
  "setup.welcome.handy.passkey",
  "setup.welcome.lede",
  "setup.welcome.restore",
  "setup.welcome.restore_body",
  "setup.welcome.restore_link",
  "setup.welcome.restore_title",
  "setup.welcome.token.help",
  "setup.welcome.token.label",
  "setup.welcome.token.title",
  "shell.account.density",
  "shell.account.emphasis",
  "shell.account.emphasis_hint",
  "shell.account.language",
  "shell.account.language_auto",
  "shell.account.language_local",
  "shell.account.open",
  "shell.account.security",
  "shell.account.sign_out",
  "shell.account.theme",
  "shell.account.title",
  "shell.account.who",
  "shell.banner.break_glass_body",
  "shell.banner.break_glass_title",
  "shell.banner.fix",
  "shell.banner.lab_body",
  "shell.banner.lab_title",
  "shell.banner.mfa_required",
  "shell.banner.password_change",
  "shell.banner.review",
  "shell.banner.weak_body",
  "shell.banner.weak_title",
  "shell.brand.home",
  "shell.command.addresses",
  "shell.command.audit_verify",
  "shell.command.dashboard_hint",
  "shell.command.density_comfortable",
  "shell.command.density_compact",
  "shell.command.density_dense",
  "shell.command.emphasis_off",
  "shell.command.emphasis_on",
  "shell.command.hosts",
  "shell.command.import",
  "shell.command.secrets",
  "shell.command.shortcuts",
  "shell.command.theme_dark",
  "shell.command.theme_light",
  "shell.command.theme_system",
  "shell.command.updates",
  "shell.command.vlans",
  "shell.command.whats_new",
  "shell.dashboard.jobs",
  "shell.dashboard.no_roles",
  "shell.dashboard.node",
  "shell.dashboard.sub",
  "shell.dashboard.uptime",
  "shell.forbidden.body",
  "shell.forbidden.title",
  "shell.keys.cancel",
  "shell.keys.claim",
  "shell.keys.close_panel",
  "shell.keys.details",
  "shell.keys.edit",
  "shell.keys.expand",
  "shell.keys.export",
  "shell.keys.extend",
  "shell.keys.filter",
  "shell.keys.focus_grid",
  "shell.keys.focus_tree",
  "shell.keys.full_page",
  "shell.keys.goto",
  "shell.keys.job_panel",
  "shell.keys.lock",
  "shell.keys.mode",
  "shell.keys.move",
  "shell.keys.move_focus",
  "shell.keys.move_focus_alt",
  "shell.keys.note",
  "shell.keys.palette",
  "shell.keys.section.anywhere",
  "shell.keys.section.changes",
  "shell.keys.section.grids",
  "shell.keys.section.tree",
  "shell.keys.select_all",
  "shell.keys.select_row",
  "shell.keys.theme",
  "shell.keys.title",
  "shell.keys.undo",
  "shell.nav.audit",
  "shell.nav.cluster",
  "shell.nav.connectors",
  "shell.nav.dashboard",
  "shell.nav.dhcp",
  "shell.nav.discovery",
  "shell.nav.dns",
  "shell.nav.ipam",
  "shell.nav.jobs",
  "shell.nav.jobs_badge",
  "shell.nav.label",
  "shell.nav.nodes",
  "shell.nav.settings",
  "shell.nav.tooltip",
  "shell.nav.topology",
  "shell.notfound.body",
  "shell.notfound.home",
  "shell.notfound.title",
  "shell.palette.foot.commands",
  "shell.palette.foot.move",
  "shell.palette.foot.open",
  "shell.palette.group.actions",
  "shell.palette.group.goto",
  "shell.palette.group.preferences",
  "shell.palette.group.search",
  "shell.palette.label",
  "shell.palette.no_match",
  "shell.palette.no_match_hint",
  "shell.palette.placeholder",
  "shell.palette.search_all",
  "shell.palette.search_label",
  "shell.palette.searching",
  "shell.placeholder.body",
  "shell.placeholder.title",
  "shell.report.account",
  "shell.report.copy",
  "shell.report.copy_failed",
  "shell.report.failed",
  "shell.report.hardened",
  "shell.report.intro",
  "shell.report.loading",
  "shell.report.open",
  "shell.report.title",
  "shell.search.empty",
  "shell.search.kind.address",
  "shell.search.kind.host",
  "shell.search.kind.interface",
  "shell.search.kind.mac",
  "shell.search.kind.prefix",
  "shell.search.kind.range",
  "shell.search.kind.vlan",
  "shell.search.results",
  "shell.search.title",
  "shell.skip_to_content",
  "shell.splash",
  "shell.status.alarms",
  "shell.status.alarms_title",
  "shell.status.connecting",
  "shell.status.critical",
  "shell.status.idle",
  "shell.status.jobs_title",
  "shell.status.last_event",
  "shell.status.live",
  "shell.status.live_title",
  "shell.status.modules_restart",
  "shell.status.modules_restart_title",
  "shell.status.no_events",
  "shell.status.offline",
  "shell.status.proposals",
  "shell.status.reconnecting",
  "shell.status.running",
  "shell.status.selection",
  "shell.status.update",
  "shell.status.update_security",
  "shell.status.update_title",
  "shell.status.version",
  "shell.status.waiting",
  "shell.theme.change",
  "shell.theme.dark",
  "shell.theme.light",
  "shell.theme.mode.dark",
  "shell.theme.mode.light",
  "shell.theme.system",
  "shell.top.command_hint",
  "shell.top.command_open",
  "shell.top.node",
  "shell.top.node_title",
  "shell.top.node_unreachable",
  "shell.top.profile",
  "shell.top.profile_title",
  "shell.top.role.candidate",
  "shell.top.role.follower",
  "shell.top.role.leader",
  "shell.top.role.learner",
  "shell.top.role.memory",
  "shell.top.role.shutdown",
  "shell.top.role.unknown",
  "shell.top.shortcuts_title",
  "toggles.audit_export.local",
  "toggles.audit_export.name",
  "toggles.audit_export.optional",
  "toggles.audit_export.required",
  "toggles.breach_check.name",
  "toggles.breach_check.off",
  "toggles.breach_check.offline",
  "toggles.breach_check.offline_preferred",
  "toggles.breach_check.online",
  "toggles.lockout.delay_then_temporary_lock",
  "toggles.lockout.lock_until_unlock",
  "toggles.lockout.name",
  "toggles.lockout.off",
  "toggles.lockout.progressive_delay",
  "toggles.mfa.administrators",
  "toggles.mfa.everyone",
  "toggles.mfa.name",
  "toggles.mfa.optional",
  "toggles.passkey_for_admins.name",
  "toggles.password_policy.custom",
  "toggles.password_policy.hardened",
  "toggles.password_policy.name",
  "toggles.password_policy.pin",
  "toggles.password_policy.standard",
  "toggles.secret_reveal.name",
  "toggles.secret_reveal.step_up.fresh",
  "toggles.secret_reveal.step_up.passkey",
  "toggles.secret_reveal.step_up.session",
  "toggles.secret_reveal.value",
  "toggles.session.name",
  "toggles.session.value",
  "toggles.token_max_days.days",
  "toggles.token_max_days.name",
  "toggles.token_max_days.unlimited",
  "toggles.updates.check_off",
  "toggles.updates.check_on",
  "toggles.updates.install.ui",
  "toggles.updates.install.ui_step_up",
  "toggles.updates.install.upload_only",
  "toggles.updates.name",
  "toggles.updates.value",
  "topology.controller.error_generic",
  "topology.controller.label",
  "topology.controller.ok",
  "topology.edge.lldp",
  "topology.edge.uplink",
  "topology.edge.vm_host",
  "topology.edge.wired",
  "topology.edge.wireless",
  "topology.empty.body",
  "topology.empty.filtered",
  "topology.empty.filtered_hint",
  "topology.empty.link",
  "topology.empty.title",
  "topology.filter.clear",
  "topology.filter.label",
  "topology.filter.placeholder",
  "topology.filter.site",
  "topology.filter.site_all",
  "topology.filter.unknown_site",
  "topology.filter.unknown_vlan",
  "topology.filter.vlan",
  "topology.filter.vlan_all",
  "topology.group.aria",
  "topology.group.close_all",
  "topology.group.label",
  "topology.kind.access_point",
  "topology.kind.container",
  "topology.kind.device",
  "topology.kind.host",
  "topology.kind.hypervisor",
  "topology.kind.router",
  "topology.kind.switch",
  "topology.kind.vm",
  "topology.legend.edges",
  "topology.legend.kinds",
  "topology.legend.label",
  "topology.legend.too_many",
  "topology.legend.vlans",
  "topology.legend.vlans_none",
  "topology.loading",
  "topology.map.label",
  "topology.neighbour.local",
  "topology.neighbour.remote",
  "topology.neighbour.ssid",
  "topology.networks.dhcp.disabled",
  "topology.networks.dhcp.relay",
  "topology.networks.dhcp.server",
  "topology.networks.management",
  "topology.networks.no_subnet",
  "topology.networks.none",
  "topology.networks.summary",
  "topology.networks.title",
  "topology.networks.untagged",
  "topology.node.aria",
  "topology.panel.back",
  "topology.panel.details",
  "topology.panel.host_link",
  "topology.panel.intent",
  "topology.panel.intent_addresses",
  "topology.panel.intent_no_addresses",
  "topology.panel.intent_none",
  "topology.panel.ips",
  "topology.panel.label",
  "topology.panel.last_seen",
  "topology.panel.macs",
  "topology.panel.model",
  "topology.panel.neighbours",
  "topology.panel.neighbours_none",
  "topology.panel.observation_link",
  "topology.panel.os",
  "topology.panel.paths",
  "topology.panel.ports",
  "topology.panel.ports_none",
  "topology.panel.sources",
  "topology.panel.ssids",
  "topology.panel.vendor",
  "topology.panel.vlans",
  "topology.path.clear",
  "topology.path.from",
  "topology.path.is_router",
  "topology.path.no_route",
  "topology.path.none",
  "topology.path.router",
  "topology.path.show",
  "topology.path.start",
  "topology.path.start_here",
  "topology.port.connected",
  "topology.port.count",
  "topology.port.down",
  "topology.port.hide",
  "topology.port.hide_aria",
  "topology.port.nothing",
  "topology.port.open",
  "topology.port.open_aria",
  "topology.port.unknown",
  "topology.port.up",
  "topology.port.uplink",
  "topology.port.vlan",
  "topology.source.intent",
  "topology.source.inventory",
  "topology.source.network_controller",
  "topology.source.probe",
  "topology.summary",
  "topology.truncated",
  "topology.zoom.fit",
  "topology.zoom.in",
  "topology.zoom.label",
  "topology.zoom.out",
  "updates.attempt.failed",
  "updates.attempt.rolled_back",
  "updates.blocked.air_gapped",
  "updates.blocked.cluster",
  "updates.blocked.container",
  "updates.blocked.in_progress",
  "updates.blocked.layout_missing",
  "updates.blocked.no_asset",
  "updates.blocked.other",
  "updates.blocked.settings_link",
  "updates.blocked.unsupervised",
  "updates.blocked.unsupported_platform",
  "updates.blocked.up_to_date",
  "updates.blocked.upload_only",
  "updates.check.checking",
  "updates.check.error",
  "updates.check.found",
  "updates.check.heading",
  "updates.check.last",
  "updates.check.never",
  "updates.check.none",
  "updates.check.now",
  "updates.check.off_air_gapped",
  "updates.check.off_setting",
  "updates.check.on",
  "updates.check.settings_link",
  "updates.check.source",
  "updates.check.state",
  "updates.code_unknown",
  "updates.install.blocked_title",
  "updates.install.button",
  "updates.install.confirm_action",
  "updates.install.confirm_body",
  "updates.install.confirm_ok",
  "updates.install.confirm_security",
  "updates.install.confirm_title",
  "updates.install.confirm_upload",
  "updates.install.copy_failed",
  "updates.install.heading",
  "updates.install.lead",
  "updates.install.pull_lead",
  "updates.install.step_up_hint",
  "updates.install.up_to_date",
  "updates.manifest.fetched",
  "updates.manifest.heading",
  "updates.manifest.uploaded",
  "updates.mark.action",
  "updates.mark.security",
  "updates.module.body",
  "updates.module.home",
  "updates.module.name.dhcp",
  "updates.module.name.discovery",
  "updates.module.name.dns",
  "updates.module.name.ipam",
  "updates.module.title",
  "updates.progress.failed",
  "updates.progress.failed_unknown",
  "updates.progress.heading",
  "updates.progress.job_link",
  "updates.release.action_title",
  "updates.release.action_unspecified",
  "updates.release.format",
  "updates.release.newest",
  "updates.release.no_notes",
  "updates.release.title",
  "updates.releases.count",
  "updates.releases.heading",
  "updates.releases.none",
  "updates.restart.body",
  "updates.restart.check_log",
  "updates.restart.check_previous",
  "updates.restart.check_service",
  "updates.restart.confirmed",
  "updates.restart.reason",
  "updates.restart.reload",
  "updates.restart.rolled_back",
  "updates.restart.timeout_body",
  "updates.restart.timeout_title",
  "updates.restart.title",
  "updates.running.format",
  "updates.running.heading",
  "updates.running.newest",
  "updates.running.platform",
  "updates.running.up_to_date",
  "updates.running.version",
  "updates.stepup.body",
  "updates.stepup.button",
  "updates.stepup.title",
  "updates.sub",
  "updates.title",
  "updates.unavailable",
  "updates.upload.button",
  "updates.upload.chosen",
  "updates.upload.expected",
  "updates.upload.file_label",
  "updates.upload.heading",
  "updates.upload.lead",
  "updates.upload.manifest_button",
  "updates.upload.manifest_done",
  "updates.upload.manifest_help",
  "updates.upload.manifest_label",
  "updates.upload.need_manifest",
  "updates.upload.uploading",
  "updates.upload.version_label",
  "updates.whatsnew.close",
  "updates.whatsnew.empty",
  "updates.whatsnew.lead",
  "updates.whatsnew.lead_first",
  "updates.whatsnew.title",
  "vault.controllers.col.node",
  "vault.controllers.col.updated",
  "vault.controllers.heading",
  "vault.downgrade",
  "vault.generations.active",
  "vault.generations.col.created",
  "vault.generations.col.id",
  "vault.generations.col.state",
  "vault.generations.heading",
  "vault.generations.loaded",
  "vault.generations.missing",
  "vault.key.active",
  "vault.key.epoch",
  "vault.key.heading",
  "vault.key.protection",
  "vault.key.provider",
  "vault.key.strongest",
  "vault.lede",
  "vault.phase.distributing",
  "vault.phase.done",
  "vault.phase.failed",
  "vault.phase.requested",
  "vault.phase.rewrapping",
  "vault.protection.dpapi_machine",
  "vault.protection.dpapi_user",
  "vault.protection.memory",
  "vault.protection.plain_file",
  "vault.protection.systemd_creds_host",
  "vault.protection.systemd_creds_tpm2",
  "vault.provider.dpapi",
  "vault.provider.file",
  "vault.provider.systemd_credential",
  "vault.provider.systemd_creds",
  "vault.refused.title",
  "vault.rotation.confirm_body",
  "vault.rotation.confirm_note",
  "vault.rotation.confirm_title",
  "vault.rotation.error",
  "vault.rotation.finished_at",
  "vault.rotation.generation",
  "vault.rotation.heading",
  "vault.rotation.lede",
  "vault.rotation.never",
  "vault.rotation.phase",
  "vault.rotation.requested",
  "vault.rotation.requested_at",
  "vault.rotation.rewrapped",
  "vault.rotation.rotate",
  "vault.rotation.unreachable",
  "vault.rotation.unreachable_text",
  "vault.rotation.waiting_for",
  "vault.step_up.body",
  "vault.step_up.sign_in",
  "vault.step_up.title",
  "vault.title",
  "vault.warning.downgrade",
  "vault.warning.missing",
  "vault.warning.rotation_failed",
  "vault.warning.weak",
  "vault.weak",
];
