// Message keys of ui/i18n/en.xlf. Regenerate with `npm run i18n`; do not edit.
export type MessageKey =
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
  | "dashboard.action.claim"
  | "dashboard.action.claim_where"
  | "dashboard.action.import"
  | "dashboard.action.prefix"
  | "dashboard.alarms.none"
  | "dashboard.alarms.title"
  | "dashboard.audit.all"
  | "dashboard.audit.none"
  | "dashboard.audit.title"
  | "dashboard.palette_hint"
  | "dashboard.tile.addresses"
  | "dashboard.tile.addresses_of"
  | "dashboard.tile.alarms"
  | "dashboard.tile.alarms_hint"
  | "dashboard.tile.waiting_for_you"
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
  | "errors.generic.client"
  | "errors.generic.field"
  | "errors.generic.not_implemented"
  | "errors.generic.server"
  | "errors.generic.unexpected"
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
  | "errors.ipam.move.host_part_taken"
  | "errors.ipam.move.unmanaged"
  | "errors.ipam.name_taken"
  | "errors.ipam.not_deleted"
  | "errors.ipam.not_found"
  | "errors.ipam.object_deleted"
  | "errors.ipam.parent_status"
  | "errors.ipam.plan.stale"
  | "errors.ipam.plan.unacknowledged"
  | "errors.ipam.prefix.full"
  | "errors.ipam.prefix.has_children"
  | "errors.ipam.prefix.has_ranges"
  | "errors.ipam.prefix.host_bits"
  | "errors.ipam.prefix.nibble_boundary"
  | "errors.ipam.prefix.overlap"
  | "errors.ipam.prefix.overlaps_range"
  | "errors.ipam.prefix.resize_orphans"
  | "errors.ipam.range.covers_reservation"
  | "errors.ipam.range.not_in_network"
  | "errors.ipam.range.outside_prefix"
  | "errors.ipam.range.overlap"
  | "errors.ipam.reference_missing"
  | "errors.ipam.revision_mismatch"
  | "errors.ipam.site.cycle"
  | "errors.ipam.status.transition"
  | "errors.ipam.unavailable"
  | "errors.ipam.validation"
  | "errors.ipam.vlan.duplicate"
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
  | "errors.users.last_administrator"
  | "errors.users.name_taken"
  | "errors.users.not_found"
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
  | "hosts.addresses.none"
  | "hosts.addresses.title"
  | "hosts.bulk.lock_title"
  | "hosts.bulk.mode_title"
  | "hosts.bulk.unlock_title"
  | "hosts.col.addresses"
  | "hosts.col.client_id"
  | "hosts.col.duid"
  | "hosts.col.interface"
  | "hosts.connect.hint"
  | "hosts.connect.rdp"
  | "hosts.connect.rdp_port"
  | "hosts.connect.ssh"
  | "hosts.connect.ssh_port"
  | "hosts.connect.target"
  | "hosts.connect.title"
  | "hosts.connect.user"
  | "hosts.crumbs"
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
  | "import.credentials.reason.forbidden"
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
  | "import.preview.summary"
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
  | "ipam.move.step.intent"
  | "ipam.move.task.device"
  | "ipam.move.task.dhcp"
  | "ipam.move.task.dns"
  | "ipam.move.task.generic"
  | "ipam.move.task.l2"
  | "ipam.move.task.observe"
  | "ipam.move.title"
  | "ipam.nav.addresses"
  | "ipam.nav.custom_fields"
  | "ipam.nav.hosts"
  | "ipam.nav.import"
  | "ipam.nav.label"
  | "ipam.nav.networks"
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
  | "ipam.prefix.in_several"
  | "ipam.prefix.no_children"
  | "ipam.prefix.not_found"
  | "ipam.prefix.ranges_grid"
  | "ipam.prefix.tab.addresses"
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
  | "jobs.step.dns_manual"
  | "jobs.step.import_apply_chunk"
  | "jobs.step.import_parse"
  | "jobs.step.import_plan"
  | "jobs.step.ipam_apply"
  | "jobs.step.ipam_intent"
  | "jobs.step.l2_move"
  | "jobs.step.observe"
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
  | "jobs.stepname.ipam_move_device"
  | "jobs.stepname.ipam_move_dhcp"
  | "jobs.stepname.ipam_move_dns"
  | "jobs.stepname.ipam_move_intent"
  | "jobs.stepname.ipam_move_l2"
  | "jobs.stepname.ipam_move_observe"
  | "jobs.stepname.l2_move"
  | "jobs.stepname.observe"
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
  | "jobs.title.import_apply"
  | "jobs.title.ipam_apply"
  | "jobs.title.move"
  | "jobs.undo.step"
  | "jobs.view.active"
  | "jobs.view.all"
  | "jobs.view.failed"
  | "jobs.view.finished"
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
  | "move.legend.auto"
  | "move.legend.manual"
  | "move.nothing"
  | "move.open_jobs"
  | "move.other_host_part"
  | "move.parallelism"
  | "move.parallelism_help"
  | "move.phase1_body"
  | "move.phase1_title"
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
  | "recovery.copied"
  | "recovery.copy_failed"
  | "recovery.download"
  | "recovery.list_label"
  | "recovery.print"
  | "recovery.saved"
  | "role.admin.description"
  | "role.admin.name"
  | "role.operator.description"
  | "role.operator.name"
  | "role.viewer.description"
  | "role.viewer.name"
  | "settings.nav.label"
  | "settings.nav.security"
  | "settings.nav.users"
  | "settings.reloaded"
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
  | "setup.done.admin"
  | "setup.done.change"
  | "setup.done.change_item"
  | "setup.done.choices"
  | "setup.done.cluster"
  | "setup.done.disk"
  | "setup.done.disk_override"
  | "setup.done.disk_unknown"
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
  | "setup.gate.disk"
  | "setup.gate.display_name"
  | "setup.gate.host_empty"
  | "setup.gate.host_invalid"
  | "setup.gate.lab_ack"
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
  | "setup.step.disk.name"
  | "setup.step.disk.title"
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
  | "shell.command.shortcuts"
  | "shell.command.theme_dark"
  | "shell.command.theme_light"
  | "shell.command.theme_system"
  | "shell.command.vlans"
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
  | "shell.nav.dashboard"
  | "shell.nav.dhcp"
  | "shell.nav.dns"
  | "shell.nav.ipam"
  | "shell.nav.jobs"
  | "shell.nav.jobs_badge"
  | "shell.nav.label"
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
  | "shell.status.no_events"
  | "shell.status.offline"
  | "shell.status.reconnecting"
  | "shell.status.running"
  | "shell.status.selection"
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
  | "toggles.session.name"
  | "toggles.session.value"
  | "toggles.token_max_days.days"
  | "toggles.token_max_days.name"
  | "toggles.token_max_days.unlimited";
/** Arguments of the messages that take any. */
export interface MessageArgs {
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
  "auth.signin.retry_in": { seconds: number };
  "common.count.items": { count: number };
  "common.greeting": { name: string | number };
  "dashboard.tile.alarms_hint": { critical: number };
  "dashboard.tile.waiting_for_you": { count: number };
  "dashboard.use.more": { count: number };
  "dashboard.use.vrf": { tenant: string | number; vrf: string | number };
  "dashboard.waiting.step": { step: number; total: number };
  "errors.auth.password.too_long": { max: string | number };
  "errors.auth.password.too_short": { min: string | number };
  "errors.auth.setup.invalid_host_name": { host_name: string | number };
  "errors.auth.throttled": { retry_after: string | number };
  "errors.auth.token.lifetime_exceeded": { max_days: string | number };
  "errors.client.bad_response": { status: string | number };
  "errors.ipam.address.duplicate": { ip: string | number };
  "errors.ipam.address.full": { cidr: string | number };
  "errors.ipam.address.in_dhcp_pool": { ip: string | number; range: string | number };
  "errors.ipam.address.network_or_broadcast": { cidr: string | number; ip: string | number };
  "errors.ipam.address.no_prefix": { ip: string | number };
  "errors.ipam.bulk.too_large": { count: number; limit: number };
  "errors.ipam.bulk.wrong_collection": { index: string | number };
  "errors.ipam.host.locked": { host: string | number };
  "errors.ipam.immutable": { field: string | number };
  "errors.ipam.in_use": { count: number; kind: string | number };
  "errors.ipam.invalid_filter": { name: string | number };
  "errors.ipam.name_taken": { name: string | number };
  "errors.ipam.not_deleted": { kind: string | number };
  "errors.ipam.not_found": { kind: string | number };
  "errors.ipam.object_deleted": { kind: string | number };
  "errors.ipam.plan.unacknowledged": { codes: string | number };
  "errors.ipam.prefix.full": { cidr: string | number; length: string | number };
  "errors.ipam.prefix.has_children": { cidr: string | number };
  "errors.ipam.prefix.has_ranges": { cidr: string | number };
  "errors.ipam.prefix.host_bits": { cidr: string | number; network: string | number };
  "errors.ipam.prefix.overlap": { cidr: string | number; existing: string | number };
  "errors.ipam.prefix.overlaps_range": { range: string | number };
  "errors.ipam.range.covers_reservation": { host: string | number; ip: string | number };
  "errors.ipam.range.not_in_network": { cidr: string | number };
  "errors.ipam.range.outside_prefix": { cidr: string | number };
  "errors.ipam.range.overlap": { existing: string | number };
  "errors.ipam.reference_missing": { kind: string | number };
  "errors.ipam.revision_mismatch": { kind: string | number };
  "errors.ipam.status.transition": { from: string | number; to: string | number };
  "errors.ipam.vlan.duplicate": { vid: string | number };
  "grid.actionbar.selected": { count: number };
  "grid.columns.move_down": { column: string | number };
  "grid.columns.move_up": { column: string | number };
  "grid.filter.invalid": { field: string | number; value: string | number };
  "grid.row_actions": { row: string | number };
  "grid.rows": { count: number };
  "grid.select_row": { row: string | number };
  "grid.selected": { count: number };
  "hosts.bulk.lock_title": { count: number };
  "hosts.bulk.mode_title": { count: number; mode: string | number };
  "hosts.bulk.unlock_title": { count: number };
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
  "ipam.move.step.intent": { new_ip: string | number; old_ip: string | number };
  "ipam.move.task.device": { cidr: string | number; new_ip: string | number };
  "ipam.move.task.dhcp": { cidr: string | number; new_ip: string | number };
  "ipam.move.task.dns": { name: string | number; new_ip: string | number };
  "ipam.move.task.generic": { cidr: string | number; new_ip: string | number; old_ip: string | number };
  "ipam.move.task.l2": { cidr: string | number };
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
  "ipam.restore.done": { kind: string | number; label: string | number };
  "ipam.restore.title": { kind: string | number; label: string | number };
  "ipam.scope.option": { tenant: string | number; vrf: string | number };
  "ipam.site.edit_title": { name: string | number };
  "ipam.tenancy.created": { name: string | number };
  "ipam.tenancy.saved": { name: string | number };
  "ipam.tenant.edit_title": { name: string | number };
  "ipam.tree.drop_hint": { cidr: string | number; count: number };
  "ipam.vlan.edit_title": { vid: string | number };
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
  "jobs.group.summary": { count: number };
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
  "move.step.l2_move": { host: string | number; vid: string | number };
  "move.step.l2_move_novlan": { cidr: string | number; host: string | number };
  "move.step.observe": { host: string | number; ip: string | number };
  "move.tasks": { count: number };
  "move.timeout.default": { timeout: string | number };
  "move.timeout.lease": { lease: string | number; timeout: string | number };
  "move.timeout.request": { timeout: string | number };
  "move.timeout_auto": { timeout: string | number };
  "principal.node": { id: string | number };
  "principal.system": { component: string | number };
  "principal.token": { id: string | number };
  "principal.user": { id: string | number };
  "principal.you": { name: string | number };
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
  "setup.disk.free_aside": { size: string | number };
  "setup.disk.fsync": { time: string | number };
  "setup.disk.media_free": { media: string | number; size: string | number };
  "setup.disk.move": { command: string | number };
  "setup.done.change_item": { item: string | number };
  "setup.done.probe_on": { networks: string | number };
  "setup.done.proxies": { count: number };
  "setup.host.placeholder": { name: string | number };
  "setup.profile.lede": { total: string | number };
  "setup.profile.table.aside": { shown: string | number; total: string | number };
  "setup.profile.table.title": { profile: string | number };
  "setup.result.codes.lede": { user: string | number };
  "setup.roles.hint": { amount: string | number };
  "setup.roles.hint_probe": { amount: string | number };
  "setup.roles.memory": { amount: string | number; total: string | number };
  "setup.roles.memory_unknown_total": { amount: string | number };
  "setup.stepno": { step: string | number; total: string | number };
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
  "shell.search.results": { count: number; query: string | number };
  "shell.status.alarms": { count: number };
  "shell.status.critical": { count: number };
  "shell.status.last_event": { ago: string | number };
  "shell.status.running": { count: number };
  "shell.status.selection": { selected: number; total: number };
  "shell.status.version": { version: string | number };
  "shell.status.waiting": { count: number };
  "shell.theme.change": { current: string | number };
  "shell.theme.system": { mode: string | number };
  "shell.top.node_title": { lag: number; revision: string | number };
  "shell.top.profile": { profile: string | number };
  "shell.top.profile_title": { profile: string | number };
  "toggles.password_policy.custom": { min: string | number };
  "toggles.session.value": { absolute: string | number; idle: string | number };
  "toggles.token_max_days.days": { days: number };
}
export const messageKeys: readonly MessageKey[] = [
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
  "dashboard.action.claim",
  "dashboard.action.claim_where",
  "dashboard.action.import",
  "dashboard.action.prefix",
  "dashboard.alarms.none",
  "dashboard.alarms.title",
  "dashboard.audit.all",
  "dashboard.audit.none",
  "dashboard.audit.title",
  "dashboard.palette_hint",
  "dashboard.tile.addresses",
  "dashboard.tile.addresses_of",
  "dashboard.tile.alarms",
  "dashboard.tile.alarms_hint",
  "dashboard.tile.waiting_for_you",
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
  "errors.generic.client",
  "errors.generic.field",
  "errors.generic.not_implemented",
  "errors.generic.server",
  "errors.generic.unexpected",
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
  "errors.ipam.move.host_part_taken",
  "errors.ipam.move.unmanaged",
  "errors.ipam.name_taken",
  "errors.ipam.not_deleted",
  "errors.ipam.not_found",
  "errors.ipam.object_deleted",
  "errors.ipam.parent_status",
  "errors.ipam.plan.stale",
  "errors.ipam.plan.unacknowledged",
  "errors.ipam.prefix.full",
  "errors.ipam.prefix.has_children",
  "errors.ipam.prefix.has_ranges",
  "errors.ipam.prefix.host_bits",
  "errors.ipam.prefix.nibble_boundary",
  "errors.ipam.prefix.overlap",
  "errors.ipam.prefix.overlaps_range",
  "errors.ipam.prefix.resize_orphans",
  "errors.ipam.range.covers_reservation",
  "errors.ipam.range.not_in_network",
  "errors.ipam.range.outside_prefix",
  "errors.ipam.range.overlap",
  "errors.ipam.reference_missing",
  "errors.ipam.revision_mismatch",
  "errors.ipam.site.cycle",
  "errors.ipam.status.transition",
  "errors.ipam.unavailable",
  "errors.ipam.validation",
  "errors.ipam.vlan.duplicate",
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
  "errors.users.last_administrator",
  "errors.users.name_taken",
  "errors.users.not_found",
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
  "hosts.addresses.none",
  "hosts.addresses.title",
  "hosts.bulk.lock_title",
  "hosts.bulk.mode_title",
  "hosts.bulk.unlock_title",
  "hosts.col.addresses",
  "hosts.col.client_id",
  "hosts.col.duid",
  "hosts.col.interface",
  "hosts.connect.hint",
  "hosts.connect.rdp",
  "hosts.connect.rdp_port",
  "hosts.connect.ssh",
  "hosts.connect.ssh_port",
  "hosts.connect.target",
  "hosts.connect.title",
  "hosts.connect.user",
  "hosts.crumbs",
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
  "import.credentials.reason.forbidden",
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
  "import.preview.summary",
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
  "ipam.move.step.intent",
  "ipam.move.task.device",
  "ipam.move.task.dhcp",
  "ipam.move.task.dns",
  "ipam.move.task.generic",
  "ipam.move.task.l2",
  "ipam.move.task.observe",
  "ipam.move.title",
  "ipam.nav.addresses",
  "ipam.nav.custom_fields",
  "ipam.nav.hosts",
  "ipam.nav.import",
  "ipam.nav.label",
  "ipam.nav.networks",
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
  "ipam.prefix.in_several",
  "ipam.prefix.no_children",
  "ipam.prefix.not_found",
  "ipam.prefix.ranges_grid",
  "ipam.prefix.tab.addresses",
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
  "jobs.step.dns_manual",
  "jobs.step.import_apply_chunk",
  "jobs.step.import_parse",
  "jobs.step.import_plan",
  "jobs.step.ipam_apply",
  "jobs.step.ipam_intent",
  "jobs.step.l2_move",
  "jobs.step.observe",
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
  "jobs.stepname.ipam_move_device",
  "jobs.stepname.ipam_move_dhcp",
  "jobs.stepname.ipam_move_dns",
  "jobs.stepname.ipam_move_intent",
  "jobs.stepname.ipam_move_l2",
  "jobs.stepname.ipam_move_observe",
  "jobs.stepname.l2_move",
  "jobs.stepname.observe",
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
  "jobs.title.import_apply",
  "jobs.title.ipam_apply",
  "jobs.title.move",
  "jobs.undo.step",
  "jobs.view.active",
  "jobs.view.all",
  "jobs.view.failed",
  "jobs.view.finished",
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
  "move.legend.auto",
  "move.legend.manual",
  "move.nothing",
  "move.open_jobs",
  "move.other_host_part",
  "move.parallelism",
  "move.parallelism_help",
  "move.phase1_body",
  "move.phase1_title",
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
  "recovery.copied",
  "recovery.copy_failed",
  "recovery.download",
  "recovery.list_label",
  "recovery.print",
  "recovery.saved",
  "role.admin.description",
  "role.admin.name",
  "role.operator.description",
  "role.operator.name",
  "role.viewer.description",
  "role.viewer.name",
  "settings.nav.label",
  "settings.nav.security",
  "settings.nav.users",
  "settings.reloaded",
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
  "setup.done.admin",
  "setup.done.change",
  "setup.done.change_item",
  "setup.done.choices",
  "setup.done.cluster",
  "setup.done.disk",
  "setup.done.disk_override",
  "setup.done.disk_unknown",
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
  "setup.gate.disk",
  "setup.gate.display_name",
  "setup.gate.host_empty",
  "setup.gate.host_invalid",
  "setup.gate.lab_ack",
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
  "setup.step.disk.name",
  "setup.step.disk.title",
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
  "shell.command.shortcuts",
  "shell.command.theme_dark",
  "shell.command.theme_light",
  "shell.command.theme_system",
  "shell.command.vlans",
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
  "shell.nav.dashboard",
  "shell.nav.dhcp",
  "shell.nav.dns",
  "shell.nav.ipam",
  "shell.nav.jobs",
  "shell.nav.jobs_badge",
  "shell.nav.label",
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
  "shell.status.no_events",
  "shell.status.offline",
  "shell.status.reconnecting",
  "shell.status.running",
  "shell.status.selection",
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
  "toggles.session.name",
  "toggles.session.value",
  "toggles.token_max_days.days",
  "toggles.token_max_days.name",
  "toggles.token_max_days.unlimited",
];
