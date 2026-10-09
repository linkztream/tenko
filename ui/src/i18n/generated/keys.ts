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
  | "account.totp.no_qr"
  | "account.totp.open_link"
  | "account.totp.params"
  | "account.totp.remove_body"
  | "account.totp.remove_refused"
  | "account.totp.remove_title"
  | "account.totp.removed"
  | "account.totp.setup"
  | "account.totp.setup_title"
  | "account.totp.status_off"
  | "account.totp.status_on"
  | "account.totp.title"
  | "account.totp.verify"
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
  | "shell.command.dashboard_hint"
  | "shell.command.density_comfortable"
  | "shell.command.density_compact"
  | "shell.command.density_dense"
  | "shell.command.emphasis_off"
  | "shell.command.emphasis_on"
  | "shell.command.shortcuts"
  | "shell.command.theme_dark"
  | "shell.command.theme_light"
  | "shell.command.theme_system"
  | "shell.dashboard.jobs"
  | "shell.dashboard.jobs_hint"
  | "shell.dashboard.no_roles"
  | "shell.dashboard.node"
  | "shell.dashboard.note"
  | "shell.dashboard.revision"
  | "shell.dashboard.revision_hint"
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
  | "shell.search.kind.mac"
  | "shell.search.kind.prefix"
  | "shell.search.kind.vlan"
  | "shell.search.results"
  | "shell.search.title"
  | "shell.skip_to_content"
  | "shell.splash"
  | "shell.status.connecting"
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
  "auth.signin.retry_in": { seconds: number };
  "common.count.items": { count: number };
  "common.greeting": { name: string | number };
  "errors.auth.password.too_long": { max: string | number };
  "errors.auth.password.too_short": { min: string | number };
  "errors.auth.setup.invalid_host_name": { host_name: string | number };
  "errors.auth.throttled": { retry_after: string | number };
  "errors.auth.token.lifetime_exceeded": { max_days: string | number };
  "errors.client.bad_response": { status: string | number };
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
  "account.totp.no_qr",
  "account.totp.open_link",
  "account.totp.params",
  "account.totp.remove_body",
  "account.totp.remove_refused",
  "account.totp.remove_title",
  "account.totp.removed",
  "account.totp.setup",
  "account.totp.setup_title",
  "account.totp.status_off",
  "account.totp.status_on",
  "account.totp.title",
  "account.totp.verify",
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
  "shell.command.dashboard_hint",
  "shell.command.density_comfortable",
  "shell.command.density_compact",
  "shell.command.density_dense",
  "shell.command.emphasis_off",
  "shell.command.emphasis_on",
  "shell.command.shortcuts",
  "shell.command.theme_dark",
  "shell.command.theme_light",
  "shell.command.theme_system",
  "shell.dashboard.jobs",
  "shell.dashboard.jobs_hint",
  "shell.dashboard.no_roles",
  "shell.dashboard.node",
  "shell.dashboard.note",
  "shell.dashboard.revision",
  "shell.dashboard.revision_hint",
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
  "shell.search.kind.mac",
  "shell.search.kind.prefix",
  "shell.search.kind.vlan",
  "shell.search.results",
  "shell.search.title",
  "shell.skip_to_content",
  "shell.splash",
  "shell.status.connecting",
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
