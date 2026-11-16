'use strict';
'require baseclass';
'require xcloud-bypass.routing as routing';

const schema = {
	collection: { state: 'complete partial busy unavailable' },
	configuration: { enabled: 'bool', console: 'bool', browser: 'bool', static_fallback: 'bool', pending_uci: 'present absent unknown', owned_settings: 'match changed unknown' },
	recovery: { state: 'none preparing armed applying applied awaiting_confirmation confirmed recovering runtime_recovery conflict rolled_back unknown', seconds_remaining: 'number', supervisor: 'running stopped unknown' },
	dependencies: {},
	vpn: { process: 'running stopped unverified unknown', ipv4: 'usable missing invalid unknown', tunnel: 'ready not_ready unknown', logical_interface: 'attached detached unknown' },
	routing: { main_ipv4_default: 'present missing unknown', ipv6_default: 'present missing unknown', vpn_default: 'present missing unknown', mark_rule: 'present missing unknown', activation_baseline: 'unchanged changed stale unknown' },
	pbr: { version: 'supported unsupported unknown', service: 'running stopped unknown', errors: 'present absent unknown', policy_configuration: 'match changed unknown' },
	policies: {}, packets: {}, bytes: {},
	dns: { nftset_capability: 'supported unsupported unknown', integration: 'ready not_ready not_required unknown', sets: 'number', population: 'nonempty empty unknown not_required', resolution: 'not_probed' },
	firewall: { candidate: 'valid invalid unknown', source: 'saved_configuration', zone: 'found missing ambiguous unknown', masquerading: 'bool', input_restricted: 'bool', forward_restricted: 'bool' },
	evidence: { tunnel: 'observed unverified', policy_rules: 'observed unverified', policy_matches: 'observed unverified', vpn_egress: 'unverified', xbox_authentication: 'unverified', game_stream: 'unverified', exit_ip: 'unknown', exit_country: 'unknown' },
	logs: { state: 'summarized unavailable not_requested', scope: 'all_openvpn_instances', authentication_failure: 'number', tls_failure: 'number', connection_failure: 'number', restart: 'number' }
};
for (const name of ['timeout', 'ubus', 'jsonfilter', 'uci', 'nft', 'ip_full', 'ss', 'dnsmasq', 'openvpn', 'fw4', 'pbr', 'logread'])
	schema.dependencies[name] = 'available missing unknown';
for (const name of ['console', 'browser', 'custom']) {
	schema.policies[name] = 'present absent unknown';
	schema.packets[name] = schema.bytes[name] = 'number';
}
const limitations = ['ipv4_only', 'client_dns_must_use_router', 'encrypted_dns_and_cached_answers_may_bypass_sets',
	'domain_equivalence_needs_validation', 'static_console_addresses_may_be_outdated',
	'counters_do_not_prove_vpn_egress_or_authentication', 'logs_are_recent_historical_signals', 'no_external_lookup_performed'];

return baseclass.extend({
	clean: function(value, kind) {
		if (!value || value.schema !== 1 || value.report !== kind || !['status', 'doctor'].includes(kind))
			throw new Error(_('The report is unavailable. Refresh and check your session.'));
		const result = { schema: 1, report: kind };
		for (const group of Object.keys(schema)) {
			result[group] = {};
			for (const key of Object.keys(schema[group])) {
				const allowed = schema[group][key], item = value[group] && value[group][key];
				result[group][key] = allowed === 'bool' ? (typeof item === 'boolean' ? item : null) :
					allowed === 'number' ? (Number.isSafeInteger(item) && item >= 0 && item < 1e15 ? item : null) :
					allowed.split(' ').includes(item) ? item : 'unknown';
			}
		}
		result.limitations = limitations.slice();
		result.privacy = 'allowlisted_fields_and_log_categories_only';
		return result;
	},

	details: function(value) {
		const data = value && value.details || {};
		const tokens = (key, valid) => {
			if (typeof data[key] !== 'string' || data[key].length > 4096 || !/^[a-z0-9 ./-]*$/.test(data[key])) return [];
			const values = data[key].split(' ').filter(Boolean);
			return values.length <= 64 && values.every(valid) ? values : [];
		};
		return {
			interface: typeof data.interface === 'string' && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/.test(data.interface) ? data.interface : '',
			addresses: tokens('addresses', value => {
				const parts = value.split('/');
				return parts.length === 2 && routing.ipv4(parts[0]) && /^(0|[1-9][0-9]?)$/.test(parts[1]) && +parts[1] <= 32;
			}),
			policies: ['console', 'browser', 'custom'].map(name => ({ name: name,
				sources: tokens(name + '_sources', value => routing.ipv4(value) || routing.subnet(value)),
				destinations: tokens(name + '_destinations', value => routing.destination(value)) }))
		};
	}
});
