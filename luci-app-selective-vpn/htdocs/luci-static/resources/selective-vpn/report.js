'use strict';
'require baseclass';
'require selective-vpn.routing as routing';

const schema = {
	collection: { state: 'complete partial busy unavailable' },
	configuration: { enabled: 'bool', rules: 'number', pending_uci: 'present absent unknown', owned_settings: 'match changed unknown' },
	recovery: { state: 'none preparing armed applying applied awaiting_confirmation confirmed recovering runtime_recovery conflict rolled_back unknown', seconds_remaining: 'number', supervisor: 'running stopped unknown' },
	dependencies: {},
	vpn: { process: 'running stopped unverified unknown', ipv4: 'usable missing invalid unknown', tunnel: 'ready not_ready unknown', logical_interface: 'attached detached unknown' },
	routing: { main_ipv4_default: 'present missing unknown', ipv6_default: 'present missing unknown', vpn_default: 'present missing unknown', mark_rule: 'present missing unknown', activation_baseline: 'unchanged changed stale unknown' },
	pbr: { version: 'supported unsupported unknown', service: 'running stopped unknown', errors: 'present absent unknown', policy_configuration: 'match changed unknown' },
	dns: { nftset_capability: 'supported unsupported unknown', integration: 'ready not_ready not_required unknown', sets: 'number', population: 'nonempty empty unknown not_required', resolution: 'not_probed' },
	firewall: { candidate: 'valid invalid unknown', source: 'saved_configuration', zone: 'found missing ambiguous unknown', masquerading: 'bool', input_restricted: 'bool', forward_restricted: 'bool' },
	evidence: { tunnel: 'observed unverified', policy_rules: 'observed unverified', policy_matches: 'observed unverified', vpn_egress: 'unverified', device_authentication: 'unverified', game_stream: 'unverified', exit_ip: 'unknown', exit_country: 'unknown' },
	logs: { state: 'summarized unavailable not_requested', scope: 'all_openvpn_instances', authentication_failure: 'number', tls_failure: 'number', connection_failure: 'number', restart: 'number' }
};
for (const name of ['timeout', 'ubus', 'jsonfilter', 'uci', 'nft', 'ip_full', 'ss', 'dnsmasq', 'openvpn', 'fw4', 'pbr', 'logread'])
	schema.dependencies[name] = 'available missing unknown';
// groups keyed by policy, such as global or tv__preset
const policies = { policies: 'present absent unknown', packets: 'number', bytes: 'number' };
const limitations = ['ipv4_only', 'client_dns_must_use_router', 'encrypted_dns_and_cached_answers_may_bypass_sets',
	'domain_equivalence_needs_validation',
	'counters_do_not_prove_vpn_egress_or_authentication', 'logs_are_recent_historical_signals', 'no_external_lookup_performed'];

function names(items) {
	return Object.keys(items).filter(name => /^[a-zA-Z_][a-zA-Z0-9_]{0,119}$/.test(name)).slice(0, 128);
}

return baseclass.extend({
	clean: function(value, kind) {
		if (!value || value.schema !== 2 || value.report !== kind || !['status', 'doctor'].includes(kind))
			throw new Error(_('The report is unavailable. Refresh and check your session.'));
		const result = { schema: 2, report: kind };
		for (const group of Object.keys(schema)) {
			result[group] = {};
			for (const key of Object.keys(schema[group])) {
				const allowed = schema[group][key], item = value[group] && value[group][key];
				result[group][key] = allowed === 'bool' ? (typeof item === 'boolean' ? item : null) :
					allowed === 'number' ? (Number.isSafeInteger(item) && item >= 0 && item < 1e15 ? item : null) :
					allowed.split(' ').includes(item) ? item : 'unknown';
			}
		}
		for (const group of Object.keys(policies)) {
			result[group] = {};
			const items = value[group] && typeof value[group] === 'object' ? value[group] : {};
			for (const name of names(items)) {
				const item = items[name];
				if (policies[group] === 'number' ? Number.isSafeInteger(item) && item >= 0 && item < 1e15 : policies[group].split(' ').includes(item))
					result[group][name] = item;
			}
		}
		result.limitations = limitations.slice();
		result.privacy = 'allowlisted_fields_and_log_categories_only';
		return result;
	},

	details: function(value) {
		const data = value && value.details || {};
		const tokens = (text, valid) => {
			if (typeof text !== 'string' || text.length > 4096 || !/^[a-z0-9 ./-]*$/.test(text)) return [];
			const values = text.split(' ').filter(Boolean);
			return values.length <= 64 && values.every(valid) ? values : [];
		};
		const group = key => value && value[key] && typeof value[key] === 'object' ? value[key] : {};
		const sources = group('sources'), destinations = group('destinations'), protocols = group('protocols'), ports = group('ports');
		return {
			interface: typeof data.interface === 'string' && /^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}$/.test(data.interface) ? data.interface : '',
			addresses: tokens(data.addresses, value => {
				const parts = value.split('/');
				return parts.length === 2 && routing.ipv4(parts[0]) && /^(0|[1-9][0-9]?)$/.test(parts[1]) && +parts[1] <= 32;
			}),
			policies: names(sources).map(name => ({ name: name,
				rule: name.split('__')[0], preset: name.split('__')[1] || '',
				sources: tokens(sources[name], value => routing.ipv4(value) || routing.subnet(value)),
				destinations: tokens(destinations[name], value => routing.destination(value)),
				protocols: tokens(protocols[name], value => ['tcp', 'udp'].includes(value)),
				ports: tokens(ports[name], value => /^[1-9][0-9]{0,4}(-[1-9][0-9]{0,4})?$/.test(value)) }))
				.filter(policy => policy.sources.length && policy.destinations.length)
		};
	}
});
