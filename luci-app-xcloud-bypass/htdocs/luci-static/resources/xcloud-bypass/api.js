'use strict';
'require baseclass';
'require rpc';

const parameters = {
	settings: [], clients: [], profiles: [], leases: [], status: [], pending: [],
	profile_summary: ['id'], import_profile: ['profile'],
	set_credentials: ['id', 'username', 'password'],
	reconnect: ['peer'], confirm: ['id']
};
parameters.preview = ['mode', 'selection', 'networks', 'devices', 'console', 'browser', 'fallback', 'custom', 'ack', 'peer', 'scope'];
parameters.apply = parameters.preview.concat('review');
const failures = {
	vpn_scope: _('Preview failed. Check the VPN profile and credentials, selected LAN networks and devices, and existing VPN or firewall conflicts.'),
	dns_policy: _('Preview failed. Check dnsmasq nftset support, client DNS settings and existing PBR policy conflicts.')
};
const methods = {};
Object.keys(parameters).forEach(name => {
	methods[name] = rpc.declare({
		object: 'xcloud-bypass', method: name,
		params: parameters[name], reject: true
	});
});
const job = rpc.declare({
	object: 'xcloud-bypass', method: 'job', params: ['id'], reject: true
});
let active = true;
window.addEventListener('pagehide', () => { active = false; });
window.addEventListener('pageshow', () => { active = true; });

async function request(method, ...args) {
	try {
		return await method(...args);
	}
	catch (error) {
		throw new Error(_('Router request failed. Check your session, permissions and connectivity.'));
	}
}

function object(value) {
	return value && typeof value === 'object' && !Array.isArray(value);
}

function validSelection(value) {
	return object(value) && typeof value.selection === 'string' && (
		(value.mode === 'managed' && /^profile\.[a-zA-Z0-9]{8}$/.test(value.selection)) ||
		(value.mode === 'external' && /^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(value.selection) &&
		 !/^xcloud_/.test(value.selection))
	);
}

return baseclass.extend({
	call: async function(name, ...args) {
		if (!active)
			throw new Error(_('This page is no longer active. Reload it before trying again.'));
		if (!Object.prototype.hasOwnProperty.call(methods, name))
			throw new Error(_('Unknown operation.'));
		const answer = await request(methods[name], ...args);
		if (!object(answer) || answer.ok !== true || typeof answer.job !== 'string')
			throw new Error(_('Unable to start the operation. Check permissions and try again.'));
		const deadline = Date.now() + 100000;
		while (active && Date.now() < deadline) {
			const state = await request(job, answer.job);
			if (!object(state) || state.ok !== true)
				throw new Error(_('The operation result is unavailable. Refresh status before retrying.'));
			if (state.state === 'complete') {
				if (!object(state.result) || (name === 'status' ? state.result.schema !== 1 : state.result.ok !== true)) {
					if (object(state.result) && Object.prototype.hasOwnProperty.call(failures, state.result.code))
						throw new Error(failures[state.result.code]);
					throw new Error(_('The operation failed. Check diagnostics over SSH.'));
				}
				return state.result;
			}
			if (state.state !== 'running')
				break;
			await new Promise(resolve => window.setTimeout(resolve, 500));
		}
		throw new Error(_('The wait ended. Refresh status before retrying; the operation may still be running.'));
	},

	selection: function(value) {
		const key = 'xcloud-vpn:' + L.env.sessionid;
		if (arguments.length) {
			if (!validSelection(value))
				throw new Error(_('Select an imported profile or an existing client.'));
			try {
				window.sessionStorage.setItem(key, JSON.stringify({ mode: value.mode, selection: value.selection }));
			}
			catch (error) {
				throw new Error(_('Allow browser session storage to keep your VPN selection.'));
			}
			return value;
		}
		try {
			const saved = JSON.parse(window.sessionStorage.getItem(key));
			return validSelection(saved) ? saved : null;
		}
		catch (error) {
			return null;
		}
	}
});
