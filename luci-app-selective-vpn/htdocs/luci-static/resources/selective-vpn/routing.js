'use strict';
'require baseclass';

function ipv4(value) {
	return typeof value === 'string' && value.split('.').length === 4 &&
		value.split('.').every(part => /^(0|[1-9][0-9]{0,2})$/.test(part) && +part <= 255);
}

function hostname(value, domain) {
	if (value.length > 253 || !/^[a-zA-Z0-9.-]+$/.test(value))
		return false;
	const labels = value.split('.');
	return (!domain || labels.length > 1) && /[a-zA-Z]/.test(labels[labels.length - 1]) &&
		labels.every(label => label.length >= 1 && label.length <= 63 && !/^-|-$/.test(label));
}

function subnet(value) {
	const parts = value.split('/');
	if (parts.length !== 2 || !ipv4(parts[0]) || !/^(0|[1-9][0-9]?)$/.test(parts[1]) || +parts[1] < 1 || +parts[1] > 32)
		return false;
	const address = parts[0].split('.').reduce((total, part) => total * 256 + +part, 0);
	return address % Math.pow(2, 32 - +parts[1]) === 0;
}

function destination(value) {
	if (ipv4(value) || subnet(value))
		return true;
	const tld = value.split('.').pop();
	return hostname(value, true) && (/^[a-z]{2,}$/.test(tld) || /^xn--.+$/.test(tld));
}

function port(value) {
	const parts = value.split('-');
	return parts.length <= 2 && parts.every(part => /^[1-9][0-9]{0,4}$/.test(part) && +part <= 65535) &&
		+parts[0] <= +parts[parts.length - 1];
}

// a double underscore separates the rule from its preset in policy names
function ruleName(value) {
	return typeof value === 'string' && /^[a-zA-Z_][a-zA-Z0-9_]{0,39}$/.test(value) &&
		!/__/.test(value) && !/^svpn_/.test(value) && value !== 'main';
}

// a hand-made PBR section that a rule replaces
function sectionName(value) {
	return /^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(value) && !/^svpn_/.test(value);
}

function presetId(value) {
	return /^[a-z][a-z0-9_]{0,62}$/.test(value) && !/__/.test(value);
}

function list(value, valid, message) {
	if (typeof value !== 'string' || new TextEncoder().encode(value).length > 4096 || /[\x00-\x08\x0b-\x1f\x7f]/.test(value))
		throw new Error(message);
	const values = value.trim() ? value.trim().split(/[ \t\n]+/) : [];
	if (values.length > 64 || !values.every(valid))
		throw new Error(message);
	return [...new Set(values)];
}

function catalog(text) {
	const presets = [];
	(typeof text === 'string' ? text.split('\n') : []).forEach(line => {
		const fields = line.split('\t');
		if (fields.length === 3 && presetId(fields[0]) && /^[a-zA-Z0-9 ().-]{1,64}$/.test(fields[1]))
			presets.push({ id: fields[0], label: fields[1], warning: fields[2] });
	});
	return presets;
}

// turn the saved draft into editable rows, global first
function rows(text, presets) {
	const error = _('The saved rules could not be read. Fix them over SSH.');
	const result = [];
	let row = null;
	(typeof text === 'string' ? text.split('\n') : []).forEach(line => {
		if (!line.trim())
			return;
		const words = line.trim().split(/\s+/);
		const key = words.shift();
		if (key === 'rule') {
			if (words.length !== 1 || !ruleName(words[0]))
				throw new Error(error);
			row = { name: words[0], address: '', presets: [], destinations: '', tcp: true, udp: true, ports: '', adopt: [] };
			result.push(row);
		}
		else if (!row)
			throw new Error(error);
		else if (key === 'address')
			row.address = words.join(' ');
		else if (key === 'proto') {
			row.tcp = words.includes('tcp');
			row.udp = words.includes('udp');
		}
		else if (key === 'dest_port')
			row.ports = words.join(' ');
		else if (key === 'destinations')
			row.destinations = words.join('\n');
		else if (key === 'preset')
			row.presets = words.filter(id => presets.some(preset => preset.id === id));
		else if (key === 'adopt' && words.every(sectionName))
			row.adopt = words;
		else
			throw new Error(error);
	});
	if (!result.length || result[0].name !== 'global')
		result.unshift({ name: 'global', address: '', presets: [], destinations: '', tcp: true, udp: true, ports: '', adopt: [] });
	return result;
}

// pick an unused rule name from a DHCP hostname or the address
function name(label, address, taken) {
	let base = String(label || '').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 32);
	if (!/^[a-z]/.test(base) || !ruleName(base) || base === 'global')
		base = 'device_' + String(address).replace(/\./g, '_');
	let candidate = base;
	for (let i = 2; taken.includes(candidate); i++)
		candidate = base + '_' + i;
	return candidate;
}

function serialize(items, presets) {
	if (!Array.isArray(items) || !items.length || items.length > 24 || items[0].name !== 'global')
		throw new Error(_('The Global rule must come first, with at most 23 device rules.'));
	const names = [], addresses = [], lines = [];
	items.forEach((row, index) => {
		const label = row.name || _('Device rule');
		if (index && (!ruleName(row.name) || row.name === 'global'))
			throw new Error(_('Rule names use letters, digits and single underscores, up to 40 characters: ') + label);
		if (names.includes(row.name))
			throw new Error(_('Each rule needs a different name: ') + label);
		names.push(row.name);
		lines.push('rule ' + row.name);
		if (index) {
			if (!ipv4(row.address))
				throw new Error(_('Enter the device IPv4 address for rule ') + label);
			if (addresses.includes(row.address))
				throw new Error(_('A device can only have one routing rule: ') + row.address);
			addresses.push(row.address);
			lines.push('address ' + row.address);
		}
		if (!row.tcp && !row.udp)
			throw new Error(_('Choose TCP, UDP or both for rule ') + label);
		lines.push('proto ' + [row.tcp ? 'tcp' : '', row.udp ? 'udp' : ''].filter(Boolean).join(' '));
		const ports = list(row.ports, port, _('Enter ports from 1 to 65535 or ranges such as 8000-8010 for rule ') + label);
		if (ports.length)
			lines.push('dest_port ' + ports.join(' '));
		const destinations = list(row.destinations.toLowerCase(), destination,
			_('Enter domains, IPv4 addresses or aligned IPv4 subnets for rule ') + label);
		if (destinations.length)
			lines.push('destinations ' + destinations.join(' '));
		const chosen = row.presets.filter(id => presets.some(preset => preset.id === id));
		if (chosen.length)
			lines.push('preset ' + chosen.join(' '));
		const adopt = (row.adopt || []).filter(sectionName);
		if (adopt.length)
			lines.push('adopt ' + adopt.join(' '));
	});
	return lines.join('\n') + '\n';
}

// hand-made PBR policies: section, label, result and the rule it maps to
function policies(text) {
	const result = [];
	(typeof text === 'string' ? text.split('\n') : []).forEach(line => {
		const fields = line.split('\t');
		if (fields.length === 5 && /^[a-z_]{1,32}$/.test(fields[3]) && (!fields[1] || fields[1] === '-' || sectionName(fields[1])) &&
			(!fields[4] || ruleName(fields[4]) || fields[4] === 'global') && fields[2].length <= 64)
			result.push({ section: fields[1] === '-' ? '' : fields[1], label: fields[2], status: fields[3], rule: fields[4] });
	});
	return result.slice(0, 256);
}

return baseclass.extend({
	ipv4: ipv4,
	subnet: subnet,
	destination: destination,
	ruleName: ruleName,
	catalog: catalog,
	rows: rows,
	name: name,
	serialize: serialize,
	policies: policies,

	options: function(form, vpn, items, presets) {
		if (!vpn || typeof vpn.selection !== 'string' || !(
			(vpn.mode === 'managed' && /^profile\.[a-zA-Z0-9]{8}$/.test(vpn.selection)) ||
			(vpn.mode === 'external' && /^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(vpn.selection) && !/^svpn_/.test(vpn.selection))))
			throw new Error(_('Choose a VPN on the VPN page first.'));
		const networks = list(form.networks, value => /^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/.test(value), _('Enter valid LAN interface names, separated by spaces or new lines.'));
		const text = serialize(items, presets);
		if (!form.ack)
			throw new Error(_('Acknowledge the IPv4 and DNS limitations before continuing.'));
		if (!ipv4(form.peer))
			throw new Error(_('Enter the IPv4 address of the device you are using to manage this router.'));
		return [vpn.mode, vpn.selection, networks.join('\n'), text, '1', form.peer];
	},

	preview: function(result, args) {
		if (!result || !/^[a-f0-9]{64}$/.test(result.review) || typeof result.routes !== 'string' ||
			!['dnsmasq.nftset', 'not_required'].includes(result.dns) || !/^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/.test(result.interface))
			throw new Error(_('The routing preview is incomplete. Preview again before applying.'));
		const error = _('The routing preview contains invalid addresses. Preview again before applying.');
		const networks = list(result.lan_networks, value => /^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/.test(value), error);
		const subnets = list(result.lan_subnets, subnet, error);
		const names = args[3].split('\n').filter(line => /^rule /.test(line)).map(line => line.slice(5));
		const routes = result.routes.split('\n').filter(Boolean).map(line => {
			const fields = line.split('\t');
			if (fields.length !== 6 || !names.includes(fields[0]) || (fields[1] && !presetId(fields[1])))
				throw new Error(error);
			return {
				rule: fields[0], preset: fields[1],
				sources: list(fields[2], value => ipv4(value) || subnet(value), error),
				destinations: list(fields[3], destination, error),
				proto: list(fields[4], value => ['tcp', 'udp'].includes(value), error),
				ports: list(fields[5], port, error)
			};
		});
		if (!routes.length || !networks.length || !subnets.length)
			throw new Error(error);
		const adopted = (typeof result.adopted === 'string' ? result.adopted.split('\n') : []).filter(Boolean).map(line => {
			const fields = line.split('\t');
			if (fields.length !== 3 || !names.includes(fields[0]) || !sectionName(fields[1]) || fields[2].length > 64)
				throw new Error(error);
			return { rule: fields[0], section: fields[1], label: fields[2] };
		});
		const client = typeof result.adopted_client === 'string' && sectionName(result.adopted_client) ? result.adopted_client : '';
		return { routes, networks, subnets, dns: result.dns, review: result.review, adopted, client,
			warnings: typeof result.warnings === 'string' ? result.warnings.split('\n') : [] };
	}
});
