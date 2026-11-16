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

function list(value, valid, message) {
	if (typeof value !== 'string' || new TextEncoder().encode(value).length > 4096 || /[\x00-\x08\x0b-\x1f\x7f]/.test(value))
		throw new Error(message);
	const values = value.trim() ? value.trim().split(/[ \t\n]+/) : [];
	if (values.length > 64 || !values.every(valid))
		throw new Error(message);
	return [...new Set(values)];
}

return baseclass.extend({
	ipv4: ipv4,

	options: function(form, vpn) {
		if (!vpn || typeof vpn.selection !== 'string' || !(
			(vpn.mode === 'managed' && /^profile\.[a-zA-Z0-9]{8}$/.test(vpn.selection)) ||
			(vpn.mode === 'external' && /^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(vpn.selection) && !/^xcloud_/.test(vpn.selection))))
			throw new Error(_('Choose a VPN on the VPN page first.'));
		if (!['lan', 'devices'].includes(form.scope))
			throw new Error(_('Choose the routing scope.'));
		const networks = list(form.networks, value => /^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/.test(value), _('Enter valid LAN interface names, separated by spaces or new lines.'));
		const devices = form.scope === 'devices' ? list(form.devices.toLowerCase(), value => ipv4(value) || hostname(value, false),
			_('Enter valid device IPv4 addresses or DHCP hostnames, separated by spaces or new lines.')) : [];
		if (form.scope === 'devices' && !devices.length)
			throw new Error(_('Enter at least one device, or explicitly choose all eligible LAN devices.'));
		const custom = list(form.custom.toLowerCase(), destination, _('Enter domains, IPv4 addresses or aligned IPv4 subnets. A default route is not allowed.'));
		if (!form.console && !form.browser && !custom.length)
			throw new Error(_('Select Xbox console, browser, or at least one custom destination.'));
		if (!form.ack)
			throw new Error(_('Acknowledge the IPv4 and DNS limitations before continuing.'));
		if (!ipv4(form.peer))
			throw new Error(_('Enter the IPv4 address of the device you are using to manage this router.'));
		return [vpn.mode, vpn.selection, networks.join('\n'), devices.join('\n'),
			form.console ? '1' : '0', form.browser ? '1' : '0', form.console && form.fallback ? '1' : '0',
			custom.join('\n'), '1', form.peer, form.scope];
	},

	preview: function(result, args) {
		if (!result || !/^[a-f0-9]{64}$/.test(result.review) || result.scope !== args[10] ||
			!['dnsmasq.nftset', 'not_required'].includes(result.dns) || !/^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/.test(result.interface))
			throw new Error(_('The routing preview is incomplete. Preview again before applying.'));
		const error = _('The routing preview contains invalid addresses. Preview again before applying.');
		const sources = list(result.sources, result.scope === 'devices' ? ipv4 : subnet, error);
		const networks = list(result.lan_networks, value => /^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/.test(value), error);
		const subnets = list(result.lan_subnets, subnet, error);
		const destinations = list(result.destinations, destination, error);
		if (!sources.length || !networks.length || !subnets.length || !destinations.length)
			throw new Error(error);
		return { sources, networks, subnets, destinations, dns: result.dns, review: result.review,
			warnings: typeof result.warnings === 'string' ? result.warnings.split('\n') : [] };
	}
});
