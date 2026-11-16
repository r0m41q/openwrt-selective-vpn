'use strict';
'require view';
'require xcloud-bypass.api as api';
'require xcloud-bypass.routing as routing';

function field(label, input, help) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': input.id }, [label]),
		E('div', { 'class': 'cbi-value-field' }, [input,
			help ? E('div', { 'class': 'cbi-value-description' }, [help]) : ''])
	]);
}

const warnings = {
	shared_pbr_will_be_enabled: _('The shared PBR service will be enabled.'),
	shared_pbr_resolver_will_change: _('PBR will use dnsmasq nftsets for domain policies.'),
	possible_policy_overlap: _('An existing PBR policy may overlap. Its priority is preserved; verify which route wins.'),
	static_console_addresses_may_be_outdated: _('The two static console addresses may be outdated.'),
	client_dns_must_use_router: _('Selected devices must use the router for DNS.'),
	encrypted_dns_and_cached_answers_may_bypass_sets: _('Encrypted DNS and cached answers may bypass domain matching.')
};

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		return Promise.all(['settings', 'leases', 'pending'].map(name => api.call(name).catch(() => null)));
	},

	message: function(text) {
		this.feedback.textContent = text;
	},

	read: function() {
		return routing.options({
			scope: this.scope.value, networks: this.networks.value, devices: this.devices.value,
			console: this.console.checked, browser: this.browser.checked, fallback: this.fallback.checked,
			custom: this.custom.value, ack: this.ack.checked, peer: this.peer.value
		}, this.vpn);
	},

	updateControls: function() {
		const locked = this.busy || this.readonly || !this.loaded || !!this.pending.id;
		this.inputs.forEach(node => { node.disabled = locked; });
		this.deviceFields.hidden = this.scope.value !== 'devices';
		this.fallback.disabled = locked || !this.console.checked;
		this.previewButton.disabled = locked;
		this.applyButton.disabled = locked || !this.review;
		this.confirmButton.disabled = this.busy || this.readonly || this.pending.state !== 'awaiting_confirmation' || this.remaining() <= 0;
		this.refresh.disabled = this.busy;
	},

	invalidate: function() {
		this.review = null;
		this.previewArea.replaceChildren();
		this.updateControls();
	},

	run: async function(action, refresh) {
		if (this.busy || (!refresh && (this.readonly || !this.loaded)))
			return;
		this.busy = true;
		this.updateControls();
		try {
			await action();
		}
		catch (error) {
			this.message(error.message);
		}
		finally {
			this.busy = false;
			this.updateControls();
		}
	},

	preview: async function() {
		if (this.pending.id)
			throw new Error(_('Finish the pending change before preparing another.'));
		this.invalidate();
		const args = this.read();
		this.message(_('Checking VPN, LAN scope, DNS and policy conflicts…'));
		const result = routing.preview(await api.call('preview', ...args), args);
		this.review = { args: args, fingerprint: JSON.stringify(args), result: result };
		const rows = [
			[_('LAN networks'), result.networks.join(', ')],
			[_('LAN subnets'), result.subnets.join(', ')],
			[_('Sources using the VPN'), result.sources.join(', ')],
			[_('Authentication destinations'), result.destinations.join(', ')],
			[_('Traffic'), _('IPv4 TCP port 443')],
			[_('DNS matching'), result.dns === 'dnsmasq.nftset' ? _('Router dnsmasq nftsets') : _('IP addresses only')]
		];
		this.previewArea.replaceChildren(
			E('h3', {}, [_('Review routing changes')]),
			E('table', { 'class': 'table' }, rows.map(row => E('tr', { 'class': 'tr' }, [
				E('th', { 'class': 'th' }, [row[0]]), E('td', { 'class': 'td' }, [row[1]])
			]))),
			E('p', {}, [args[0] === 'managed' ? _('The selected managed VPN will start. LAN forwarding and bypass policies will be updated for this scope.') :
				_('The existing VPN must already be running. LAN forwarding and bypass policies will be updated for this scope.')]),
			E('p', {}, [_('Obsolete bypass resources will be restored or removed. WAN defaults and unrelated configuration are checked before the change is accepted.')]),
			E('ul', {}, result.warnings.filter(name => Object.prototype.hasOwnProperty.call(warnings, name)).map(name => E('li', {}, [warnings[name]])))
		);
		this.message(_('Review the sources and destinations above, then apply. Network changes will need confirmation.'));
	},

	apply: async function() {
		if (!this.review || this.pending.id || JSON.stringify(this.read()) !== this.review.fingerprint) {
			this.invalidate();
			throw new Error(_('Preview the current settings before applying.'));
		}
		const reviewed = this.review;
		this.review = null;
		this.message(_('Applying routing changes. Keep this page open…'));
		try {
			const result = await api.call('apply', ...reviewed.args, reviewed.result.review);
			if (!/^[a-f0-9]{32}$/.test(result.id))
				throw new Error(_('No confirmation identifier was returned.'));
			const pending = await api.call('pending');
			this.setPending(pending);
			if (pending.id !== result.id)
				throw new Error(_('The change is no longer awaiting confirmation. Refresh recovery status.'));
			this.message(_('Routing changed. Confirm below only if you can still reach the router.'));
		}
		catch (error) {
			try { this.setPending(await api.call('pending')); }
			catch (pendingError) { this.loaded = false; }
			this.message(_('Apply failed or its result was lost. Check recovery below. If no change is pending, reload saved settings and preview again.'));
		}
	},

	remaining: function() {
		return Math.max(0, (this.pending.seconds_remaining || 0) - Math.floor((Date.now() - this.pendingAt) / 1000));
	},

	setPending: function(pending) {
		if (!pending || typeof pending.id !== 'string' || (pending.id && !/^[a-f0-9]{32}$/.test(pending.id)))
			throw new Error(_('Recovery status is unavailable. Reload before applying changes.'));
		this.pending = pending;
		this.pendingAt = Date.now();
		if (!Number.isInteger(pending.seconds_remaining) || pending.seconds_remaining < 0 || pending.seconds_remaining > 120)
			this.pending.seconds_remaining = 0;
		this.tick();
	},

	tick: function() {
		if (this.timer != null)
			window.clearTimeout(this.timer);
		this.timer = null;
		this.pendingArea.hidden = !this.pending.id;
		const remaining = this.remaining();
		if (this.pending.id) {
			this.recovery.textContent = this.pending.state === 'awaiting_confirmation' && remaining > 0 ?
				_('Confirm the change while router access works. Seconds remaining: ') + remaining :
				_('The change is not ready to confirm, or its window has ended. Refresh recovery status; leave the recovery service running.');
			if (remaining > 0 && this.active)
				this.timer = window.setTimeout(() => this.tick(), 1000);
		}
		this.updateControls();
	},

	confirm: async function() {
		if (!this.pending.id || this.pending.state !== 'awaiting_confirmation' || this.remaining() <= 0)
			throw new Error(_('The confirmation window has ended. Refresh recovery status.'));
		const id = this.pending.id;
		try {
			await api.call('confirm', id);
			this.setPending({ id: '' });
			this.message(_('Routing changes confirmed. Tunnel and policy readiness do not verify Xbox sign-in or gameplay.'));
		}
		catch (error) {
			this.message(_('Confirmation failed or expired. Refresh recovery status and check diagnostics over SSH.'));
			try { this.setPending(await api.call('pending')); }
			catch (pendingError) { this.loaded = false; }
		}
	},

	render: function(data) {
		const settings = data[0] || {};
		this.loaded = !!(data[0] && data[2]);
		this.readonly = !L.hasViewPermission();
		this.busy = false;
		this.review = null;
		this.pending = { id: '' };
		this.pendingAt = Date.now();
		this.active = true;
		this.vpn = api.selection() || { mode: settings.mode, selection: settings.selection };
		const input = (id, type) => E('input', { id: id, type: type || 'text', 'class': type === 'checkbox' ? 'cbi-input-checkbox' : 'cbi-input-text' });
		const textarea = id => E('textarea', { id: id, rows: 3, 'class': 'cbi-input-textarea' });
		const button = (label, action) => E('button', { type: 'button', 'class': 'btn cbi-button-action', click: () => this.run(action) }, [label]);
		this.scope = E('select', { id: 'routing-scope', 'class': 'cbi-input-select' }, [
			E('option', { value: 'lan' }, [_('All eligible LAN devices')]), E('option', { value: 'devices' }, [_('Selected devices')])
		]);
		this.scope.value = settings.devices && settings.devices.trim() ? 'devices' : 'lan';
		this.networks = input('routing-networks'); this.networks.value = settings.networks || '';
		this.devices = textarea('routing-devices'); this.devices.value = settings.devices || '';
		this.console = input('routing-console', 'checkbox'); this.console.checked = settings.console !== '0';
		this.browser = input('routing-browser', 'checkbox'); this.browser.checked = settings.browser === '1';
		this.fallback = input('routing-fallback', 'checkbox'); this.fallback.checked = settings.fallback === '1';
		this.custom = textarea('routing-custom'); this.custom.value = settings.custom || '';
		this.peer = input('routing-peer');
		this.ack = input('routing-ack', 'checkbox'); this.ack.checked = settings.ipv6_acknowledged === '1';
		this.suggestions = E('select', { id: 'routing-leases', 'class': 'cbi-input-select' }, [E('option', { value: '' }, [_('Choose a DHCP device')])]);
		const leases = data[1] && typeof data[1].leases === 'string' ? data[1].leases.split('\n') : [];
		leases.slice(0, 64).forEach(line => {
			const pair = line.split('\t');
			if (pair.length === 2 && routing.ipv4(pair[0]) && /^[a-zA-Z0-9.-]{1,253}$/.test(pair[1]))
				this.suggestions.appendChild(E('option', { value: pair[0] }, [pair[1] + ' (' + pair[0] + ')']));
		});
		this.addDevice = button(_('Add address'), async () => {
			if (!routing.ipv4(this.suggestions.value))
				throw new Error(_('Choose a DHCP device first.'));
			const values = this.devices.value.trim() ? this.devices.value.trim().split(/\s+/) : [];
			if (!values.includes(this.suggestions.value)) values.push(this.suggestions.value);
			this.devices.value = values.join('\n');
			this.invalidate();
		});
		this.deviceFields = E('div', {}, [
			field(_('Devices'), this.devices, _('IPv4 addresses or DHCP hostnames, separated by spaces or new lines. An empty selection is rejected.')),
			field(_('DHCP suggestions'), this.suggestions, data[1] ? _('Suggestions do not select devices automatically. Preview checks LAN membership.') : _('DHCP suggestions are unavailable. Enter addresses or hostnames manually.')),
			this.addDevice,
			E('p', {}, [_('DHCP addresses can change. Hostnames are resolved when applying; reserve device addresses for a stable selection.')])
		]);
		this.feedback = E('p', { role: 'status', 'aria-live': 'polite' });
		this.previewArea = E('div');
		this.previewButton = button(_('Preview changes'), () => this.preview());
		this.applyButton = button(_('Apply routing changes'), () => this.apply());
		this.confirmButton = button(_('Confirm router access'), () => this.confirm());
		this.refresh = E('button', { type: 'button', 'class': 'btn', click: () => this.run(async () => {
			try { this.setPending(await api.call('pending')); }
			catch (error) { this.loaded = false; throw error; }
			if (!this.pending.id)
				this.message(_('No change is awaiting confirmation. Reload the page to see saved settings.'));
		}, true) }, [_('Refresh recovery status')]);
		this.recovery = E('p', { role: 'status', 'aria-live': 'polite' });
		this.pendingArea = E('div', {}, [E('h3', {}, [_('Pending routing change')]), this.recovery,
			E('p', {}, [_('Leaving the change unconfirmed triggers automatic rollback. A failed recovery keeps its journal for repair over SSH.')]), this.confirmButton]);
		this.inputs = [this.scope, this.networks, this.devices, this.console, this.browser, this.fallback, this.custom, this.peer, this.ack, this.suggestions, this.addDevice];
		this.inputs.forEach(node => ['input', 'change'].forEach(event => node.addEventListener(event, () => this.invalidate())));
		window.addEventListener('pagehide', () => {
			this.active = false;
			window.clearTimeout(this.timer);
		});
		window.addEventListener('pageshow', () => { this.active = true; this.tick(); });
		try { this.setPending(data[2]); }
		catch (error) { this.loaded = false; this.message(error.message); }
		if (!this.loaded)
			this.message(_('Settings or recovery status could not be loaded. Reload before changing routing.'));
		if (this.readonly)
			this.message(_('You have read-only access. Ask an administrator to change routing settings.'));
		this.updateControls();
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('Authentication routing')]),
			E('p', {}, [_('Route selected authentication destinations over the VPN using IPv4 TCP port 443. Other traffic keeps its existing routing policies.')]),
			E('p', {}, [_('VPN: '), this.vpn.selection || _('None selected'), ' ', E('a', { href: L.url('admin/services/xcloud-bypass/vpn') }, [_('Choose VPN')])]),
			field(_('Routing scope'), this.scope), this.deviceFields,
			field(_('Xbox console'), this.console), field(_('Browser xCloud'), this.browser),
			field(_('Custom destinations'), this.custom, _('Domains, IPv4 addresses or IPv4 subnets, separated by spaces or new lines.')),
			E('details', {}, [E('summary', {}, [_('Advanced')]),
				field(_('LAN networks'), this.networks, _('Leave blank for eligible networks in the LAN firewall zone. Enter interface names to select other local static networks.')),
				field(_('Static console fallback'), this.fallback, _('Use 20.201.200.49 and 51.12.31.0 instead of console domains. Observed on one setup; addresses may change.'))
			]),
			field(_('Your management device IPv4'), this.peer, _('The IPv4 address of the device you are using to manage this router.')),
			field(_('I understand the limitations'), this.ack, _('IPv6 is not covered. Domain matching needs router DNS; encrypted DNS and cached answers may bypass it. Xbox sign-in and gameplay still need testing.')),
			this.previewButton, ' ', this.applyButton, this.feedback, this.previewArea, this.pendingArea, this.refresh
		]);
	}
});
