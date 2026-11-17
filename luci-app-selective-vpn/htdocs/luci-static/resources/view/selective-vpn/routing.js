'use strict';
'require view';
'require selective-vpn.api as api';
'require selective-vpn.routing as routing';

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
	static_console_addresses_may_be_outdated: _('The static preset addresses may be outdated.'),
	client_dns_must_use_router: _('Devices must use the router for DNS.'),
	encrypted_dns_and_cached_answers_may_bypass_sets: _('Encrypted DNS and cached answers may bypass domain matching.')
};

function traffic(route) {
	const proto = route.proto.map(value => value.toUpperCase()).join(', ');
	return route.ports.length ? proto + ' ' + _('ports') + ' ' + route.ports.join(', ') : proto + ', ' + _('all ports');
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		return Promise.all(['settings', 'leases', 'pending', 'rules'].map(name => api.call(name).catch(() => null)));
	},

	message: function(text) {
		this.feedback.textContent = text;
	},

	read: function() {
		return routing.options({ networks: this.networks.value, ack: this.ack.checked, peer: this.peer.value },
			this.vpn, this.rows, this.presets);
	},

	updateControls: function() {
		const locked = this.busy || this.readonly || !this.loaded || !!this.pending.id;
		this.inputs.concat(this.rowInputs).forEach(node => { node.disabled = locked; });
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

	// inputs write straight into the row objects, edits drop the reviewed preview
	renderRows: function() {
		this.rowInputs = [];
		const bind = (node, row, key, property) => {
			node[property || 'value'] = row[key];
			['input', 'change'].forEach(event => node.addEventListener(event, () => {
				row[key] = node[property || 'value'];
				this.invalidate();
			}));
			this.rowInputs.push(node);
			return node;
		};
		this.ruleArea.replaceChildren(...this.rows.map((row, index) => {
			const id = 'rule-' + index + '-';
			const global = index === 0;
			const presetBoxes = this.presets.map(preset => {
				const box = E('input', { id: id + preset.id, type: 'checkbox', 'class': 'cbi-input-checkbox' });
				box.checked = row.presets.includes(preset.id);
				box.addEventListener('change', () => {
					row.presets = this.presets.map(item => item.id).filter(item =>
						item === preset.id ? box.checked : row.presets.includes(item));
					this.invalidate();
				});
				this.rowInputs.push(box);
				return E('div', {}, [box, ' ', E('label', { 'for': box.id }, [preset.label]),
					preset.warning ? E('div', { 'class': 'cbi-value-description' }, [_('These addresses were seen on one setup and may change.')]) : '']);
			});
			const destinations = bind(E('textarea', { id: id + 'destinations', rows: 3, 'class': 'cbi-input-textarea' }), row, 'destinations');
			const tcp = bind(E('input', { id: id + 'tcp', type: 'checkbox', 'class': 'cbi-input-checkbox' }), row, 'tcp', 'checked');
			const udp = bind(E('input', { id: id + 'udp', type: 'checkbox', 'class': 'cbi-input-checkbox' }), row, 'udp', 'checked');
			const ports = bind(E('input', { id: id + 'ports', type: 'text', 'class': 'cbi-input-text' }), row, 'ports');
			const head = [];
			if (global) {
				head.push(E('h3', {}, [_('Global')]),
					E('p', {}, [_('Applies to every eligible LAN device without its own rule.')]));
			}
			else {
				const remove = E('button', { type: 'button', 'class': 'btn cbi-button-remove', click: () => {
					this.rows.splice(index, 1);
					this.renderRows();
					this.invalidate();
				} }, [_('Remove')]);
				this.rowInputs.push(remove);
				head.push(E('h3', {}, [_('Device rule')]),
					field(_('Name'), bind(E('input', { id: id + 'name', type: 'text', 'class': 'cbi-input-text' }), row, 'name')),
					field(_('IPv4 address'), bind(E('input', { id: id + 'address', type: 'text', 'class': 'cbi-input-text' }), row, 'address'),
						_('This device uses only the routes below instead of Global. With no presets or destinations it stays on its normal connection.')));
				head.push(remove);
			}
			return E('div', { 'class': 'cbi-section' }, head.concat([
				field(_('Presets'), E('div', { id: id + 'presets' }, presetBoxes), _('Each preset keeps its own protocol and port.')),
				field(_('Custom destinations'), destinations, _('Domains, IPv4 addresses or IPv4 subnets, separated by spaces or new lines.')),
				field(_('Protocols'), E('div', { id: id + 'proto' }, [tcp, ' ', E('label', { 'for': tcp.id }, ['TCP']), ' ', udp, ' ', E('label', { 'for': udp.id }, ['UDP'])]),
					_('Applies to custom destinations only.')),
				field(_('Destination ports'), ports, _('Leave blank for all ports. Separate ports or ranges such as 8000-8010 with spaces.'))
			]));
		}));
	},

	addDevice: function() {
		const manual = this.manual.value.trim();
		const address = manual || this.suggestions.value;
		if (!routing.ipv4(address))
			throw new Error(manual ? _('Enter a valid IPv4 address.') : _('Choose a DHCP device or enter an IPv4 address.'));
		if (this.rows.some(row => row.address === address))
			throw new Error(_('A device can only have one routing rule: ') + address);
		if (this.rows.length >= 24)
			throw new Error(_('At most 23 device rules are supported.'));
		const global = this.rows[0];
		const label = manual ? '' : this.leases[address];
		this.rows.push({ name: routing.name(label, address, this.rows.map(row => row.name)), address: address,
			presets: global.presets.slice(), destinations: global.destinations, tcp: global.tcp, udp: global.udp, ports: global.ports });
		this.manual.value = '';
		this.suggestions.value = '';
		this.renderRows();
		this.invalidate();
		this.message(_('Device added with a copy of the Global routes. Clear them to keep this device on its normal connection.'));
	},

	preview: async function() {
		if (this.pending.id)
			throw new Error(_('Finish the pending change before preparing another.'));
		this.invalidate();
		const args = this.read();
		this.message(_('Saving rules and checking VPN, LAN, DNS and policy conflicts…'));
		const result = routing.preview(await api.call('preview', ...args), args);
		this.review = { args: args, fingerprint: JSON.stringify(args), result: result };
		const labels = {};
		this.presets.forEach(preset => { labels[preset.id] = preset.label; });
		const rows = result.routes.map(route => {
			const sources = route.rule === 'global' ? (route.sources.length ? route.sources.join(', ') : _('No devices left')) :
				route.sources.join(', ');
			const name = route.rule === 'global' ? _('Global') : route.rule;
			return [name + (route.preset ? ' · ' + (labels[route.preset] || route.preset) : ''), sources,
				route.destinations.length ? route.destinations.join(', ') : _('None, normal connection'),
				route.destinations.length ? traffic(route) : '-'];
		});
		this.previewArea.replaceChildren(
			E('h3', {}, [_('Routes after applying')]),
			E('table', { 'class': 'table' }, [E('tr', { 'class': 'tr table-titles' }, [_('Rule'), _('Devices'), _('Destinations'), _('Traffic')]
				.map(text => E('th', { 'class': 'th' }, [text])))].concat(rows.map(row => E('tr', { 'class': 'tr' },
				row.map(text => E('td', { 'class': 'td' }, [text])))))),
			E('p', {}, [_('LAN networks: '), result.networks.join(', '), ' (', result.subnets.join(', '), ')']),
			E('p', {}, [_('DNS matching: '), result.dns === 'dnsmasq.nftset' ? _('Router dnsmasq nftsets') : _('IP addresses only')]),
			E('p', {}, [args[0] === 'managed' ? _('The selected managed VPN will start. LAN forwarding and managed policies will be updated.') :
				_('The existing VPN must already be running. LAN forwarding and managed policies will be updated.')]),
			E('ul', {}, result.warnings.filter(name => Object.prototype.hasOwnProperty.call(warnings, name)).map(name => E('li', {}, [warnings[name]])))
		);
		this.message(_('Rules saved as a draft. Review the routes above, then apply. Network changes will need confirmation.'));
	},

	apply: async function() {
		let current = null;
		try { current = JSON.stringify(this.read()); }
		catch (error) { current = null; }
		if (!this.review || this.pending.id || current !== this.review.fingerprint) {
			this.invalidate();
			throw new Error(_('Preview the current rules before applying.'));
		}
		const reviewed = this.review;
		this.review = null;
		this.message(_('Applying routing changes. Keep this page open…'));
		try {
			const args = reviewed.args;
			const result = await api.call('apply', args[0], args[1], args[2], args[4], args[5], reviewed.result.review);
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
			this.message(_('Apply failed or its result was lost. Check recovery below. If no change is pending, reload the page and preview again.'));
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
			this.message(_('Routing changes confirmed. Check destination traffic from a device.'));
		}
		catch (error) {
			this.message(_('Confirmation failed or expired. Refresh recovery status and check diagnostics over SSH.'));
			try { this.setPending(await api.call('pending')); }
			catch (pendingError) { this.loaded = false; }
		}
	},

	render: function(data) {
		const settings = data[0] || {};
		this.loaded = !!(data[0] && data[2] && data[3]);
		this.readonly = !L.hasViewPermission();
		this.busy = false;
		this.review = null;
		this.pending = { id: '' };
		this.pendingAt = Date.now();
		this.active = true;
		this.rowInputs = [];
		this.vpn = api.selection() || { mode: settings.mode, selection: settings.selection };
		this.feedback = E('p', { role: 'status', 'aria-live': 'polite' });
		this.presets = routing.catalog(data[3] && data[3].presets);
		try { this.rows = routing.rows(data[3] && data[3].rules, this.presets); }
		catch (error) { this.rows = routing.rows('', this.presets); this.loaded = false; this.message(error.message); }
		const input = (id, type) => E('input', { id: id, type: type || 'text', 'class': type === 'checkbox' ? 'cbi-input-checkbox' : 'cbi-input-text' });
		const button = (label, action) => E('button', { type: 'button', 'class': 'btn cbi-button-action', click: () => this.run(action) }, [label]);
		this.networks = input('routing-networks'); this.networks.value = settings.networks || '';
		this.peer = input('routing-peer');
		this.ack = input('routing-ack', 'checkbox'); this.ack.checked = settings.ipv6_acknowledged === '1';
		this.manual = input('routing-manual');
		this.suggestions = E('select', { id: 'routing-leases', 'class': 'cbi-input-select' }, [E('option', { value: '' }, [_('Choose a DHCP device')])]);
		this.leases = {};
		const leases = data[1] && typeof data[1].leases === 'string' ? data[1].leases.split('\n') : [];
		leases.slice(0, 64).forEach(line => {
			const pair = line.split('\t');
			if (pair.length === 2 && routing.ipv4(pair[0]) && /^[a-zA-Z0-9.-]{1,253}$/.test(pair[1])) {
				this.leases[pair[0]] = pair[1];
				this.suggestions.appendChild(E('option', { value: pair[0] }, [pair[1] + ' (' + pair[0] + ')']));
			}
		});
		this.addButton = button(_('Add device'), async () => this.addDevice());
		this.ruleArea = E('div');
		this.previewArea = E('div');
		this.previewButton = button(_('Preview changes'), () => this.preview());
		this.applyButton = button(_('Apply routing changes'), () => this.apply());
		this.confirmButton = button(_('Confirm router access'), () => this.confirm());
		this.refresh = E('button', { type: 'button', 'class': 'btn', click: () => this.run(async () => {
			try { this.setPending(await api.call('pending')); }
			catch (error) { this.loaded = false; throw error; }
			if (!this.pending.id)
				this.message(_('No change is awaiting confirmation. Reload the page to see saved rules.'));
		}, true) }, [_('Refresh recovery status')]);
		this.recovery = E('p', { role: 'status', 'aria-live': 'polite' });
		this.pendingArea = E('div', {}, [E('h3', {}, [_('Pending routing change')]), this.recovery,
			E('p', {}, [_('Leaving the change unconfirmed triggers automatic rollback. A failed recovery keeps its journal for repair over SSH.')]), this.confirmButton]);
		this.inputs = [this.networks, this.peer, this.ack, this.manual, this.suggestions, this.addButton];
		[this.networks, this.peer, this.ack].forEach(node => ['input', 'change'].forEach(event => node.addEventListener(event, () => this.invalidate())));
		this.renderRows();
		window.addEventListener('pagehide', () => {
			this.active = false;
			window.clearTimeout(this.timer);
		});
		window.addEventListener('pageshow', () => { this.active = true; this.tick(); });
		try { this.setPending(data[2]); }
		catch (error) { this.loaded = false; this.message(error.message); }
		if (!this.loaded && !this.feedback.textContent)
			this.message(_('Rules or recovery status could not be loaded. Reload before changing routing.'));
		if (this.readonly)
			this.message(_('You have read-only access. Ask an administrator to change routing settings.'));
		this.updateControls();
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('Routing rules')]),
			E('p', {}, [_('Choose which destinations go over the VPN. Other traffic keeps its existing routing. Only IPv4 is covered.')]),
			E('p', {}, [_('VPN: '), this.vpn.selection || _('None selected'), ' ', E('a', { href: L.url('admin/services/selective-vpn/vpn') }, [_('Choose VPN')])]),
			this.ruleArea,
			E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, [_('Add a device rule')]),
				field(_('DHCP device'), this.suggestions, data[1] ? _('DHCP addresses can change. Reserve an address for a stable rule.') :
					_('DHCP suggestions are unavailable. Enter an address instead.')),
				field(_('Or IPv4 address'), this.manual),
				this.addButton
			]),
			E('details', {}, [E('summary', {}, [_('Advanced')]),
				field(_('LAN networks'), this.networks, _('Leave blank for eligible networks in the LAN firewall zone. Enter interface names to select other local static networks.'))
			]),
			field(_('Your management device IPv4'), this.peer, _('The IPv4 address of the device you are using to manage this router.')),
			field(_('I understand the limitations'), this.ack, _('IPv6 is not covered. Domain matching needs router DNS; encrypted DNS and cached answers may bypass it. Check destination traffic after applying.')),
			this.previewButton, ' ', this.applyButton, this.feedback, this.previewArea, this.pendingArea, this.refresh
		]);
	}
});
