'use strict';
'require baseclass';
'require view';
'require selective-vpn.api as api';
'require selective-vpn.report as report';
'require selective-vpn.routing as routing';

const labels = {
	unknown: _('Unknown'), complete: _('Complete'), partial: _('Incomplete'), busy: _('Busy'), unavailable: _('Unavailable'),
	ready: _('Ready'), not_ready: _('Not ready'), running: _('Running'), stopped: _('Stopped'), unverified: _('Unverified'),
	usable: _('Usable'), missing: _('Missing'), invalid: _('Invalid'), attached: _('Attached'), detached: _('Detached'),
	present: _('Present'), absent: _('Absent'), match: _('Matches saved ownership'), changed: _('Changed'), stale: _('From an earlier boot'),
	supported: _('Supported'), unsupported: _('Unsupported'), not_required: _('Not required'), nonempty: _('Populated'), empty: _('Empty'),
	not_probed: _('Not tested'), valid: _('Valid'), found: _('Found'), ambiguous: _('Ambiguous'), observed: _('Observed'),
	none: _('None'), preparing: _('Preparing'), armed: _('Recovery armed'), applying: _('Applying'), applied: _('Applied'),
	awaiting_confirmation: _('Awaiting confirmation'), confirmed: _('Confirmed'), recovering: _('Recovering'),
	runtime_recovery: _('Service recovery needed'), conflict: _('Configuration conflict'), rolled_back: _('Rolled back'),
	available: _('Available'), summarized: _('Summarized'), not_requested: _('Not requested')
};

function policyName(name) {
	const parts = name.split('__');
	return (parts[0] === 'global' ? _('Global') : parts[0]) + (parts[1] ? ' (' + parts[1] + ')' : '');
}
const actions = {
	enable: { title: _('Enable saved routing'), help: _('Reapply the saved VPN, LAN networks and rules. Review changes on the Routing page when changing settings.') },
	reconnect: { title: _('Restart managed VPN'), help: _('Restart only the active managed VPN, then reapply saved routing. Existing external VPN clients are managed on their own configuration page.') },
	reload: { title: _('Reload PBR'), help: _('Reapply saved routing and reload the shared PBR service. Other policies keep their configured priority. The VPN is checked and started if needed.') },
	disable: { title: _('Disable routing'), help: _('Remove managed policies and forwarding, and stop the managed VPN. Saved selections and private profiles remain. External VPN clients stay running.') },
	rollback: { title: _('Restore previous configuration'), help: _('Restore the previous confirmed routing configuration. This requires a previous confirmed configuration and may start its VPN.') }
};

function display(value) {
	return typeof value === 'boolean' ? (value ? _('Yes') : _('No')) :
		typeof value === 'number' ? String(value) : labels[value] || _('Unknown');
}

function table(rows) {
	return E('table', { 'class': 'table' }, rows.map(row => E('tr', { 'class': 'tr' }, [
		E('th', { 'class': 'th' }, [row[0]]), E('td', { 'class': 'td' }, [row[1]])
	])));
}

const Monitor = view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,
	diagnostic: false,

	load: async function() {
		if (this.diagnostic) return null;
		const data = [];
		// these reads share the backend lifecycle lock
		for (const name of ['status', 'settings', 'pending']) {
			if (this.active === false) return null;
			data.push(await api.call(name).catch(() => null));
		}
		return data;
	},

	remaining: function() {
		return Math.max(0, (this.pending.seconds_remaining || 0) - Math.floor((Date.now() - this.pendingAt) / 1000));
	},

	setPending: function(value) {
		if (!value || typeof value.id !== 'string' || (value.id && (!/^[a-f0-9]{32}$/.test(value.id) ||
			!['preparing', 'armed', 'applying', 'applied', 'awaiting_confirmation', 'recovering', 'runtime_recovery', 'conflict'].includes(value.state))))
			throw new Error(_('Recovery status is unavailable. Refresh before making changes.'));
		this.pending = { id: value.id, state: value.state, seconds_remaining:
			Number.isInteger(value.seconds_remaining) && value.seconds_remaining >= 0 && value.seconds_remaining <= 120 ? value.seconds_remaining : 0 };
		this.pendingAt = Date.now();
		this.recoveryLoaded = true;
	},

	fresh: function() {
		return this.updatedAt != null && Date.now() - this.updatedAt < 60000;
	},

	controls: function() {
		const locked = !this.active || this.busy || this.readonly || !this.loaded || !this.fresh() || !!this.pending.id;
		for (const name of Object.keys(this.buttons)) {
			this.buttons[name].disabled = locked || (name === 'enable' ? this.settings.enabled !== '0' :
				['reconnect', 'reload', 'disable'].includes(name) && this.settings.enabled !== '1') ||
				(name === 'reconnect' && this.settings.mode !== 'managed');
		}
		this.peer.disabled = locked;
		this.execute.disabled = locked || !this.action;
		this.confirmButton.disabled = !this.active || this.busy || this.readonly || !this.recoveryLoaded ||
			this.pending.state !== 'awaiting_confirmation' || this.remaining() <= 0;
		this.refreshButton.disabled = !this.active || this.busy;
		this.downloadButton.disabled = this.busy || !this.fresh() || !this.cleaned;
	},

	accept: function(data) {
		this.loaded = false;
		this.recoveryLoaded = false;
		this.setPending(data && data[2]);
		if (!data || !data[0] || !data[1])
			throw new Error(_('Status is unavailable. Check your session and router connection, then refresh.'));
		this.cleaned = report.clean(data[0], 'status');
		this.detail = report.details(data[0]);
		this.settings = data[1];
		this.updatedAt = Date.now();
		this.loaded = ['complete', 'partial'].includes(this.cleaned.collection.state);
		this.draw();
	},

	draw: function() {
		const data = this.cleaned;
		if (!data) return;
		const rows = this.diagnostic ? [
			[_('Collection'), display(data.collection.state)],
			[_('Recovery'), display(data.recovery.state)],
			[_('Recovery supervisor'), display(data.recovery.supervisor)],
			[_('VPN process'), display(data.vpn.process)], [_('Tunnel IPv4'), display(data.vpn.ipv4)],
			[_('Logical VPN interface'), display(data.vpn.logical_interface)],
			[_('Main IPv4 default route'), display(data.routing.main_ipv4_default)],
			[_('IPv6 default route'), display(data.routing.ipv6_default)],
			[_('VPN policy table default'), display(data.routing.vpn_default)],
			[_('VPN mark rule'), display(data.routing.mark_rule)],
			[_('Activation route baseline'), display(data.routing.activation_baseline)],
			[_('Saved firewall candidate'), display(data.firewall.candidate)],
			[_('Saved VPN firewall zone'), display(data.firewall.zone)],
			[_('Saved masquerading'), display(data.firewall.masquerading)],
			[_('Saved input restricted'), display(data.firewall.input_restricted)],
			[_('Saved forwarding restricted'), display(data.firewall.forward_restricted)],
			[_('Domain resolution probe'), display(data.dns.resolution)],
			[_('Log summary'), display(data.logs.state)],
			[_('Recent authentication failures'), display(data.logs.authentication_failure)],
			[_('Recent TLS failures'), display(data.logs.tls_failure)],
			[_('Recent connection failures'), display(data.logs.connection_failure)],
			[_('Recent restarts'), display(data.logs.restart)]
		] : [
			[_('Routing enabled'), display(data.configuration.enabled)],
			[_('Tunnel'), display(data.vpn.tunnel)], [_('VPN process'), display(data.vpn.process)],
			[_('Tunnel interface'), this.detail.interface || _('Unknown')],
			[_('Tunnel IPv4 addresses'), this.detail.addresses.join(', ') || _('Unknown')],
			[_('Applied rules'), display(data.configuration.rules)],
			[_('Exit IP and country'), _('Not checked')]
		];
		rows.push(
			[_('PBR service'), display(data.pbr.service)], [_('PBR version'), display(data.pbr.version)],
			[_('PBR errors'), display(data.pbr.errors)], [_('PBR configuration'), display(data.pbr.policy_configuration)],
			[_('dnsmasq nftset capability'), display(data.dns.nftset_capability)],
			[_('DNS integration'), display(data.dns.integration)], [_('Owned DNS sets'), display(data.dns.sets)],
			[_('DNS set population'), display(data.dns.population)],
			[_('Tunnel evidence'), display(data.evidence.tunnel)],
			[_('Policy rule evidence'), display(data.evidence.policy_rules)],
			[_('Policy match evidence'), display(data.evidence.policy_matches)]
		);
		for (const name of Object.keys(data.policies))
			rows.push([policyName(name) + _(' rule / packets / bytes'),
				display(data.policies[name]) + ' / ' + display(data.packets[name]) + ' / ' + display(data.bytes[name])]);
		this.statusArea.replaceChildren(table(rows));
		const warnings = [];
		if (data.collection.state !== 'complete') warnings.push(_('Some checks are incomplete. Unknown values do not indicate a working connection.'));
		if (data.configuration.pending_uci !== 'absent') warnings.push(_('There may be unsaved UCI changes. Review them before recovery actions.'));
		if (data.configuration.owned_settings === 'changed') warnings.push(_('Managed configuration changed outside this application. Recovery may need SSH review.'));
		if (data.configuration.enabled === true && (data.vpn.tunnel !== 'ready' || data.vpn.logical_interface !== 'attached' ||
			data.pbr.service !== 'running' || data.pbr.version !== 'supported' || data.pbr.errors !== 'absent' ||
			data.routing.main_ipv4_default !== 'present' || data.routing.vpn_default !== 'present' ||
			data.routing.mark_rule !== 'present' || data.evidence.policy_rules !== 'observed'))
			warnings.push(_('Routing prerequisites are missing or unverified. Check VPN, PBR, routes and diagnostics.'));
		if (data.configuration.enabled === true && !['ready', 'not_required'].includes(data.dns.integration)) warnings.push(_('Domain routing is not ready. Check router DNS and dnsmasq nftset support.'));
		if (data.vpn.replaced_client === 'running') warnings.push(_('The OpenVPN client this profile replaced is running again. Two connections to one provider can drop each other; stop the old client.'));
		if (data.configuration.enabled === true && data.recovery.supervisor !== 'running') warnings.push(_('The recovery supervisor is not confirmed running. Check it over SSH before network changes.'));
		this.warnings.replaceChildren(...warnings.map(text => E('p', { 'class': 'alert-message warning' }, [text])));
		if (!this.diagnostic) {
			const policies = this.detail.policies;
			const domains = new Set(policies.flatMap(policy => policy.destinations).filter(value => /[a-z]/.test(value)));
			this.scopeArea.replaceChildren(
				E('p', {}, [_('Configured routed domains: ') + (data.pbr.policy_configuration === 'match' ? domains.size : _('Unknown'))]),
				...policies.map(policy => E('p', {}, [policyName(policy.name) + ': ' + policy.sources.join(', ') + ' → ' +
					policy.destinations.join(', ') + ' (' + policy.protocols.join('/').toUpperCase() +
					(policy.ports.length ? ' ' + policy.ports.join(', ') : '') + ')'])),
				E('p', {}, [_('These are the saved IPv4 routes for each rule. Rule evidence above shows whether the matching managed rules were observed; domain counts do not show successful DNS resolution.')])
			);
		}
		else this.scopeArea.replaceChildren(table(Object.keys(data.dependencies).map(name => [name, display(data.dependencies[name])])));
	},

	schedule: function() {
		if (this.pollTimer != null) window.clearTimeout(this.pollTimer);
		this.pollTimer = null;
		if (!this.diagnostic && this.active && !document.hidden && this.auto.checked && !this.busy)
			this.pollTimer = window.setTimeout(() => this.refresh(), 30000);
	},

	tick: function() {
		if (this.tickTimer != null) window.clearTimeout(this.tickTimer);
		this.tickTimer = null;
		this.age.textContent = this.updatedAt == null ? _('No report collected.') :
			(this.fresh() ? _('Seconds since last report: ') : _('Stale report. Seconds since last update: ')) + Math.max(0, Math.floor((Date.now() - this.updatedAt) / 1000));
		this.recovery.textContent = this.pending.id ?
			(display(this.pending.state) + (this.remaining() > 0 ? _(' — seconds remaining: ') + this.remaining() : _(' — refresh recovery status; leave the recovery service running.'))) : '';
		this.controls();
		if (this.active && !document.hidden) this.tickTimer = window.setTimeout(() => this.tick(), 1000);
	},

	refresh: async function() {
		if (this.busy || !this.active || document.hidden) return;
		this.busy = true;
		this.controls();
		try {
			if (this.diagnostic) {
				const value = report.clean(await api.call('doctor'), 'doctor');
				if (!this.active) return;
				this.cleaned = value;
				this.updatedAt = Date.now();
				this.draw();
			}
			else {
				const data = await this.load();
				if (!this.active) return;
				this.accept(data);
			}
			this.feedback.textContent = _('Report updated.');
		}
		catch (error) {
			this.loaded = false;
			this.updatedAt = null;
			this.cleaned = null;
			this.statusArea.replaceChildren();
			this.scopeArea.replaceChildren();
			this.warnings.replaceChildren();
			this.auto.checked = false;
			this.feedback.textContent = _('Refresh failed. Check your session, permissions and router connection. Automatic updates are paused.');
		}
		finally {
			this.busy = false;
			this.tick();
			this.schedule();
		}
	},

	choose: function(name) {
		if (!Object.prototype.hasOwnProperty.call(actions, name) || this.buttons[name].disabled) return;
		this.action = name;
		this.actionHelp.textContent = actions[name].help + _(' Enter the IPv4 address of your management device. Confirm router access after the change, or it will roll back.');
		this.execute.textContent = actions[name].title;
		this.controls();
	},

	mutate: async function(confirm) {
		if (this.busy || !this.active || this.readonly || (confirm ? !this.recoveryLoaded : !this.loaded)) return;
		const name = this.action;
		if (confirm ? this.confirmButton.disabled : !name || this.buttons[name].disabled) return;
		if (!confirm && !routing.ipv4(this.peer.value)) {
			this.feedback.textContent = _('Enter the IPv4 address of the device you are using to manage this router.');
			return;
		}
		this.busy = true;
		this.controls();
		this.feedback.textContent = _('Changing routing. Keep this page open…');
		try {
			const value = await api.call(confirm ? 'confirm' : name === 'reload' ? 'enable' : name, confirm ? this.pending.id : this.peer.value);
			if (!confirm && !/^[a-f0-9]{32}$/.test(value.id)) throw new Error('pending');
			const pending = await api.call('pending');
			this.setPending(pending);
			if (!confirm && pending.id !== value.id) throw new Error('pending');
			this.feedback.textContent = confirm ? _('Change confirmed. Refresh status to check the result.') :
				_('Change applied. Confirm below only if router access still works.');
		}
		catch (error) {
			this.feedback.textContent = _('The operation failed or its result was lost. It has not been retried. Check recovery status and SSH diagnostics before trying again.');
			try { this.setPending(await api.call('pending')); }
			catch (pendingError) { this.loaded = this.recoveryLoaded = false; }
		}
		finally {
			this.action = null;
			this.busy = false;
			this.updatedAt = null;
			this.cleaned = null;
			this.statusArea.replaceChildren();
			this.scopeArea.replaceChildren();
			this.warnings.replaceChildren();
			this.tick();
			this.schedule();
		}
	},

	download: function() {
		if (this.downloadButton.disabled || !this.cleaned) return;
		const clean = report.clean(this.cleaned, 'doctor');
		E('a', { href: 'data:application/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(clean, null, 2) + '\n'), download: 'selective-vpn-diagnostics.json' }).click();
	},

	render: function(data) {
		this.active = true; this.busy = false; this.loaded = this.recoveryLoaded = false;
		this.readonly = !L.hasViewPermission();
		this.settings = {}; this.pending = { id: '' }; this.pendingAt = Date.now();
		this.cleaned = null; this.updatedAt = null; this.buttons = {}; this.action = null;
		this.feedback = E('p', { role: 'status', 'aria-live': 'polite' });
		this.age = E('p'); this.recovery = E('p'); this.statusArea = E('div'); this.scopeArea = E('div'); this.warnings = E('div');
		this.peer = E('input', { id: 'recovery-peer', type: 'text', 'class': 'cbi-input-text', placeholder: _('Management device IPv4') });
		this.actionHelp = E('p');
		const button = (label, handler) => E('button', { type: 'button', 'class': 'btn cbi-button-action', click: handler }, [label]);
		this.execute = button(_('Choose a recovery action'), () => this.mutate(false));
		this.confirmButton = button(_('Confirm router access'), () => this.mutate(true));
		this.refreshButton = button(this.diagnostic ? _('Run diagnostics') : _('Refresh status'), () => this.refresh());
		this.downloadButton = button(_('Download redacted report'), () => this.download());
		this.auto = E('input', { type: 'checkbox', change: () => this.schedule() });
		this.auto.checked = !this.diagnostic;
		for (const name of Object.keys(actions)) this.buttons[name] = button(actions[name].title, () => this.choose(name));
		const link = (path, text) => E('a', { 'class': 'btn', href: L.url('admin', 'services', 'selective-vpn', path) }, [text]);
		const root = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [this.diagnostic ? _('Selective VPN diagnostics') : _('Selective VPN status')]),
			this.feedback, this.age, this.refreshButton,
			this.diagnostic ? this.downloadButton : E('label', {}, [this.auto, _(' Refresh every 30 seconds')]),
			this.warnings, this.statusArea, this.scopeArea,
			E('p', {}, [_('IPv4 policies require router DNS for domains. Encrypted DNS, cached answers and IPv6 may bypass them. Counters show rule matches; VPN egress and destination access remain unverified.')]),
			this.diagnostic ? E('p', {}, [_('The download contains fixed status fields and log category counts, without addresses, domains, credentials or raw logs. Log counts include all OpenVPN clients and may describe earlier failures. Firewall values describe saved configuration.')]) :
				E('div', {}, [link('routing', _('Review and apply routing')), link('vpn', _('VPN configuration')), link('diagnostics', _('Diagnostics'))]),
			E('div', { hidden: this.diagnostic }, [
				E('h3', {}, [_('Recovery')]), ...Object.values(this.buttons), this.actionHelp,
				E('label', { 'for': 'recovery-peer' }, [_('Management device IPv4')]), this.peer, this.execute, this.recovery, this.confirmButton
			])
		]);
		if (data) {
			try { this.accept(data); }
			catch (error) { this.feedback.textContent = error.message; }
		}
		window.addEventListener('pagehide', () => { this.active = false; this.stopTimers(); });
		window.addEventListener('pageshow', () => { this.active = true; this.tick(); this.schedule(); });
		document.addEventListener('visibilitychange', () => {
			this.stopTimers();
			if (this.active && !document.hidden) { this.tick(); this.schedule(); }
		});
		this.tick(); this.schedule();
		return root;
	},

	stopTimers: function() {
		if (this.pollTimer != null) window.clearTimeout(this.pollTimer);
		if (this.tickTimer != null) window.clearTimeout(this.tickTimer);
		this.pollTimer = this.tickTimer = null;
	}
});

// luci requires give an instance, so pages extend the view class from here
return baseclass.extend({ View: Monitor });
