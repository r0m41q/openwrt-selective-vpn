'use strict';
'require view';
'require ui';
'require selective-vpn.api as api';

function field(label, input, help) {
	return E('div', { 'class': 'cbi-value' }, [
		E('label', { 'class': 'cbi-value-title', 'for': input.id }, [label]),
		E('div', { 'class': 'cbi-value-field' }, [
			input, help ? E('div', { 'class': 'cbi-value-description' }, [help]) : ''
		])
	]);
}

const problems = {
	disabled: _('The client is disabled.'),
	uci_only: _('The client has no configuration file. It can only be copied.'),
	hooks: _('The client runs custom scripts.'),
	device: _('Set a fixed tunnel name such as dev tun0, with dev-type tun.'),
	route_nopull: _('Add route-nopull so the server cannot change routing.'),
	ipv6_filter: _('Add pull-filter ignore "ifconfig-ipv6".'),
	routes: _('Remove redirect-gateway and route lines.'),
	dns: _('Remove dhcp-option and dns lines.'),
	unsupported: _('Unsupported setting: ')
};

function lines(text, pattern) {
	return typeof text === 'string' ? text.split('\n').filter(value => pattern.test(value)) : [];
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: async function() {
		const data = await Promise.all(['settings', 'profiles', 'clients'].map(name =>
			api.call(name).catch(() => null)));
		const status = await api.call('status').catch(() => null);
		return { settings: data[0], profiles: data[1], clients: data[2], status: status };
	},

	message: function(text) {
		this.feedback.textContent = text;
	},

	run: async function(action) {
		if (this.busy || this.readonly)
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

	current: function() {
		return { mode: this.mode.value, selection: this.mode.value === 'managed' ? this.profiles.value : this.clients.value };
	},

	updateControls: function() {
		const locked = this.busy || this.readonly || !this.loaded;
		[this.mode, this.profiles, this.clients, this.file, this.upload, this.save, this.username, this.password, this.copy].forEach(node => {
			node.disabled = locked;
		});
		this.refresh.disabled = this.busy;
		this.managed.hidden = this.mode.value !== 'managed';
		this.external.hidden = this.mode.value !== 'external';
		this.credentials.hidden = this.mode.value !== 'managed' || !this.authRequired;
		this.save.disabled = locked || !this.authRequired;
		this.copy.disabled = locked || !this.clients.value;
		this.reconnect.disabled = locked || this.settings.enabled !== '1' || this.settings.mode !== 'managed' ||
			this.current().mode !== 'managed' || this.current().selection !== this.settings.selection;
	},

	showSummary: async function() {
		this.authRequired = false;
		this.username.value = '';
		this.password.value = '';
		this.summary.replaceChildren();
		this.checks.replaceChildren();
		this.updateControls();
		if (this.mode.value === 'external' && this.clients.value)
			return this.showCheck();
		if (this.mode.value !== 'managed' || !this.profiles.value)
			return;
		const result = await api.call('profile_summary', this.profiles.value);
		const values = Object.create(null);
		String(result.summary || '').split('\n').forEach(line => {
			const index = line.indexOf('=');
			if (index > 0)
				values[line.slice(0, index)] = line.slice(index + 1);
		});
		if (values.auth_required !== '0' && values.auth_required !== '1')
			throw new Error(_('Profile summary is incomplete. Reload the page or import a replacement.'));
		this.authRequired = values.auth_required === '1';
		const rows = [
			[_('Tunnel device'), /^tun_sv[0-9]+$/.test(values.device) ? values.device : _('Unknown')],
			[_('Remote endpoints'), /^[0-9]{1,2}$/.test(values.remote_count) ? values.remote_count : _('Unknown')],
			[_('Peer verification'), values.peer_verification === 'fingerprint' ? _('Certificate fingerprint') :
				values.peer_verification === 'ca' ? _('Certificate authority') : _('Unknown')],
			...(/^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/.test(values.adopted_client || '') ? [[_('Replaces OpenVPN client'),
				values.adopted_client + ' (' + _('disabled when this profile starts') + ')']] : []),
			[_('Authentication'), this.authRequired ?
				(result.credentials_saved === true ? _('Credentials saved') : _('Username and password required')) :
				_('No username or password required')]
		];
		this.summary.replaceChildren(E('table', { 'class': 'table' }, rows.map(row =>
			E('tr', { 'class': 'tr' }, [E('th', { 'class': 'th' }, [row[0]]), E('td', { 'class': 'td' }, [row[1]])]))));
	},

	// everything that keeps an existing client from being used as it is
	showCheck: async function() {
		const result = await api.call('client_check', this.clients.value);
		const found = (typeof result.problems === 'string' ? result.problems.split('\n') : []).filter(Boolean).map(line => {
			const fields = line.split('\t');
			return Object.prototype.hasOwnProperty.call(problems, fields[0]) ?
				problems[fields[0]] + (fields[0] === 'unsupported' ? fields.slice(1).join(' ').slice(0, 160) : '') : '';
		}).filter(Boolean);
		this.checks.replaceChildren(found.length ? E('div', {}, [
			E('p', {}, [_('This client cannot be used as it is:')]),
			E('ul', {}, found.map(text => E('li', {}, [text]))),
			E('p', {}, [_('Fix these in its OpenVPN configuration, or copy it into a managed profile, which handles all of them.')])
		]) : E('p', {}, [_('This client looks compatible. Copying it into a managed profile also works.')]));
	},

	copyClient: async function() {
		const client = this.clients.value;
		if (!client)
			throw new Error(_('Choose a client first.'));
		this.message(_('Copying the client…'));
		const result = await api.call('adopt_client', client).catch(() => {
			throw new Error(_('The client could not be copied. Its certificate, key and password files must be readable by root and not writable by others, and the profile must pass the same checks as an upload.'));
		});
		if (!/^profile\.[a-zA-Z0-9]{8}$/.test(result.id))
			throw new Error(_('The copied profile could not be identified. Reload this page.'));
		this.profiles.appendChild(E('option', { value: result.id }, [result.id]));
		this.profiles.value = result.id;
		this.mode.value = 'managed';
		await this.select();
		this.message(_('Copied. The old client keeps running until you apply routing, then it is disabled. Its PBR policies can be imported on the Routing page.'));
	},

	select: async function() {
		this.message('');
		await this.showSummary();
		api.selection(this.current());
		this.message(_('Selected for your next routing change in this browser tab.'));
	},

	importProfile: async function() {
		const file = this.file.files[0];
		if (!file || file.size < 1 || file.size > 32768)
			throw new Error(_('Choose an OpenVPN profile between 1 and 32768 bytes.'));
		this.message(_('Importing profile…'));
		try {
			const text = await file.text();
			if (/[^\t\n\r\x20-\x7e]/.test(text))
				throw new Error(_('The profile contains unsupported characters.'));
			const result = await api.call('import_profile', text).catch(() => {
				throw new Error(_('Profile rejected. Use a TUN client profile with inline certificates or peer fingerprints. Scripts, plugins and insecure TLS options are unsupported. Check profile storage over SSH if the profile is valid.'));
			});
			if (!/^profile\.[a-zA-Z0-9]{8}$/.test(result.id))
				throw new Error(_('The imported profile could not be identified. Reload this page.'));
			this.profiles.appendChild(E('option', { value: result.id }, [result.id]));
			this.profiles.value = result.id;
			this.mode.value = 'managed';
			await this.select();
			this.message(_('Profile imported. Enter credentials if required, then apply your routing settings to start it.'));
		}
		finally {
			this.file.value = '';
		}
	},

	saveCredentials: async function() {
		const username = this.username.value;
		const password = this.password.value;
		const valid = value => new TextEncoder().encode(value).length >= 1 &&
			new TextEncoder().encode(value).length <= 127 && !/[\x00-\x1f\x7f]/.test(value);
		try {
			if (!valid(username) || !valid(password))
				throw new Error(_('Enter a username and password of 1 to 127 bytes each, without control characters.'));
			await api.call('set_credentials', this.profiles.value, username, password);
			await this.showSummary();
			this.message(this.settings.enabled === '1' && this.settings.mode === 'managed' && this.settings.selection === this.profiles.value ?
				_('Credentials saved. Reconnect the active managed VPN to use them.') :
				_('Credentials saved. Apply routing settings to start this profile.'));
		}
		finally {
			this.username.value = '';
			this.password.value = '';
		}
	},

	showStatus: function(report) {
		let text = _('VPN status is unavailable. Check the recovery service and diagnostics over SSH.');
		if (report && report.collection && report.collection.state === 'busy')
			text = _('Another operation is running. Refresh status when it finishes.');
		else if (report && report.dependencies && report.dependencies.openvpn === 'missing')
			text = _('OpenVPN is missing. Install openvpn-openssl before applying routing settings.');
		else if (report && report.configuration && report.configuration.enabled === false)
			text = _('Bypass is disabled. Apply routing settings to start the selected VPN.');
		else if (report && report.vpn) {
			if (report.vpn.tunnel === 'ready')
				text = _('The active VPN process and a usable tunnel IPv4 address were observed. Destination traffic has not been verified.');
			else if (report.vpn.process === 'stopped')
				text = _('The active VPN is stopped. Reconnect the managed client, or start your external client through its existing configuration.');
			else if (report.vpn.ipv4 === 'missing' || report.vpn.ipv4 === 'invalid')
				text = _('The active VPN has no usable tunnel IPv4. Check credentials, TLS settings and server reachability over SSH.');
		}
		this.status.textContent = text;
	},

	refreshStatus: async function() {
		try {
			this.showStatus(await api.call('status'));
		}
		catch (error) {
			this.showStatus(null);
			throw error;
		}
	},

	openReconnect: function() {
		if (this.reconnect.disabled)
			return;
		const peer = E('input', { 'class': 'cbi-input-text', id: 'selective-vpn-peer', type: 'text' });
		const start = E('button', { 'class': 'btn cbi-button-action', type: 'button', click: () => {
			const parts = peer.value.split('.');
			if (parts.length !== 4 || parts.some(value => !/^(0|[1-9][0-9]{0,2})$/.test(value) || +value > 255)) {
				peer.setCustomValidity(_('Enter the IPv4 address of the device you are using to manage this router.'));
				peer.reportValidity();
				return;
			}
			ui.hideModal();
			this.run(async () => {
				this.message(_('Reconnecting the managed VPN…'));
				const result = await api.call('reconnect', peer.value);
				if (typeof result.id !== 'string' || !result.id)
					throw new Error(_('No confirmation was returned. Check status before retrying.'));
				this.confirmation(result.id);
				await this.refreshStatus();
			});
		} }, [_('Reconnect')]);
		peer.addEventListener('input', () => peer.setCustomValidity(''));
		ui.showModal(_('Reconnect managed VPN'), [
			E('p', {}, [_('Matching traffic will pause briefly. Confirm the change within the remaining two-minute window after it starts, or the previous configuration will be restored automatically.')]),
			field(_('Your management device IPv4'), peer),
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', type: 'button', click: ui.hideModal }, [_('Cancel')]), ' ', start
			])
		]);
	},

	confirmation: function(id) {
		const feedback = E('p', { role: 'status' }, [_('Confirm only if you can still reach the router. An expired confirmation will be rejected.')]);
		const confirm = E('button', { 'class': 'btn cbi-button-apply', type: 'button', click: async () => {
			confirm.disabled = true;
			try {
				await api.call('confirm', id);
				ui.hideModal();
				this.message(_('Reconnect confirmed.'));
			}
			catch (error) {
				feedback.textContent = _('Confirmation failed or expired. Refresh status and check recovery over SSH.');
			}
		} }, [_('Confirm connection')]);
		ui.showModal(_('Keep this connection?'), [feedback,
			E('div', { 'class': 'right' }, [
				E('button', { 'class': 'btn', type: 'button', click: ui.hideModal }, [_('Leave unconfirmed')]), ' ', confirm
			])
		]);
		this.message(_('Reconnect is waiting for confirmation. Leaving it unconfirmed triggers automatic rollback.'));
	},

	render: function(data) {
		this.loaded = !!(data.settings && data.profiles && data.clients);
		this.settings = data.settings || {};
		this.readonly = !L.hasViewPermission();
		this.busy = false;
		this.authRequired = false;
		const button = (label, action) => E('button', { 'class': 'btn cbi-button-action', type: 'button', click: () => this.run(action) }, [label]);
		this.mode = E('select', { id: 'selective-vpn-mode', 'class': 'cbi-input-select' }, [
			E('option', { value: 'managed' }, [_('Imported profile')]),
			E('option', { value: 'external' }, [_('Existing OpenVPN client')])
		]);
		this.profiles = E('select', { id: 'selective-vpn-profile', 'class': 'cbi-input-select' }, [E('option', { value: '' }, [_('Choose a profile')])]);
		this.clients = E('select', { id: 'selective-vpn-client', 'class': 'cbi-input-select' }, [E('option', { value: '' }, [_('Choose a client')])]);
		lines(data.profiles && data.profiles.profiles, /^profile\.[a-zA-Z0-9]{8}$/).forEach(id => {
			this.profiles.appendChild(E('option', { value: id }, [id]));
		});
		lines(data.clients && data.clients.clients, /^[a-zA-Z_][a-zA-Z0-9_]{0,62}$/).filter(id => !/^svpn_/.test(id)).forEach(id => {
			this.clients.appendChild(E('option', { value: id }, [id]));
		});
		const selected = api.selection() || this.settings;
		this.mode.value = selected.mode === 'external' ? 'external' : 'managed';
		(this.mode.value === 'external' ? this.clients : this.profiles).value = selected.selection || '';
		[this.mode, this.profiles, this.clients].forEach(node => node.addEventListener('change', () => this.run(() => this.select())));
		this.file = E('input', { id: 'selective-vpn-upload', type: 'file', accept: '.ovpn,.conf', 'class': 'cbi-input-file' });
		this.upload = button(_('Import profile'), () => this.importProfile());
		this.username = E('input', { id: 'selective-vpn-username', type: 'text', autocomplete: 'off', 'class': 'cbi-input-text' });
		this.password = E('input', { id: 'selective-vpn-password', type: 'password', autocomplete: 'new-password', 'class': 'cbi-input-text' });
		this.save = button(_('Save credentials'), () => this.saveCredentials());
		this.summary = E('div');
		this.credentials = E('div', {}, [
			field(_('VPN username'), this.username), field(_('VPN password'), this.password),
			E('p', {}, [_('Saved credentials are never shown. Enter both fields to replace them.')]), this.save
		]);
		this.managed = E('div', {}, [field(_('Imported profile'), this.profiles),
			field(_('Upload or replace profile'), this.file, _('TUN client profile, up to 32 KiB. Certificates and keys must be inline.')),
			this.upload, this.summary, this.credentials
		]);
		this.checks = E('div');
		this.copy = button(_('Copy into a managed profile'), () => this.copyClient());
		this.external = E('div', {}, [field(_('Existing client'), this.clients),
			E('p', {}, [_('Start this client and manage its credentials through its existing OpenVPN configuration. Compatibility is checked before routing changes are applied.')]),
			this.checks, this.copy
		]);
		this.feedback = E('p', { role: 'status', 'aria-live': 'polite' });
		this.status = E('p', { role: 'status', 'aria-live': 'polite' });
		this.refresh = E('button', { 'class': 'btn', type: 'button', click: async () => {
			if (this.busy)
				return;
			this.busy = true;
			this.updateControls();
			try { await this.refreshStatus(); }
			catch (error) { this.message(error.message); }
			finally { this.busy = false; this.updateControls(); }
		} }, [_('Refresh status')]);
		this.reconnect = E('button', { 'class': 'btn cbi-button-action', type: 'button', click: () => this.openReconnect() }, [_('Reconnect active VPN')]);
		this.showStatus(data.status);
		this.updateControls();
		const root = E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, [_('VPN setup')]),
			E('p', {}, [_('Choose a VPN for selective routing. Importing or selecting a profile does not start it; apply your routing settings when ready.')]),
			field(_('VPN source'), this.mode), this.managed, this.external, this.feedback,
			E('h3', {}, [_('Active connection')]), this.status, this.refresh, ' ', this.reconnect
		]);
		if (!this.loaded)
			this.message(_('VPN settings could not be loaded. Check permissions and the recovery service, then reload this page.'));
		else {
			this.busy = true;
			this.updateControls();
			this.showSummary().catch(() => this.message(_('Profile summary is unavailable. Reload the page or import a replacement.'))).finally(() => {
				this.busy = false;
				this.updateControls();
			});
		}
		if (this.readonly)
			this.message(_('You have read-only access. Ask an administrator to change VPN settings.'));
		return root;
	}
});
