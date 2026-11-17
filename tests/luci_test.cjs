const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const resources = path.join(__dirname, '../luci-app-selective-vpn/htdocs/luci-static/resources');

function load(file, dependencies) {
	const source = readFileSync(path.join(resources, file), 'utf8');
	return vm.runInNewContext('(function() {\n' + source + '\n})()', {
		_: text => text, TextEncoder, ...dependencies
	});
}

function apiFixture(handler) {
	const storage = new Map();
	const events = {};
	let now = 0;
	const calls = [];
	const api = load('selective-vpn/api.js', {
		baseclass: { extend: value => value },
		L: { env: { sessionid: 'test-session' } },
		Date: { now: () => now },
		window: {
			addEventListener: (event, fn) => { events[event] = fn; },
			setTimeout: (fn, delay) => { now += delay; queueMicrotask(fn); },
			sessionStorage: {
				setItem: (key, value) => storage.set(key, value),
				getItem: key => storage.get(key) || null
			}
		},
		rpc: { declare: options => async (...args) => {
			calls.push({ options, args });
			return handler(options.method, args);
		} }
	});
	return { api, calls, storage, events };
}

test('RPC jobs are polled until complete, including status without an ok field', async () => {
	let polls = 0;
	const f = apiFixture(method => method !== 'job' ? { ok: true, job: 'job-1' } :
		++polls === 1 ? { ok: true, state: 'running' } :
			{ ok: true, state: 'complete', result: { schema: 2, vpn: { tunnel: 'ready' } } });
	assert.equal((await f.api.call('status')).vpn.tunnel, 'ready');
	assert.equal(polls, 2);
	assert.equal(f.calls[0].options.reject, true);
	assert.deepEqual(f.calls[1].args, ['job-1']);
});

test('RPC failures, expired jobs and lost sessions do not expose response text', async () => {
	for (const response of [null, 6, { ok: false }, { ok: true, state: 'complete', result: { ok: false, error: 'secret-password' } }]) {
		const f = apiFixture(method => method === 'job' ? response : { ok: true, job: 'job-1' });
		await assert.rejects(f.api.call('set_credentials', 'profile.abcdefgh', 'alice', 'secret-password'),
			error => !error.message.includes('secret-password'));
	}
	const f = apiFixture(() => { throw new Error('secret-password'); });
	await assert.rejects(f.api.call('clients'), error => !error.message.includes('secret-password'));
	await assert.rejects(f.api.call('execute'), /Unknown operation/);
});

test('job polling stops at its deadline or on navigation', async () => {
	const f = apiFixture(method => method === 'job' ? { ok: true, state: 'running' } : { ok: true, job: 'job-1' });
	await assert.rejects(f.api.call('clients'), /may still be running/);
	assert.ok(f.calls.length <= 201);
	f.events.pagehide();
	const before = f.calls.length;
	await assert.rejects(f.api.call('clients'), /no longer active/);
	assert.equal(f.calls.length, before);
	f.events.pageshow();
});

test('the saved selection contains only validated identifiers', () => {
	const f = apiFixture(() => {});
	f.api.selection({ mode: 'managed', selection: 'profile.abcdefgh', password: 'secret-password' });
	assert.equal(f.api.selection().selection, 'profile.abcdefgh');
	assert.ok(![...f.storage.values()].join('').includes('secret-password'));
	assert.throws(() => f.api.selection({ mode: 'managed', selection: '../private' }));
	assert.throws(() => f.api.selection({ mode: 'external', selection: 'svpn_client' }));
	assert.throws(() => f.api.selection({ mode: 'external' }));
	f.api.selection({ mode: 'external', selection: '_personal' });
	assert.equal(f.api.selection().mode, 'external');
});

class Element {
	constructor(tag, attributes = {}, children = []) {
		this.tag = tag;
		this.attributes = attributes;
		this.children = [];
		this.events = {};
		this.disabled = false;
		this.value = '';
		this.id = attributes.id;
		if (attributes.value != null) this.value = attributes.value;
		Object.entries(attributes).forEach(([key, value]) => {
			if (typeof value === 'function') this.events[key] = value;
		});
		children.forEach(child => this.appendChild(child));
	}
	appendChild(child) { this.children.push(child); return child; }
	replaceChildren(...children) { this.children = children; }
	addEventListener(event, fn) { this.events[event] = fn; }
	setCustomValidity(text) { this.validation = text; }
	reportValidity() { return !this.validation; }
}

function descendants(node) {
	return [node, ...(node.children || []).flatMap(child => typeof child === 'object' ? descendants(child) : [])];
}

function viewFixture(handler, writable = true) {
	const calls = [];
	const selections = [];
	const ui = { showModal: (title, children) => { ui.modal = { title, children }; }, hideModal: () => { ui.modal = null; } };
	const view = load('view/selective-vpn/vpn.js', {
		view: { extend: value => value }, ui,
		L: { hasViewPermission: () => writable },
		E: (tag, attributes, children) => new Element(tag, attributes, children),
		api: {
			call: async (...args) => { calls.push(args); return handler(...args); },
			selection: value => { if (value) selections.push(value); return null; }
		}
	});
	return { view, calls, selections, ui };
}

const baseData = {
	settings: { enabled: '1', mode: 'managed', selection: 'profile.abcdefgh' },
	profiles: { profiles: 'profile.abcdefgh' }, clients: { clients: 'personal\nsvpn_client\n<script>' },
	status: { configuration: { enabled: true }, vpn: { tunnel: 'ready' } }
};
const summary = auth => ({ ok: true, summary: `device=tun_sv0\nauth_required=${auth}\nremote_count=1\npeer_verification=ca`, credentials_saved: true });
const settle = () => new Promise(resolve => setImmediate(resolve));

test('VPN view shows sanitized summaries and keeps credentials blank', async () => {
	const f = viewFixture(() => summary(1));
	const root = f.view.render(baseData);
	await settle();
	assert.equal(f.view.username.value, '');
	assert.equal(f.view.password.value, '');
	assert.equal(f.view.credentials.hidden, false);
	assert.equal(f.view.clients.children.length, 2);
	assert.match(f.view.status.textContent, /has not been verified/);
	assert.ok(descendants(root).every(node => node.innerHTML === undefined));
	f.view.username.value = 'alice';
	f.view.password.value = 'secret-password';
	await f.view.run(() => f.view.saveCredentials());
	assert.ok(f.calls.some(call => call[0] === 'set_credentials' && call[3] === 'secret-password'));
	assert.equal(f.view.username.value, '');
	assert.equal(f.view.password.value, '');
	assert.ok(!f.view.feedback.textContent.includes('secret-password'));
});

test('credential failures clear both fields, and certificate profiles hide them', async () => {
	let fail = false;
	const f = viewFixture(method => {
		if (fail && method === 'set_credentials') throw new Error('Save failed.');
		return summary(1);
	});
	f.view.render(baseData);
	await settle();
	f.view.username.value = 'alice'; f.view.password.value = 'secret-password';
	fail = true;
	await f.view.run(() => f.view.saveCredentials());
	assert.equal(f.view.password.value, '');
	assert.equal(f.view.username.value, '');
	assert.match(f.view.feedback.textContent, /Save failed/);
	const certificate = viewFixture(() => summary(0));
	certificate.view.render(baseData);
	await settle();
	assert.equal(certificate.view.credentials.hidden, true);
});

test('profile replacement selects the new bundle without applying routing', async () => {
	const f = viewFixture(method => method === 'import_profile' ? { ok: true, id: 'profile.ABC12345' } : summary(0));
	f.view.render(baseData);
	await settle();
	f.view.file.files = [{ size: 7, text: async () => 'client\n' }];
	await f.view.run(() => f.view.importProfile());
	assert.equal(f.view.profiles.value, 'profile.ABC12345');
	assert.equal(f.selections.at(-1).selection, 'profile.ABC12345');
	assert.equal(f.view.file.value, '');
	assert.equal(f.view.reconnect.disabled, true);
	assert.ok(!f.calls.some(call => ['apply', 'enable', 'reconnect'].includes(call[0])));
});

test('invalid uploads are rejected before RPC and backend errors stay private', async () => {
	const f = viewFixture(method => {
		if (method === 'import_profile') throw new Error('private-key-material');
		return summary(0);
	});
	f.view.render(baseData);
	await settle();
	for (const file of [{ size: 32769 }, { size: 3, text: async () => 'a\0b' }]) {
		f.view.file.files = [file];
		await f.view.run(() => f.view.importProfile());
	}
	assert.ok(!f.calls.some(call => call[0] === 'import_profile'));
	f.view.file.files = [{ size: 7, text: async () => 'client\n' }];
	await f.view.run(() => f.view.importProfile());
	assert.match(f.view.feedback.textContent, /TUN client profile/);
	assert.ok(!f.view.feedback.textContent.includes('private-key-material'));
});

test('read-only access and failed loading disable mutations', async () => {
	for (const [data, writable] of [[baseData, false], [{ ...baseData, settings: null }, true]]) {
		const f = viewFixture(() => summary(1), writable);
		f.view.render(data);
		await settle();
		assert.equal(f.view.upload.disabled, true);
		assert.equal(f.view.save.disabled, true);
		assert.equal(f.view.reconnect.disabled, true);
		f.view.openReconnect();
		assert.equal(f.ui.modal, undefined);
	}
});

test('reconnect asks for management IPv4 and confirms the returned transaction only', async () => {
	const f = viewFixture(method => method === 'reconnect' ? { ok: true, id: 'transaction-1' } :
		method === 'status' ? baseData.status : method === 'confirm' ? { ok: true } : summary(1));
	f.view.render(baseData);
	await settle();
	f.view.openReconnect();
	const nodes = f.ui.modal.children.flatMap(descendants);
	const peer = nodes.find(node => node.id === 'selective-vpn-peer');
	const start = nodes.find(node => node.tag === 'button' && node.children[0] === 'Reconnect');
	peer.value = 'bad-address';
	start.events.click();
	assert.ok(peer.validation);
	assert.ok(!f.calls.some(call => call[0] === 'reconnect'));
	peer.value = '192.168.8.2';
	start.events.click();
	await settle();
	assert.ok(f.calls.some(call => call[0] === 'reconnect' && call[1] === '192.168.8.2'));
	assert.equal(f.ui.modal.title, 'Keep this connection?');
	const confirm = f.ui.modal.children.flatMap(descendants).find(node => node.tag === 'button' && node.children[0] === 'Confirm connection');
	await confirm.events.click();
	assert.ok(f.calls.some(call => call[0] === 'confirm' && call[1] === 'transaction-1'));
	assert.match(f.view.feedback.textContent, /confirmed/);
});

test('reconnect failure does not offer confirmation', async () => {
	const f = viewFixture(method => {
		if (method === 'reconnect') throw new Error('Reconnect failed.');
		return summary(1);
	});
	f.view.render(baseData);
	await settle();
	f.view.openReconnect();
	const nodes = f.ui.modal.children.flatMap(descendants);
	nodes.find(node => node.id === 'selective-vpn-peer').value = '192.168.8.2';
	nodes.find(node => node.tag === 'button' && node.children[0] === 'Reconnect').events.click();
	await settle();
	assert.equal(f.ui.modal, null);
	assert.match(f.view.feedback.textContent, /Reconnect failed/);
	assert.ok(!f.calls.some(call => call[0] === 'confirm'));
});

const routingLogic = () => load('selective-vpn/routing.js', { baseclass: { extend: value => value } });
const vpnSelection = { mode: 'managed', selection: 'profile.abcdefgh' };
const presetText = 'xcloud_native\txCloud native\t\nxcloud_native_static\txCloud native static IPs (experimental)\tstatic_console_addresses_may_be_outdated\n';
const ruleRow = changes => ({ name: 'global', address: '', presets: [], destinations: '', tcp: true, udp: true, ports: '', ...changes });
const routingForm = changes => ({ networks: '', ack: true, peer: '192.168.8.2', ...changes });
const reviewResult = changes => ({ lan_networks: 'lan', lan_subnets: '192.168.8.0/24', interface: 'svpn_vpn',
	dns: 'dnsmasq.nftset', warnings: '', review: 'a'.repeat(64),
	routes: 'global\t\t192.168.8.0/25 192.168.8.128/26\texample.org\ttcp udp\t\n' +
		'global\txcloud_native\t192.168.8.0/25\txsts.auth.xboxlive.com\ttcp\t443', ...changes });
const optOut = '\ntv\t\t192.168.8.30\t\ttcp udp\t';
const texts = node => typeof node === 'string' ? [node] : (node.children || []).flatMap(texts);

test('saved rules load global first and serialize back with presets and ports', () => {
	const logic = routingLogic();
	const presets = logic.catalog(presetText + 'bad id\tx\t\n');
	assert.deepEqual(Array.from(presets, preset => preset.id), ['xcloud_native', 'xcloud_native_static']);
	const rows = logic.rows('rule tv\naddress 192.168.8.30\nproto udp\n', presets);
	assert.equal(rows[0].name, 'global');
	assert.equal(rows[1].udp, true);
	assert.equal(rows[1].tcp, false);
	const text = logic.serialize([ruleRow({ presets: ['xcloud_native', 'unknown'], destinations: 'EXAMPLE.ORG\n198.51.100.0/24', tcp: true, udp: false, ports: '443 8000-8010' }),
		ruleRow({ name: 'tv', address: '192.168.8.30' })], presets);
	assert.equal(text, 'rule global\nproto tcp\ndest_port 443 8000-8010\ndestinations example.org 198.51.100.0/24\npreset xcloud_native\n' +
		'rule tv\naddress 192.168.8.30\nproto tcp udp\n');
	assert.deepEqual(Array.from(logic.rows(text, presets), row => row.name), ['global', 'tv']);
	assert.throws(() => logic.rows('rule $(id)\n', presets), /could not be read/);
	assert.throws(() => logic.rows('address 192.168.8.30\n', presets), /could not be read/);
});

test('invalid rules and routing fields are rejected before any request', () => {
	const logic = routingLogic();
	const presets = logic.catalog(presetText);
	const device = changes => ruleRow({ name: 'tv', address: '192.168.8.30', ...changes });
	for (const rows of [
		[device()], [ruleRow(), device({ name: 'my__tv' })], [ruleRow(), device({ name: 'svpn_tv' })],
		[ruleRow(), device({ name: 'main' })], [ruleRow(), device({ name: 'global' })], [ruleRow(), device({ name: '' })],
		[ruleRow(), device({ address: '999.1.1.1' })], [ruleRow(), device(), device({ name: 'tv2' })],
		[ruleRow(), device(), device()], [ruleRow({ tcp: false, udp: false })], [ruleRow({ ports: '0' })],
		[ruleRow({ ports: '70000' })], [ruleRow({ ports: '10-5' })], [ruleRow({ destinations: '0.0.0.0/0' })],
		[ruleRow({ destinations: '$(id)' })], [ruleRow({ destinations: 'x'.repeat(4097) })],
		[ruleRow(), ...Array.from({ length: 24 }, (_, i) => device({ name: 'd' + i, address: '192.168.8.' + (i + 10) }))]
	]) assert.throws(() => logic.options(routingForm(), vpnSelection, rows, presets));
	for (const changes of [{ networks: 'lan;id' }, { ack: false }, { peer: 'not-an-address' }])
		assert.throws(() => logic.options(routingForm(changes), vpnSelection, [ruleRow()], presets));
	assert.throws(() => logic.options(routingForm(), {}, [ruleRow()], presets), /Choose a VPN/);
	const args = logic.options(routingForm(), vpnSelection, [ruleRow()], presets);
	assert.deepEqual(Array.from(args), ['managed', 'profile.abcdefgh', '', 'rule global\nproto tcp udp\n', '1', '192.168.8.2']);
});

test('malformed previews cannot authorize apply', () => {
	const logic = routingLogic();
	const presets = logic.catalog(presetText);
	const args = logic.options(routingForm(), vpnSelection, [ruleRow(), ruleRow({ name: 'tv', address: '192.168.8.30' })], presets);
	assert.equal(logic.preview(reviewResult({ routes: reviewResult().routes + optOut }), args).routes.length, 3);
	for (const changes of [{ review: '' }, { routes: '' }, { routes: undefined }, { dns: 'unsupported' },
		{ routes: 'phone\t\t192.168.8.12\t\ttcp\t' }, { routes: 'global\t\t0.0.0.0/0\t\ttcp\t' },
		{ routes: 'global\t\t192.168.8.0/24\t$(id)\ttcp\t' }, { routes: 'global\tBad__id\t192.168.8.0/24\t\ttcp\t' },
		{ routes: 'global\t\t192.168.8.0/24\t\ticmp\t' }, { routes: 'global\t\t192.168.8.0/24\t\ttcp' }])
		assert.throws(() => logic.preview(reviewResult(changes), args));
});

const routingData = changes => [{}, { leases: '192.168.8.12\tXbox-One\n192.168.8.13\t-\n' }, { id: '' },
	{ rules: 'rule global\npreset xcloud_native\ndestinations example.org\n', presets: presetText }, ...(changes || [])];

function routingFixture(handler = () => {}, writable = true, data = routingData()) {
	const calls = [];
	const events = {};
	const timers = new Map();
	let nextTimer = 0, now = 0;
	const view = load('view/selective-vpn/routing.js', {
		view: { extend: value => value }, routing: routingLogic(),
		L: { hasViewPermission: () => writable, url: value => '/' + value },
		Date: { now: () => now },
		window: {
			addEventListener: (event, fn) => { events[event] = fn; },
			setTimeout: fn => { timers.set(++nextTimer, fn); return nextTimer; },
			clearTimeout: id => timers.delete(id)
		},
		E: (tag, attributes, children) => new Element(tag, attributes, children),
		api: { selection: () => vpnSelection, call: async (...args) => {
			calls.push(args);
			return handler(...args);
		} }
	});
	const root = view.render(data);
	view.peer.value = '192.168.8.2'; view.ack.checked = true;
	return { view, calls, root, events, timers, advance: seconds => {
		now += seconds * 1000;
		const current = [...timers.values()]; timers.clear(); current.forEach(fn => fn());
	} };
}

test('new device rules copy Global and take names from DHCP hostnames', async () => {
	const f = routingFixture(() => reviewResult());
	assert.equal(f.view.rows.length, 1);
	assert.equal(f.view.applyButton.disabled, true);
	f.view.suggestions.value = '192.168.8.12';
	await f.view.run(() => f.view.addDevice());
	assert.deepEqual({ ...f.view.rows[1], presets: Array.from(f.view.rows[1].presets) }, { name: 'xbox_one', address: '192.168.8.12',
		presets: ['xcloud_native'], destinations: 'example.org', tcp: true, udp: true, ports: '' });
	f.view.rows[0].presets.push('xcloud_native_static');
	assert.deepEqual(Array.from(f.view.rows[1].presets), ['xcloud_native']);
	f.view.manual.value = '192.168.8.40';
	await f.view.run(() => f.view.addDevice());
	assert.equal(f.view.rows[2].name, 'device_192_168_8_40');
	f.view.manual.value = '192.168.8.40';
	await f.view.run(() => f.view.addDevice());
	assert.equal(f.view.rows.length, 3);
	assert.match(f.view.feedback.textContent, /only have one routing rule/);
	assert.ok(!f.calls.length);
	assert.ok(descendants(f.root).every(node => node.innerHTML === undefined));
});

test('preview sends the rule rows and lists every route, including opt-outs', async () => {
	const f = routingFixture(() => reviewResult({ routes: reviewResult().routes + optOut }));
	f.view.manual.value = '192.168.8.30';
	await f.view.run(() => f.view.addDevice());
	f.view.rows[1].name = 'tv';
	f.view.rows[1].presets = [];
	f.view.rows[1].destinations = '';
	await f.view.run(() => f.view.preview());
	const sent = f.calls.find(call => call[0] === 'preview');
	assert.equal(sent[4], 'rule global\nproto tcp udp\ndestinations example.org\npreset xcloud_native\nrule tv\naddress 192.168.8.30\nproto tcp udp\n');
	assert.equal(f.view.applyButton.disabled, false);
	const text = texts(f.view.previewArea).join('|');
	assert.match(text, /Global · xCloud native\|192\.168\.8\.0\/25\|xsts\.auth\.xboxlive\.com\|TCP ports 443/);
	assert.match(text, /tv\|192\.168\.8\.30\|None, normal connection/);
});

test('preview errors keep apply disabled', async () => {
	for (const code of ['rules', 'vpn_scope', 'dns_policy']) {
		const api = apiFixture(method => method === 'job' ? { ok: true, state: 'complete', result: { ok: false, code, error: 'private-secret' } } : { ok: true, job: '1' }).api;
		await assert.rejects(api.call('preview'), error => /could not be saved|Preview failed/.test(error.message) && !error.message.includes('private-secret'));
	}
	const f = routingFixture(() => { throw new Error('Preview failed. Check DNS.'); });
	await f.view.run(() => f.view.preview());
	assert.equal(f.view.applyButton.disabled, true);
	assert.ok(!f.calls.some(call => call[0] === 'apply'));
});

test('invalid rows do not send preview or apply requests', async () => {
	const f = routingFixture(() => reviewResult());
	f.view.rows[0].tcp = false; f.view.rows[0].udp = false;
	await f.view.run(() => f.view.preview());
	await f.view.run(() => f.view.apply());
	assert.equal(f.calls.length, 0);
	assert.match(f.view.feedback.textContent, /Preview the current rules/);
});

test('edits invalidate preview and apply also checks rows without input events', async () => {
	const f = routingFixture(() => reviewResult());
	await f.view.run(() => f.view.preview());
	assert.equal(f.view.applyButton.disabled, false);
	f.view.networks.value = 'lan';
	f.view.networks.events.input();
	assert.equal(f.view.applyButton.disabled, true);
	await f.view.run(() => f.view.preview());
	f.view.rows[0].destinations = 'example.net';
	await f.view.run(() => f.view.apply());
	assert.ok(!f.calls.some(call => call[0] === 'apply'));
	await f.view.run(() => f.view.preview());
	f.view.rows[0].presets.push('xcloud_native_static');
	await f.view.run(() => f.view.apply());
	assert.ok(!f.calls.some(call => call[0] === 'apply'));
});

test('apply sends reviewed arguments and requires confirmation of the returned transaction', async () => {
	const id = 'b'.repeat(32);
	const f = routingFixture(method => method === 'preview' ? reviewResult() :
		method === 'apply' ? { ok: true, id } : method === 'pending' ?
			{ ok: true, id, state: 'awaiting_confirmation', seconds_remaining: 60 } : { ok: true });
	await f.view.run(() => f.view.preview());
	await f.view.run(() => f.view.apply());
	const applied = f.calls.find(call => call[0] === 'apply');
	assert.deepEqual(applied.slice(1), ['managed', 'profile.abcdefgh', '', '1', '192.168.8.2', 'a'.repeat(64)]);
	assert.equal(f.view.confirmButton.disabled, false);
	assert.equal(f.view.previewButton.disabled, true);
	assert.ok(f.view.rowInputs.every(node => node.disabled));
	await f.view.run(() => f.view.confirm());
	assert.ok(f.calls.some(call => call[0] === 'confirm' && call[1] === id));
	assert.equal(f.view.pending.id, '');
	assert.equal(f.timers.size, 0);
});

test('expired confirmation and navigation stop the countdown without confirming', async () => {
	const pending = { id: 'b'.repeat(32), state: 'awaiting_confirmation', seconds_remaining: 2 };
	const data = routingData(); data[2] = pending;
	const f = routingFixture(() => {}, true, data);
	assert.equal(f.view.confirmButton.disabled, false);
	f.advance(3);
	assert.equal(f.view.confirmButton.disabled, true);
	assert.equal(f.timers.size, 0);
	await f.view.run(() => f.view.confirm());
	assert.equal(f.calls.length, 0);
	assert.match(f.view.feedback.textContent, /window has ended/);
	f.view.setPending({ ...pending, seconds_remaining: 60 });
	f.events.pagehide();
	assert.equal(f.timers.size, 0);
});

test('lost apply responses recover pending state and never retry apply automatically', async () => {
	const f = routingFixture(method => {
		if (method === 'preview') return reviewResult();
		if (method === 'apply') throw new Error('Transport lost.');
		return { id: 'b'.repeat(32), state: 'awaiting_confirmation', seconds_remaining: 60 };
	});
	await f.view.run(() => f.view.preview());
	await f.view.run(() => f.view.apply());
	assert.equal(f.calls.filter(call => call[0] === 'apply').length, 1);
	assert.equal(f.view.confirmButton.disabled, false);
	assert.match(f.view.feedback.textContent, /result was lost/);
});

test('readonly, unreadable rules and unavailable recovery status disable routing mutations', () => {
	const broken = routingData(); broken[3] = { rules: 'rule $(id)\n', presets: presetText };
	const missing = routingData(); missing[2] = null;
	const empty = routingData(); empty[3] = null;
	for (const [writable, data] of [[false, routingData()], [true, missing], [true, broken], [true, empty]]) {
		const f = routingFixture(() => {}, writable, data);
		assert.equal(f.view.previewButton.disabled, true);
		assert.equal(f.view.applyButton.disabled, true);
		assert.equal(f.view.confirmButton.disabled, true);
		assert.ok(f.view.rowInputs.every(node => node.disabled));
	}
});

function reportLogic() {
	return load('selective-vpn/report.js', { baseclass: { extend: value => value }, routing: routingLogic() });
}

function statusReport(changes = {}) {
	return {
		schema: 2, report: 'status', collection: { state: 'complete' },
		configuration: { enabled: true, rules: 2, pending_uci: 'absent', owned_settings: 'match' },
		recovery: { state: 'confirmed', supervisor: 'running' }, vpn: { tunnel: 'ready', process: 'running', ipv4: 'usable', logical_interface: 'attached' },
		routing: { main_ipv4_default: 'present', vpn_default: 'present', mark_rule: 'present' },
		pbr: { service: 'running', version: 'supported', errors: 'absent', policy_configuration: 'match' },
		dns: { integration: 'ready', nftset_capability: 'supported', sets: 1, population: 'empty' },
		evidence: { tunnel: 'observed', policy_rules: 'observed', policy_matches: 'unverified' },
		policies: { global__xcloud_native: 'present', tv: 'present' },
		packets: { global__xcloud_native: 0, tv: 3 }, bytes: { global__xcloud_native: 0, tv: 180 },
		details: { interface: 'tun_sv0', addresses: '10.8.0.2/24' },
		sources: { global__xcloud_native: '192.168.8.0/25 192.168.8.128/26', tv: '192.168.8.30' },
		destinations: { global__xcloud_native: 'xsts.auth.xboxlive.com', tv: 'example.com 9.9.9.9' },
		protocols: { global__xcloud_native: 'tcp', tv: 'tcp udp' },
		ports: { global__xcloud_native: '443', tv: '' },
		...changes
	};
}

function textContent(node) {
	return typeof node === 'object' ? [node.textContent || '', ...(node.children || []).map(textContent)].join(' ') : String(node);
}

function monitorFixture(handler, options = {}) {
	const calls = [], events = {}, documentEvents = {}, timers = new Map(), downloads = [];
	let now = 0, sequence = 0;
	const doc = { hidden: false, addEventListener: (name, fn) => { documentEvents[name] = fn; } };
	const pending = { ok: true, id: '' };
	const settings = { enabled: '1', mode: 'managed' };
	const view = load('selective-vpn/monitor.js', {
		view: { extend: value => value }, report: reportLogic(), routing: routingLogic(),
		Date: { now: () => now }, document: doc,
		L: { hasViewPermission: () => options.writable !== false, url: (...parts) => '/' + parts.join('/') },
		window: {
			addEventListener: (name, fn) => { events[name] = fn; },
			setTimeout: (fn, delay) => { timers.set(++sequence, { fn, delay }); return sequence; },
			clearTimeout: id => timers.delete(id)
		},
		E: (tag, attributes, children) => {
			const node = new Element(tag, attributes, children);
			if (tag === 'a') node.click = () => downloads.push(node.attributes);
			return node;
		},
		api: { call: async (...args) => {
			calls.push(args);
			if (handler) return handler(...args);
			return args[0] === 'status' ? statusReport() : args[0] === 'settings' ? settings : pending;
		} }
	});
	view.diagnostic = options.diagnostic === true;
	const data = Object.prototype.hasOwnProperty.call(options, 'data') ? options.data : [statusReport(), settings, pending];
	const root = view.render(view.diagnostic ? null : data);
	view.peer.value = '192.168.8.2';
	return { view, root, calls, events, timers, document: doc, documentEvents, downloads,
		advance: ms => { now += ms; view.tick(); },
		fire: delay => {
			const entry = [...timers].find(([, timer]) => timer.delay === delay);
			assert.ok(entry, 'expected timer'); timers.delete(entry[0]); return entry[1].fn();
		} };
}

test('doctor jobs accept report schemas and recovery calls keep their narrow arguments', async () => {
	const f = apiFixture(method => method === 'job' ? { ok: true, state: 'complete', result: { schema: 2, report: 'doctor' } } : { ok: true, job: '1' });
	assert.equal((await f.api.call('doctor')).report, 'doctor');
	for (const operation of ['enable', 'disable', 'rollback']) {
		const api = apiFixture(method => method === 'job' ? { ok: true, state: 'complete', result: { ok: true } } : { ok: true, job: '1' });
		await api.api.call(operation, '192.168.8.2');
		assert.deepEqual(Array.from(api.calls[0].options.params), ['peer']);
		assert.deepEqual(api.calls[0].args, ['192.168.8.2']);
	}
});

test('report cleaning drops secrets, raw logs, addresses and false gameplay claims', () => {
	const raw = statusReport({ report: 'doctor', password: 'private-secret', logs: { raw: 'private-secret', authentication_failure: 2 },
		evidence: { game_stream: 'observed', device_authentication: 'observed', exit_ip: '203.0.113.5' },
		packets: { global: 'private-secret', tv: -1, phone: 1e15, 'bad-name': 1, '<b>': 1, ok: 5 } });
	const value = reportLogic().clean(raw, 'doctor');
	const encoded = JSON.stringify(value);
	for (const secret of ['private-secret', '10.8.0.2', '192.168.8.0', 'xsts.auth', '203.0.113.5']) assert.ok(!encoded.includes(secret));
	assert.equal(value.evidence.game_stream, 'unknown');
	assert.deepEqual(Object.keys(value.packets), ['ok']);
	assert.equal(value.packets.ok, 5);
	assert.equal(value.logs.authentication_failure, 2);
	assert.equal(value.configuration.rules, 2);
	assert.throws(() => reportLogic().clean({ schema: 1 }, 'doctor'));
});

test('overview shows configured scope and separate tunnel, rule and traffic evidence', () => {
	const f = monitorFixture();
	const text = textContent(f.root);
	for (const expected of ['tun_sv0', '10.8.0.2/24', 'Global (xcloud_native): 192.168.8.0/25, 192.168.8.128/26 → xsts.auth.xboxlive.com (TCP 443)',
		'tv: 192.168.8.30 → example.com, 9.9.9.9 (TCP/UDP)', 'Configured routed domains: 2', 'tv rule / packets / bytes', 'remain unverified']) assert.ok(text.includes(expected), expected);
	assert.match(textContent(f.view.statusArea), /Present \/ 0 \/ 0/);
	assert.equal(f.view.buttons.disable.disabled, false);
	assert.equal(f.view.buttons.reconnect.disabled, false);
	assert.equal(f.view.warnings.children.length, 0);
	assert.ok(descendants(f.root).every(node => node.innerHTML === undefined));
});

test('disabled, degraded and busy reports do not imply a working connection', () => {
	const settings = { enabled: '0', mode: 'external' };
	const disabled = monitorFixture(null, { data: [statusReport({ configuration: { enabled: false } }), settings, { id: '' }] });
	assert.equal(disabled.view.buttons.enable.disabled, false);
	assert.equal(disabled.view.buttons.reconnect.disabled, true);
	assert.equal(disabled.view.buttons.disable.disabled, true);
	const degraded = monitorFixture(null, { data: [statusReport({ collection: { state: 'partial' }, vpn: { tunnel: 'not_ready' }, dns: { integration: 'not_ready' } }), { enabled: '1' }, { id: '' }] });
	assert.match(textContent(degraded.view.warnings), /incomplete/);
	assert.match(textContent(degraded.view.warnings), /prerequisites/);
	assert.match(textContent(degraded.view.warnings), /Domain routing is not ready/);
	const busy = monitorFixture(null, { data: [statusReport({ collection: { state: 'busy' } }), { enabled: '1' }, { id: '' }] });
	assert.equal(busy.view.buttons.disable.disabled, true);
});

test('stale reports block new actions until refreshed', async () => {
	const f = monitorFixture();
	f.advance(61000);
	assert.match(f.view.age.textContent, /Stale/);
	assert.equal(f.view.buttons.disable.disabled, true);
	await f.view.mutate(false);
	assert.equal(f.calls.length, 0);
	await f.view.refresh();
	assert.equal(f.view.buttons.disable.disabled, false);
	assert.match(f.view.age.textContent, /Seconds since/);
});

test('monitor polling is delayed, non-overlapping and paused on hidden pages or navigation', async () => {
	let resolve;
	const f = monitorFixture(method => method === 'status' ? new Promise(done => { resolve = done; }) : method === 'settings' ? { enabled: '1' } : { id: '' });
	assert.equal([...f.timers.values()].filter(timer => timer.delay === 30000).length, 1);
	const refresh = f.fire(30000);
	await settle();
	assert.equal(f.view.busy, true);
	await f.view.refresh();
	assert.equal(f.calls.filter(call => call[0] === 'status').length, 1);
	assert.equal([...f.timers.values()].filter(timer => timer.delay === 30000).length, 0);
	f.document.hidden = true; f.documentEvents.visibilitychange();
	assert.equal(f.timers.size, 0);
	resolve(statusReport()); await refresh;
	assert.equal(f.timers.size, 0);
	f.document.hidden = false; f.documentEvents.visibilitychange();
	assert.equal(f.timers.size, 2);
	f.events.pagehide();
	assert.equal(f.timers.size, 0);
	await f.view.refresh();
	assert.equal(f.calls.filter(call => call[0] === 'status').length, 1);
});

test('refresh failures remove old readiness and pause automatic updates', async () => {
	const f = monitorFixture(() => { throw new Error('private-secret'); });
	await f.view.refresh();
	assert.equal(f.view.cleaned, null);
	assert.equal(f.view.statusArea.children.length, 0);
	assert.equal(f.view.auto.checked, false);
	assert.equal(f.view.buttons.disable.disabled, true);
	assert.ok(!f.view.feedback.textContent.includes('private-secret'));
	assert.equal([...f.timers.values()].filter(timer => timer.delay === 30000).length, 0);
});

test('read-only and missing recovery data block mutations while diagnostics remain readable', async () => {
	for (const options of [{ writable: false }, { data: [null, null, null] }]) {
		const f = monitorFixture(null, options);
		for (const button of Object.values(f.view.buttons)) assert.equal(button.disabled, true);
		assert.equal(f.view.confirmButton.disabled, true);
		f.view.choose('disable'); await f.view.mutate(false);
		assert.equal(f.calls.length, 0);
	}
	const f = monitorFixture(() => statusReport({ report: 'doctor' }), { writable: false, diagnostic: true });
	await f.view.refresh();
	assert.equal(f.view.downloadButton.disabled, false);
});

test('each recovery action requires an explicit choice, valid peer and confirmation', async () => {
	for (const action of ['enable', 'reconnect', 'reload', 'disable', 'rollback']) {
		const id = 'c'.repeat(32);
		const f = monitorFixture(method => method === 'pending' ? { id, state: 'awaiting_confirmation', seconds_remaining: 60 } : { ok: true, id },
			{ data: [statusReport(), { enabled: action === 'enable' ? '0' : '1', mode: 'managed' }, { id: '' }] });
		f.view.choose(action);
		assert.equal(f.calls.length, 0);
		f.view.peer.value = 'bad-address'; await f.view.mutate(false);
		assert.equal(f.calls.length, 0);
		f.view.peer.value = '192.168.8.2'; await f.view.mutate(false);
		assert.deepEqual(f.calls[0], [action === 'reload' ? 'enable' : action, '192.168.8.2']);
		assert.equal(f.view.confirmButton.disabled, false);
		assert.equal(f.view.buttons.disable.disabled, true);
		await f.view.mutate(true);
		assert.ok(f.calls.some(call => call[0] === 'confirm' && call[1] === id));
	}
});

test('lost recovery responses are not retried and confirmation expires', async () => {
	const id = 'c'.repeat(32);
	const f = monitorFixture(method => {
		if (method === 'disable') throw new Error('private-secret');
		return { id, state: 'awaiting_confirmation', seconds_remaining: 2 };
	});
	f.view.choose('disable'); await f.view.mutate(false);
	assert.equal(f.calls.filter(call => call[0] === 'disable').length, 1);
	assert.equal(f.view.confirmButton.disabled, false);
	assert.match(f.view.feedback.textContent, /has not been retried/);
	assert.ok(!f.view.feedback.textContent.includes('private-secret'));
	f.advance(3000); await f.view.mutate(true);
	assert.equal(f.view.confirmButton.disabled, true);
	assert.ok(!f.calls.some(call => call[0] === 'confirm'));
});

test('pending confirmation remains available when status collection is busy', async () => {
	const id = 'd'.repeat(32);
	const f = monitorFixture(() => ({ ok: true, id: '' }), { data: [statusReport({ collection: { state: 'busy' } }), { enabled: '1' }, { id, state: 'awaiting_confirmation', seconds_remaining: 60 }] });
	assert.equal(f.view.confirmButton.disabled, false);
	await f.view.mutate(true);
	assert.deepEqual(f.calls[0], ['confirm', id]);
	assert.equal(f.view.confirmButton.disabled, true);
});

test('diagnostics run on demand and download only the cleaned doctor report', async () => {
	const f = monitorFixture(() => statusReport({ report: 'doctor', password: 'private-secret', logs: { raw: 'private-secret', tls_failure: 2 } }), { diagnostic: true });
	assert.equal(f.calls.length, 0);
	assert.equal(f.view.downloadButton.disabled, true);
	assert.equal([...f.timers.values()].filter(timer => timer.delay === 30000).length, 0);
	await f.view.refresh(); f.view.download();
	assert.deepEqual(f.calls, [['doctor']]);
	assert.equal(f.downloads.length, 1);
	const downloaded = decodeURIComponent(f.downloads[0].href.split(',')[1]);
	for (const secret of ['private-secret', '10.8.0.2', '192.168.8.0', 'xsts.auth']) assert.ok(!downloaded.includes(secret));
	assert.equal(JSON.parse(downloaded).logs.tls_failure, 2);
	assert.equal(f.downloads[0].download, 'selective-vpn-diagnostics.json');
	f.advance(61000); f.view.download();
	assert.equal(f.downloads.length, 1);
});

test('malformed overview details and recovery identifiers cannot become actionable evidence', () => {
	const detail = reportLogic().details({ details: { interface: '<script>', addresses: '999.0.0.1/24' },
		sources: { global: '0.0.0.0/0', tv: '192.168.8.30', 'x y': '192.168.8.31' }, destinations: { global: 'example.com', tv: '$(id)' } });
	assert.equal(detail.interface, '');
	assert.equal(detail.addresses.length, 0);
	assert.equal(detail.policies.length, 0);
	for (const pending of [{ id: '../shadow' }, { id: 'e'.repeat(32), state: 'constructor' }]) {
		const f = monitorFixture(null, { data: [statusReport(), { enabled: '1' }, pending] });
		assert.equal(f.view.buttons.disable.disabled, true);
		assert.equal(f.view.confirmButton.disabled, true);
	}
});

test('the monitor reads lock-sharing RPCs in order', async () => {
	let release;
	const f = monitorFixture(method => method === 'status' ? new Promise(resolve => { release = resolve; }) :
		method === 'settings' ? { enabled: '1' } : { id: '' });
	const loading = f.view.load();
	await settle();
	assert.deepEqual(f.calls, [['status']]);
	release(statusReport()); await loading;
	assert.deepEqual(f.calls, [['status'], ['settings'], ['pending']]);
});

test('rules keep the PBR policies they replace and previews list them', () => {
	const logic = routingLogic();
	const presets = logic.catalog(presetText);
	const rows = logic.rows('rule global\ndestinations example.com\nadopt gaming everyone\n', presets);
	assert.deepEqual(Array.from(rows[0].adopt), ['gaming', 'everyone']);
	assert.equal(logic.serialize(rows, presets), 'rule global\nproto tcp udp\ndestinations example.com\nadopt gaming everyone\n');
	assert.throws(() => logic.rows('rule global\nadopt svpn_route_global\n', presets), /could not be read/);
	const args = logic.options(routingForm(), vpnSelection, rows, presets);
	const result = logic.preview(reviewResult({ adopted: 'global\tgaming\tGaming PC\n', adopted_client: 'personal' }), args);
	assert.deepEqual({ ...result.adopted[0] }, { rule: 'global', section: 'gaming', label: 'Gaming PC' });
	assert.equal(result.client, 'personal');
	for (const adopted of ['tv\tgaming\tx', 'global\tsvpn_route_global\tx', 'global\tgaming'])
		assert.throws(() => logic.preview(reviewResult({ adopted }), args));
	assert.equal(logic.preview(reviewResult({ adopted_client: '$(id)' }), args).client, '');
	const report = logic.policies('1\tgaming\tGaming PC\timported\tglobal\n2\t-\tPhone\tsources\t\n3\t$(id)\tx\tok\t\n');
	assert.deepEqual(Array.from(report, item => item.status), ['imported', 'sources']);
});

test('importing PBR policies sends the edited rows and reloads them', async () => {
	const policies = '1\tgaming\tGaming PC\timported\tdevice_192_168_8_20\n2\tphone\tPhone\tsources\t\n';
	const f = routingFixture(method => method === 'import_pbr' ? { ok: true,
		rules: 'rule global\npreset xcloud_native\nrule device_192_168_8_20\naddress 192.168.8.20\nadopt gaming\n',
		policies: policies + '\t\t\tglobal_skips\ttv\n' } : reviewResult(), true, routingData([{ policies }]));
	assert.equal(f.view.importButton.disabled, false);
	assert.match(texts(f.view.policyArea).join('|'), /Gaming PC\|Can be imported into rule device_192_168_8_20/);
	f.view.rows[0].destinations = 'example.net';
	await f.view.run(() => f.view.importPolicies());
	const sent = f.calls.find(call => call[0] === 'import_pbr');
	assert.deepEqual(sent.slice(1, 3), ['managed', 'profile.abcdefgh']);
	assert.match(sent[3], /destinations example\.net/);
	assert.deepEqual(Array.from(f.view.rows[1].adopt), ['gaming']);
	assert.match(texts(f.view.ruleArea).join('|'), /Replaces hand-made PBR policies: gaming/);
	assert.match(texts(f.view.policyArea).join('|'), /Imported into rule device_192_168_8_20.*Rule tv/);
	assert.ok(!f.calls.some(call => ['preview', 'apply'].includes(call[0])));
	const empty = routingFixture(() => reviewResult(), true, routingData([{ policies: '2\tphone\tPhone\tsources\t\n' }]));
	assert.equal(empty.view.importButton.disabled, true);
});

test('an existing client lists every problem and can be copied into a profile', async () => {
	const f = viewFixture(method => method === 'client_check' ? { ok: true, problems: 'device\t\nroutes\t\nunsupported\tProfile line 3: Unsupported profile option.\nbogus\t\n' } :
		method === 'adopt_client' ? { ok: true, id: 'profile.ABC12345' } : summary(1));
	f.view.render({ ...baseData, settings: { enabled: '0', mode: 'external', selection: 'personal' } });
	await settle();
	f.view.mode.value = 'external';
	f.view.clients.value = 'personal';
	await f.view.run(() => f.view.select());
	assert.deepEqual(f.calls.find(call => call[0] === 'client_check'), ['client_check', 'personal']);
	const text = texts(f.view.checks).join('|');
	assert.match(text, /fixed tunnel name/);
	assert.match(text, /redirect-gateway/);
	assert.match(text, /Unsupported setting: Profile line 3/);
	assert.equal(texts(f.view.checks).filter(item => /bogus/.test(item)).length, 0);
	await f.view.run(() => f.view.copyClient());
	assert.deepEqual(f.calls.find(call => call[0] === 'adopt_client'), ['adopt_client', 'personal']);
	assert.equal(f.view.mode.value, 'managed');
	assert.equal(f.view.profiles.value, 'profile.ABC12345');
	assert.match(f.view.feedback.textContent, /old client keeps running until you apply/);
	assert.ok(!f.calls.some(call => ['apply', 'enable'].includes(call[0])));
});
