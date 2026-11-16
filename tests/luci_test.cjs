const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const vm = require('node:vm');

const resources = path.join(__dirname, '../luci-app-xcloud-bypass/htdocs/luci-static/resources');

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
	const api = load('xcloud-bypass/api.js', {
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
			{ ok: true, state: 'complete', result: { schema: 1, vpn: { tunnel: 'ready' } } });
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
	assert.throws(() => f.api.selection({ mode: 'external', selection: 'xcloud_client' }));
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
	const view = load('view/xcloud-bypass/vpn.js', {
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
	profiles: { profiles: 'profile.abcdefgh' }, clients: { clients: 'personal\nxcloud_client\n<script>' },
	status: { configuration: { enabled: true }, vpn: { tunnel: 'ready' } }
};
const summary = auth => ({ ok: true, summary: `device=tun_xc0\nauth_required=${auth}\nremote_count=1\npeer_verification=ca`, credentials_saved: true });
const settle = () => new Promise(resolve => setImmediate(resolve));

test('VPN view shows sanitized summaries and keeps credentials blank', async () => {
	const f = viewFixture(() => summary(1));
	const root = f.view.render(baseData);
	await settle();
	assert.equal(f.view.username.value, '');
	assert.equal(f.view.password.value, '');
	assert.equal(f.view.credentials.hidden, false);
	assert.equal(f.view.clients.children.length, 2);
	assert.match(f.view.status.textContent, /remain unverified/);
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
	const peer = nodes.find(node => node.id === 'xcloud-peer');
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
	nodes.find(node => node.id === 'xcloud-peer').value = '192.168.8.2';
	nodes.find(node => node.tag === 'button' && node.children[0] === 'Reconnect').events.click();
	await settle();
	assert.equal(f.ui.modal, null);
	assert.match(f.view.feedback.textContent, /Reconnect failed/);
	assert.ok(!f.calls.some(call => call[0] === 'confirm'));
});
