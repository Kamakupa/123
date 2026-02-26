"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const WebSocket = require("ws");
const msgpack = require("@msgpack/msgpack");
const nodeFetch = require("node-fetch");
const { SocksProxyAgent } = require("socks-proxy-agent");
const { HttpsProxyAgent } = require("https-proxy-agent");

const config = {
	username: "MooShop",
	clanName: "MooShop",
	botsPerServer: 10,
	chat: "discord.gg/JNrKFu2pJV",
	sandbox: false,
	serverUrl: ""
};

const network = Object.freeze((() => {
	const sandbox = !!config.sandbox;
	const siteHost = sandbox ? "sandbox.moomoo.io" : "moomoo.io";
	return {
		sandbox,
		siteHost,
		siteOrigin: `https://${siteHost}`,
		siteReferer: `https://${siteHost}/`,
		apiBase: sandbox ? "https://api-sandbox.moomoo.io" : "https://api.moomoo.io",
		wsDomain: "moomoo.io"
	};
})());

const settings = Object.freeze({
	apiBase: network.apiBase,
	serversPath: "/servers?v=1.26",
	verifyPath: "/verify",
	wsDomain: network.wsDomain,
	userAgent: "Mozilla/5.0",
	maxAltcha: 1000000,
	proxyMaxConns: 3,
	proxyWaitMs: 500,
	proxyCooldownMs: 20000,
	connectStaggerMs: 100,
	reconnectMs: 1700,
	pingMs: 2500,
	moveTickMs: 250,
	spawnRetryMs: 1200,
	chatIntervalMs: 1000,
	requestIntervalMs: 500,
	acceptIntervalMs: 500,
	clanCreateRetryMs: 1200,
	clanCreateMaxAttempts: 6,
	botsAutoJoinClan: true,
	safeDistance: 240,
	safeBand: 70,
	moveAngleEpsilon: 0.25,
	lookAngleEpsilon: 0.04
});

const requestHeaders = Object.freeze({
	accept: "application/json, text/plain, */*",
	origin: network.siteOrigin,
	referer: network.siteReferer,
	"user-agent": settings.userAgent
});

const now = () => Date.now();
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const randInt = (min, max) => min + Math.floor(Math.random() * (max - min + 1));
const ts = () => new Date().toISOString().slice(11, 23);
const log = text => console.log(`[${ts()}] ${String(text)}`);

function normalizeAngle(value) {
	const n = Number(value);
	if (!Number.isFinite(n)) return null;
	let out = n;
	while (out > Math.PI) out -= Math.PI * 2;
	while (out < -Math.PI) out += Math.PI * 2;
	return out;
}

function angleDiff(a, b) {
	const aa = normalizeAngle(a);
	const bb = normalizeAngle(b);
	if (aa == null || bb == null) return Math.PI * 2;
	let diff = Math.abs(aa - bb);
	if (diff > Math.PI) diff = Math.PI * 2 - diff;
	return diff;
}

function toBytes(raw) {
	if (Buffer.isBuffer(raw)) return new Uint8Array(raw);
	if (raw instanceof Uint8Array) return raw;
	if (raw instanceof ArrayBuffer) return new Uint8Array(raw);
	if (ArrayBuffer.isView(raw)) return new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
	return null;
}

function decodeFrames(raw) {
	const bytes = toBytes(raw);
	if (!bytes || !bytes.length) return [];
	try {
		return Array.from(msgpack.decodeMulti(bytes));
	} catch {
		try {
			return [msgpack.decode(bytes)];
		} catch {
			return [];
		}
	}
}

function encodeFrame(type, args) {
	return Buffer.from(msgpack.encode([type, args]));
}

function parseSpawnSid(payload) {
	if (Array.isArray(payload)) {
		const sid = Number(payload[1]);
		if (Number.isFinite(sid)) return sid;
		const id = Number(payload[0]);
		if (Number.isFinite(id)) return id;
	}
	if (payload && typeof payload === "object") {
		const sid = Number(payload.sid);
		if (Number.isFinite(sid)) return sid;
		const id = Number(payload.id);
		if (Number.isFinite(id)) return id;
	}
	const n = Number(payload);
	return Number.isFinite(n) ? n : null;
}

async function fetchJson(pathOrUrl, agent) {
	const url = pathOrUrl.startsWith("http") ? pathOrUrl : `${settings.apiBase}${pathOrUrl}`;
	const options = { headers: requestHeaders };
	if (agent) options.agent = agent;
	const response = await nodeFetch(url, options);
	const body = await response.text();
	if (!response.ok) {
		const snippet = String(body || "").replace(/\s+/g, " ").slice(0, 180);
		throw new Error(`HTTP ${response.status} ${url}${snippet ? ` :: ${snippet}` : ""}`);
	}
	try {
		return JSON.parse(body);
	} catch {
		throw new Error(`Invalid JSON from ${url}`);
	}
}

function toFiniteNumber(value) {
	const n = Number(value);
	return Number.isFinite(n) ? n : null;
}

function asNonEmptyString(value) {
	const text = String(value == null ? "" : value).trim();
	return text || "";
}

function serverIdentity(serverLike) {
	const region = asNonEmptyString(serverLike?.region).toLowerCase();
	const key = asNonEmptyString(serverLike?.key).toLowerCase();
	return `${region}.${key}`;
}

function serverFreeSlots(serverLike) {
	const count = toFiniteNumber(serverLike?.playerCount);
	const capacity = toFiniteNumber(serverLike?.playerCapacity);
	if (count == null || capacity == null) return null;
	return Math.max(0, Math.floor(capacity - count));
}

function serverLoadLabel(serverLike) {
	const count = toFiniteNumber(serverLike?.playerCount);
	const capacity = toFiniteNumber(serverLike?.playerCapacity);
	if (count == null || capacity == null) return "unknown";
	return `${Math.floor(count)}/${Math.floor(capacity)}`;
}

function serverLabel(serverLike) {
	const region = asNonEmptyString(serverLike?.region).toLowerCase() || "?";
	const name = asNonEmptyString(serverLike?.name) || asNonEmptyString(serverLike?.key) || "?";
	return `${region}:${name}`;
}

function chooseLaunchServers(servers, botsPerServer) {
	const eligible = [];
	const skipped = [];
	for (const server of servers) {
		const free = serverFreeSlots(server);
		if (free != null && free < botsPerServer) {
			skipped.push({ server, free });
			continue;
		}
		eligible.push(server);
	}
	eligible.sort((a, b) => {
		const freeA = serverFreeSlots(a);
		const freeB = serverFreeSlots(b);
		if (freeA != null && freeB != null && freeA !== freeB) return freeB - freeA;
		if (freeA != null && freeB == null) return -1;
		if (freeA == null && freeB != null) return 1;
		return String(a.region).localeCompare(String(b.region)) || String(a.key).localeCompare(String(b.key));
	});
	return { eligible, skipped };
}

function normalizeServer(raw) {
	if (!raw || !raw.key || !raw.region) return null;
	return {
		key: String(raw.key),
		region: String(raw.region).toLowerCase(),
		name: String(raw.name || ""),
		playerCount: toFiniteNumber(raw.playerCount),
		playerCapacity: toFiniteNumber(raw.playerCapacity)
	};
}

function parseServerUrl(value) {
	const text = String(value || "").trim();
	if (!text) return null;
	let url;
	try {
		url = new URL(text);
	} catch {
		throw new Error("config.serverUrl must be a valid URL");
	}
	if (url.protocol === "ws:" || url.protocol === "wss:") {
		const host = String(url.hostname || "").toLowerCase();
		const parts = host.split(".");
		if (parts.length < 3 || !parts[0] || !parts[1]) {
			throw new Error(`config.serverUrl ws host must look like key.region.${network.wsDomain}`);
		}
		return {
			kind: "ws",
			raw: text,
			key: parts[0],
			region: parts[1]
		};
	}
	if (url.protocol === "http:" || url.protocol === "https:") {
		const serverParam = String(url.searchParams.get("server") || "").trim();
		if (!serverParam) {
			throw new Error("config.serverUrl http/https format must include ?server=region:NAME");
		}
		const idx = serverParam.indexOf(":");
		if (idx <= 0 || idx === serverParam.length - 1) {
			throw new Error("config.serverUrl ?server value must look like region:NAME");
		}
		const region = serverParam.slice(0, idx).trim().toLowerCase();
		const name = serverParam.slice(idx + 1).trim();
		if (!region || !name) {
			throw new Error("config.serverUrl ?server value must look like region:NAME");
		}
		return {
			kind: "server-query",
			raw: text,
			region,
			name
		};
	}
	throw new Error(`config.serverUrl must be ws(s)://... or https://${network.siteHost}/?server=region:NAME`);
}

async function fetchServers(agent) {
	const rows = await fetchJson(settings.serversPath, agent);
	if (!Array.isArray(rows)) throw new Error("Unexpected /servers response shape");
	const deduped = new Map();
	for (const row of rows) {
		const server = normalizeServer(row);
		if (!server) continue;
		deduped.set(`${server.key}.${server.region}`, server);
	}
	return [...deduped.values()].sort((a, b) => a.region.localeCompare(b.region) || a.key.localeCompare(b.key));
}

function digestHex(algorithm, input) {
	const normalized = String(algorithm || "SHA-256").toLowerCase().replace(/[^a-z0-9]/g, "");
	return crypto.createHash(normalized).update(String(input || "")).digest("hex");
}

function solveAltcha(challenge) {
	const algorithm = String(challenge?.algorithm || "SHA-256").toUpperCase();
	const target = String(challenge?.challenge || "").toLowerCase();
	const salt = String(challenge?.salt || "");
	const max = Math.min(Number(challenge?.maxnumber) || settings.maxAltcha, settings.maxAltcha);
	if (!target || !salt) throw new Error("Bad ALTCHA payload");
	const startedAt = now();
	for (let number = 0; number <= max; number++) {
		if (digestHex(algorithm, `${salt}${number}`) === target) {
			return { number, took: now() - startedAt };
		}
	}
	throw new Error("ALTCHA solve failed");
}

function encodeAltcha(challenge, solution) {
	const payload = {
		algorithm: challenge.algorithm,
		challenge: challenge.challenge,
		number: solution.number,
		salt: challenge.salt,
		signature: challenge.signature,
		took: solution.took
	};
	return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}

async function buildWsUrl(server, agent) {
	const challenge = await fetchJson(settings.verifyPath, agent);
	const solution = solveAltcha(challenge);
	const token = `alt:${encodeAltcha(challenge, solution)}`;
	if (server.wsUrl) {
		const url = new URL(server.wsUrl);
		url.searchParams.set("token", token);
		return url.toString();
	}
	return `wss://${server.key}.${server.region}.${settings.wsDomain}?token=${encodeURIComponent(token)}`;
}

function resolveProxyFile() {
	const direct = path.resolve(__dirname, "proxy.txt");
	if (fs.existsSync(direct)) return direct;
	const plural = path.resolve(__dirname, "proxies.txt");
	if (fs.existsSync(plural)) return plural;
	throw new Error("Missing proxy file. Add proxy.txt or proxies.txt");
}

function normalizeProxy(line) {
	const value = String(line || "").trim();
	if (!value) return "";
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return value;
	return `http://${value}`;
}

function buildProxyAgent(proxyUrl) {
	const scheme = proxyUrl.split("://")[0].toLowerCase();
	if (scheme.startsWith("socks")) return new SocksProxyAgent(proxyUrl);
	return new HttpsProxyAgent(proxyUrl);
}

function loadProxyUrls(filePath) {
	const seen = new Set();
	const list = [];
	const lines = fs.readFileSync(filePath, "utf8").split(/\r?\n/);
	for (const line of lines) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#")) continue;
		const normalized = normalizeProxy(trimmed);
		if (!normalized || seen.has(normalized)) continue;
		seen.add(normalized);
		list.push(normalized);
	}
	return list;
}

function isProxyFailure(errorLike) {
	const text = String(errorLike?.message || errorLike || "").toLowerCase();
	if (!text) return false;
	if (text.includes("invalid connection")) return false;
	if (text.includes("close 4001")) return false;
	return ["proxy", "socks", "tunneling", "econnrefused", "econnreset", "etimedout", "ehostunreach", "enotfound", "socket hang up", "407"]
		.some(token => text.includes(token));
}

class TimerBag {
	constructor() {
		this.ids = new Map();
	}

	setInterval(key, fn, ms) {
		this.clear(key);
		const id = setInterval(fn, ms);
		this.ids.set(key, id);
		return id;
	}

	setTimeout(key, fn, ms) {
		this.clear(key);
		const id = setTimeout(() => {
			this.ids.delete(key);
			fn();
		}, ms);
		this.ids.set(key, id);
		return id;
	}

	clear(key) {
		const id = this.ids.get(key);
		if (id == null) return;
		clearTimeout(id);
		clearInterval(id);
		this.ids.delete(key);
	}

	clearAll() {
		for (const id of this.ids.values()) {
			clearTimeout(id);
			clearInterval(id);
		}
		this.ids.clear();
	}
}

class ProxyPool {
	constructor(proxyUrls) {
		this.states = new Map();
		for (const proxyUrl of proxyUrls) {
			if (this.states.has(proxyUrl)) continue;
			let agent;
			try {
				agent = buildProxyAgent(proxyUrl);
			} catch {
				continue;
			}
			this.states.set(proxyUrl, {
				id: proxyUrl,
				agent,
				inFlight: 0,
				failCount: 0,
				cooldownUntil: 0,
				lastUsedAt: 0
			});
		}
	}

	size() {
		return this.states.size;
	}

	capacity() {
		return this.size() * settings.proxyMaxConns;
	}

	acquire() {
		const current = now();
		const candidates = [];
		for (const state of this.states.values()) {
			if (state.inFlight >= settings.proxyMaxConns) continue;
			if (state.cooldownUntil > current) continue;
			candidates.push(state);
		}
		if (!candidates.length) return null;
		candidates.sort((a, b) => (a.inFlight - b.inFlight) || (a.failCount - b.failCount) || (a.lastUsedAt - b.lastUsedAt));
		const chosen = candidates[0];
		chosen.inFlight += 1;
		chosen.lastUsedAt = current;
		return { id: chosen.id, agent: chosen.agent };
	}

	release(lease, ok, error) {
		if (!lease) return;
		const state = this.states.get(lease.id);
		if (!state) return;
		state.inFlight = Math.max(0, state.inFlight - 1);
		if (ok) {
			state.failCount = Math.max(0, state.failCount - 1);
			if (state.failCount === 0) state.cooldownUntil = 0;
			return;
		}
		state.failCount += 1;
		state.cooldownUntil = now() + settings.proxyCooldownMs * Math.min(4, state.failCount);
		void error;
	}
}

async function withProxy(pool, label, task) {
	let lastError = null;
	const attempts = Math.max(20, pool.size() * 5);
	for (let i = 0; i < attempts; i++) {
		const lease = pool.acquire();
		if (!lease) {
			await wait(settings.proxyWaitMs);
			continue;
		}
		try {
			const result = await task(lease.agent);
			pool.release(lease, true);
			return result;
		} catch (error) {
			lastError = error;
			const penalize = isProxyFailure(error);
			pool.release(lease, !penalize, error);
		}
	}
	throw new Error(`${label} failed: ${String(lastError?.message || lastError || "unknown")}`);
}

class BotClient {
	constructor(swarm, server, slot) {
		this.swarm = swarm;
		this.server = server;
		this.slot = slot;
		this.label = `${server.region}.${server.key}#${slot + 1}`;
		this.name = `${config.username}`;
		this.chatLine = String(config.chat || "").slice(0, 30);
		this.ws = null;
		this.lease = null;
		this.connecting = false;
		this.closed = false;
		this.lastSocketError = "";
		this.joined = false;
		this.ownSid = null;
		this.self = null;
		this.teamId = null;
		this.isOwner = false;
		this.pendingClanRequests = [];
		this.players = new Map();
		this.lastMove = null;
		this.lastLook = null;
		this.orbit = Math.random() < 0.5 ? -1 : 1;
		this.idleAngle = 0;
		this.idleUntil = 0;
		this.timers = new TimerBag();
	}

	start() {
		void this.connect();
	}

	// Clan / alliance helpers
	sendCreateClan(name) {
		const payload = name === "" ? String.fromCharCode(0) : String(name || "");
		this.send("L", payload);
	}

	sendClanRequest(targetSid) {
		if (targetSid == null) {
			log(`sendClanRequest: invalid sid=${String(targetSid)}`);
			return false;
		}
		const sid = typeof targetSid === "string" ? targetSid.trim() : targetSid;
		if (sid === "") {
			log(`sendClanRequest: invalid sid=${String(targetSid)}`);
			return false;
		}
		const ok = this.send("b", sid);
		log(`sendClanRequest: from=${this.label} to=${String(sid)} ok=${String(!!ok)}`);
		return ok;
	}

	acceptClanRequest(requesterSid) {
		if (!Number.isFinite(Number(requesterSid))) return false;
		return this.send("P", Number(requesterSid), 1);
	}

	startClanBehavior() {
		// each server needs its own clan creator
		const existingCreator = this.swarm.getClanCreator(this.server);
		const isCreator = existingCreator ? existingCreator === this : this.swarm.assignClanCreator(this.server, this);
		if (isCreator) {
			// creator retries clan creation a few times to reduce startup race failures.
			const name = config.clanName || config.username || "MooShop";
			let attempts = 0;
			const sendCreateAttempt = () => {
				if (!this.joined || !this.isOpen() || this.closed) return;
				attempts += 1;
				log(`creating clan: owner=${this.label} name=${name} attempt=${attempts}`);
				this.sendCreateClan(name);
			};
			const startAcceptLoop = () => {
				if (this.timers.ids.has("clan-accept")) return;
				this.timers.setInterval("clan-accept", () => {
					// accept one pending request per interval (including human players)
					if (!this.pendingClanRequests.length) return;
					const req = this.pendingClanRequests.shift();
					if (!req || !Number.isFinite(Number(req.sid))) return;
					log(`accepting clan request: owner=${this.label} -> sid=${String(req.sid)} name=${req.name}`);
					this.acceptClanRequest(req.sid);
				}, settings.acceptIntervalMs);
			};

			this.timers.setTimeout("clan-create", () => {
				sendCreateAttempt();
				this.timers.setInterval("clan-create-retry", () => {
					if (this.isOwner || this.teamId != null) {
						this.timers.clear("clan-create-retry");
						startAcceptLoop();
						return;
					}
					if (attempts >= settings.clanCreateMaxAttempts) {
						log(`clan create attempts exhausted for ${this.label}; continuing with accept loop`);
						this.timers.clear("clan-create-retry");
						startAcceptLoop();
						return;
					}
					sendCreateAttempt();
				}, settings.clanCreateRetryMs);
			}, 600 + randInt(0, 400));
		} else {
			if (!settings.botsAutoJoinClan) {
				log(`clan auto-join disabled for ${this.label}; keeping slots open for players`);
				return;
			}
			// requester behaviour: repeatedly request to join this server's creator clan.
			const requestJoin = () => {
				const creator = this.swarm.getClanCreator(this.server);
				if (!creator || creator === this) return;
				const target = creator.teamId;
				const targetTeam = this.normalizeTeam(target);
				if (!targetTeam) return;
				const ownTeam = this.normalizeTeam(this.teamId);
				if (ownTeam && ownTeam === targetTeam) {
					log(`clan joined: ${this.label} team=${String(this.teamId)}; stopping join retries`);
					this.timers.clear("clan-request");
					return;
				}
				log(`requesting to join: ${this.label} -> creator=${creator.label} target=${String(target)}`);
				this.sendClanRequest(target);
			};
			requestJoin();
			this.timers.setInterval("clan-request", requestJoin, settings.requestIntervalMs);
		}
	}

	stop() {
		this.closed = true;
		this.timers.clearAll();
		if (this.ws) {
			try {
				this.ws.close(1000, "shutdown");
			} catch {}
		} else {
			this.releaseLease(true);
		}
		this.ws = null;
	}

	isOpen() {
		return !!(this.ws && this.ws.readyState === WebSocket.OPEN);
	}

	releaseLease(ok, error) {
		if (!this.lease) return;
		this.swarm.proxyPool.release(this.lease, !!ok, error);
		this.lease = null;
	}

	resetSessionState() {
		this.joined = false;
		this.ownSid = null;
		this.self = null;
		this.teamId = null;
		this.isOwner = false;
		this.pendingClanRequests = [];
		this.players.clear();
		this.lastMove = null;
		this.lastLook = null;
		// clear clan timers if any
		this.timers.clear("clan-accept");
		this.timers.clear("clan-request");
		this.timers.clear("clan-create");
		this.timers.clear("clan-create-retry");
	}

	scheduleReconnect(reason) {
		if (this.closed) return;
		if (this.timers.ids.has("reconnect")) return;
		const delay = settings.reconnectMs + randInt(100, 900);
		if (reason) log(`reconnect ${this.label} in ${delay}ms :: ${reason}`);
		this.timers.setTimeout("reconnect", () => {
			if (!this.closed) void this.connect();
		}, delay);
	}

	send(type, ...args) {
		if (!this.isOpen()) return false;
		try {
			this.ws.send(encodeFrame(type, args), { binary: true });
			return true;
		} catch {
			return false;
		}
	}

	setMove(angle) {
		if (angle == null) {
			if (this.lastMove == null) return true;
			this.lastMove = null;
			return this.send("9", null);
		}
		const value = normalizeAngle(angle);
		if (value == null) return false;
		if (this.lastMove != null && angleDiff(this.lastMove, value) <= settings.moveAngleEpsilon) return true;
		this.lastMove = value;
		return this.send("9", value);
	}

	setLook(angle) {
		const value = normalizeAngle(angle);
		if (value == null) return false;
		if (this.lastLook != null && angleDiff(this.lastLook, value) <= settings.lookAngleEpsilon) return true;
		this.lastLook = value;
		return this.send("D", value);
	}

	spawn() {
		return this.send("M", {
			name: this.name,
			moofoll: true,
			skin: randInt(0, 9)
		});
	}

	sendChat() {
		if (!this.chatLine || !this.joined) return;
		this.send("6", this.chatLine);
	}

	startSpawnLoop(initialDelayMs) {
		this.timers.setInterval("spawn", () => {
			if (!this.closed && this.isOpen() && !this.joined) this.spawn();
		}, settings.spawnRetryMs);
		this.timers.setTimeout("spawn-kick", () => {
			if (!this.closed && this.isOpen() && !this.joined) this.spawn();
		}, Math.max(0, initialDelayMs));
	}

	startChatLoop() {
		this.timers.setInterval("chat", () => {
			if (!this.closed) this.sendChat();
		}, settings.chatIntervalMs);
	}

	startPingLoop() {
		this.timers.setInterval("ping", () => {
			if (!this.closed && this.isOpen()) this.send("0");
		}, settings.pingMs);
	}

	startMoveLoop() {
		this.timers.setInterval("move", () => this.tickMovement(), settings.moveTickMs);
	}

	handlePlayers(snapshot) {
		const flat = Array.isArray(snapshot) ? snapshot : [];
		const next = new Map();
		let self = null;
		for (let i = 0; i + 12 < flat.length; i += 13) {
			const sid = Number(flat[i]);
			if (!Number.isFinite(sid)) continue;
			const team = flat[i + 7] == null ? null : flat[i + 7];
			const player = {
				sid,
				x: Number(flat[i + 1]) || 0,
				y: Number(flat[i + 2]) || 0,
				team
			};
			next.set(sid, player);
			if (this.ownSid != null && sid === this.ownSid) {
				self = player;
				if (team != null && String(team).trim() !== "") this.teamId = team;
			}
		}
		this.players = next;
		this.self = self;
	}

	normalizeTeam(value) {
		if (value == null) return "";
		return String(value).trim().toLowerCase();
	}

	isFriendlyTarget(player) {
		if (!player) return false;
		const playerTeam = this.normalizeTeam(player.team);
		if (!playerTeam) return false;
		const ownTeam = this.normalizeTeam(this.teamId);
		if (ownTeam && playerTeam === ownTeam) return true;
		const mooShopTeam = this.normalizeTeam(config.clanName || config.username || "MooShop");
		return !!mooShopTeam && playerTeam === mooShopTeam;
	}

	nearestTarget() {
		if (!this.self) return null;
		let target = null;
		let minDistSq = Infinity;
		for (const player of this.players.values()) {
			if (player.sid === this.ownSid) continue;
			if (this.isFriendlyTarget(player)) continue;
			const dx = player.x - this.self.x;
			const dy = player.y - this.self.y;
			const distSq = dx * dx + dy * dy;
			if (distSq < minDistSq) {
				minDistSq = distSq;
				target = player;
			}
		}
		return target;
	}

	tickMovement() {
		if (this.closed || !this.joined || !this.self || !this.isOpen()) return;
		const target = this.nearestTarget();
		if (!target) {
			if (now() >= this.idleUntil) {
				this.idleAngle = Math.random() * Math.PI * 2 - Math.PI;
				this.idleUntil = now() + randInt(1000, 3000);
			}
			this.setMove(this.idleAngle);
			return;
		}
		const dx = target.x - this.self.x;
		const dy = target.y - this.self.y;
		const distance = Math.hypot(dx, dy);
		const toward = Math.atan2(dy, dx);
		this.setLook(toward);
		if (distance > settings.safeDistance + settings.safeBand) {
			this.setMove(toward);
			return;
		}
		if (distance < settings.safeDistance - settings.safeBand) {
			this.setMove(normalizeAngle(toward + Math.PI));
			return;
		}
		if (Math.random() < 0.03) this.orbit *= -1;
		this.setMove(normalizeAngle(toward + (Math.PI / 2) * this.orbit));
	}

	onFrame(type, args) {
		if (type === "io-init") {
			this.startSpawnLoop(randInt(40, 160));
			return;
		}
		if (type === "C") {
			const sid = Number(args[0]);
			if (Number.isFinite(sid)) this.ownSid = sid;
			return;
		}
		if (type === "D") {
			if (!args[1]) return;
			const sid = parseSpawnSid(args[0]);
			if (sid != null) this.ownSid = sid;
			if (!this.joined) {
				this.joined = true;
				this.timers.clear("spawn");
				this.timers.clear("spawn-kick");
				this.startChatLoop();
				this.sendChat();
				log(`joined ${this.label} sid=${String(this.ownSid)}`);
				try {
					this.startClanBehavior();
				} catch (e) {
					void e;
				}
			}
			return;
		}
		if (type === "P") {
			this.joined = false;
			this.self = null;
			this.players.clear();
			this.timers.setTimeout("respawn", () => {
				if (!this.closed && this.isOpen()) this.startSpawnLoop(randInt(80, 220));
			}, randInt(500, 900));
			return;
		}
		if (type === "a") {
			this.handlePlayers(Array.isArray(args[0]) ? args[0] : args);
		}

		// server alliance notification (numeric code 2)
		if (type === 2 || type === "2") {
			const sid = Number(args[0]);
			if (Number.isFinite(sid)) {
				// avoid duplicates
				if (!this.pendingClanRequests.find(p => p.sid === sid)) {
					this.pendingClanRequests.push({ sid, name: String(args[1] || "") });
					log(`pending clan request received: sid=${String(sid)} name=${String(args[1] || "")}`);
				}
			}
		}

		// server set player team (numeric code 3) -> args: [teamId, isOwner]
		if (type === 3 || type === "3") {
			this.teamId = args[0];
			this.isOwner = !!args[1];
			log(`team update ${this.label} team=${String(this.teamId)} isOwner=${String(this.isOwner)}`);
			return;
		}
	}

	onMessage(raw, socketRef) {
		if (socketRef !== this.ws) return;
		for (const frame of decodeFrames(raw)) {
			if (!Array.isArray(frame) || !frame.length) continue;
			const type = frame[0];
			const args = frame.length === 2 && Array.isArray(frame[1]) ? frame[1] : frame.slice(1);
			this.onFrame(type, args);
		}
	}

	onOpen(socketRef) {
		if (socketRef !== this.ws) return;
		this.send("0");
		this.startPingLoop();
		this.startMoveLoop();
	}

	onClose(code, reason, socketRef) {
		if (socketRef !== this.ws) return;
		const reasonText = Buffer.isBuffer(reason) ? reason.toString("utf8") : String(reason || "");
		const penalize = isProxyFailure(this.lastSocketError || reasonText) && code !== 4001;
		this.timers.clearAll();
		this.ws = null;
		this.releaseLease(!penalize, penalize ? new Error(`close ${code} ${reasonText.slice(0, 80)}`) : null);
		this.lastSocketError = "";
		this.resetSessionState();
		if (!this.closed) this.scheduleReconnect(`code=${code} reason=${reasonText.slice(0, 80)}`);
	}

	onError(error, socketRef) {
		if (socketRef !== this.ws) return;
		this.lastSocketError = String(error?.message || error || "unknown");
	}

	async connect() {
		if (this.closed || this.ws || this.connecting) return;
		this.connecting = true;
		try {
			while (!this.closed && !this.ws) {
				const lease = this.swarm.proxyPool.acquire();
				if (!lease) {
					await wait(settings.proxyWaitMs);
					continue;
				}
				this.lease = lease;

				let wsUrl;
				try {
					wsUrl = await buildWsUrl(this.server, lease.agent);
				} catch (error) {
					const penalize = isProxyFailure(error);
					this.releaseLease(!penalize, error);
					await wait(settings.reconnectMs + randInt(120, 700));
					continue;
				}

				let socket;
				try {
					socket = new WebSocket(wsUrl, {
						perMessageDeflate: false,
						headers: {
							Origin: network.siteOrigin,
							Referer: network.siteReferer,
							"User-Agent": settings.userAgent
						},
						agent: lease.agent
					});
				} catch (error) {
					const penalize = isProxyFailure(error);
					this.releaseLease(!penalize, error);
					await wait(settings.reconnectMs + randInt(120, 700));
					continue;
				}

				this.lastSocketError = "";
				this.ws = socket;
				socket.on("open", () => this.onOpen(socket));
				socket.on("message", raw => this.onMessage(raw, socket));
				socket.on("close", (code, reason) => this.onClose(code, reason, socket));
				socket.on("error", error => this.onError(error, socket));
				return;
			}
		} finally {
			this.connecting = false;
		}
	}
}

class BotSwarm {
	constructor() {
		const proxyFile = resolveProxyFile();
		const proxyUrls = loadProxyUrls(proxyFile);
		if (!proxyUrls.length) throw new Error(`No proxies loaded from ${proxyFile}`);
		this.proxyPool = new ProxyPool(proxyUrls);
		this.bots = [];
		this.clanCreators = new Map();
	}

	assignClanCreator(server, bot) {
		const key = serverIdentity(server);
		if (!key || key === ".") return false;
		const existing = this.clanCreators.get(key);
		if (!existing) {
			this.clanCreators.set(key, bot);
			log(`assigned clan creator: ${bot.label} server=${key}`);
			return true;
		}
		return existing === bot;
	}

	getClanCreator(server) {
		const key = serverIdentity(server);
		if (!key || key === ".") return null;
		return this.clanCreators.get(key) || null;
	}

	getOwnerForServer(server) {
		for (const bot of this.bots) {
			if (!bot || !bot.server) continue;
			if (bot.server.key === server.key && bot.server.region === server.region && bot.slot === 0) return bot;
		}
		return null;
	}

	async start() {
		const override = parseServerUrl(config.serverUrl);
		const botsPerServer = Math.max(1, Math.floor(Number(config.botsPerServer) || 0));
		let allServers = [];
		try {
			allServers = await withProxy(this.proxyPool, "fetch-servers", agent => fetchServers(agent));
		} catch (error) {
			// Allow direct ws override to proceed even if discovery endpoint is unavailable.
			if (!override || override.kind !== "ws") throw error;
			log(`server discovery unavailable for ws override: ${String(error?.message || error)}`);
		}

		const serverIndex = new Map();
		for (const server of allServers) serverIndex.set(serverIdentity(server), server);

		let servers;
		if (override) {
			if (override.kind === "ws") {
				const requested = {
					key: override.key,
					region: override.region,
					wsUrl: override.raw,
					name: override.key,
					playerCount: null,
					playerCapacity: null
				};
				const known = serverIndex.get(serverIdentity(requested));
				servers = [known ? { ...requested, ...known, wsUrl: requested.wsUrl } : requested];
			} else {
				const wantedRegion = String(override.region).toLowerCase();
				const wantedName = String(override.name).toLowerCase();
				const match = allServers.find(server =>
					server.region === wantedRegion && String(server.name || "").toLowerCase() === wantedName
				);
				if (!match) {
					throw new Error(`No server found for ${override.raw}. Expected ?server=${wantedRegion}:${override.name}`);
				}
				servers = [match];
			}
			const selected = servers[0];
			const free = serverFreeSlots(selected);
			if (free != null && free < botsPerServer) {
				throw new Error(
					`Server ${serverLabel(selected)} is too full (${serverLoadLabel(selected)}). `
					+ `Need at least ${botsPerServer} free slots, found ${free}.`
				);
			}
			if (free == null) {
				log(`capacity unknown for ${serverLabel(selected)}; launching ${botsPerServer} bots without pre-check`);
			}
		} else {
			const planned = chooseLaunchServers(allServers, botsPerServer);
			servers = planned.eligible;
			if (planned.skipped.length) {
				const preview = planned.skipped
					.slice(0, 12)
					.map(item => `${serverLabel(item.server)} load=${serverLoadLabel(item.server)} free=${item.free}`)
					.join(" | ");
				log(
					`skipping ${planned.skipped.length} crowded/full servers `
					+ `(need >=${botsPerServer} free): ${preview}${planned.skipped.length > 12 ? " ..." : ""}`
				);
			}
			if (!servers.length) {
				throw new Error(`No launch targets available: every server has <${botsPerServer} free slots.`);
			}
		}

		const regions = new Set(servers.map(server => server.region));
		const totalBots = servers.length * botsPerServer;
		const previewTargets = servers
			.slice(0, 12)
			.map(server => `${serverLabel(server)} load=${serverLoadLabel(server)} free=${String(serverFreeSlots(server) ?? "?")}`)
			.join(" | ");
		log(`servers=${servers.length} regions=${regions.size} bots/server=${botsPerServer} totalBots=${totalBots}`);
		log(`launch targets: ${previewTargets}${servers.length > 12 ? " ..." : ""}`);

		let launchIndex = 0;
		for (let slot = 0; slot < botsPerServer; slot++) {
			for (const server of servers) {
				const bot = new BotClient(this, server, slot);
				this.bots.push(bot);
				setTimeout(() => bot.start(), launchIndex * settings.connectStaggerMs);
				launchIndex += 1;
			}
		}
	}

	async stop() {
		for (const bot of this.bots) bot.stop();
		this.clanCreators.clear();
		await wait(100);
	}
}

async function main() {
	const swarm = new BotSwarm();
	let stopping = false;
	const shutdown = async () => {
		if (stopping) return;
		stopping = true;
		await swarm.stop();
		process.exit(0);
	};
	process.once("SIGINT", () => { void shutdown(); });
	process.once("SIGTERM", () => { void shutdown(); });
	await swarm.start();
}

module.exports = {
	CONFIG: config,
	BotSwarm,
	ProxyPool,
	encodeFrame,
	decodeFrames
};

if (require.main === module) {
	main().catch(error => {
		const text = error?.stack || String(error);
		console.error(text);
		process.exit(1);
	});
}
