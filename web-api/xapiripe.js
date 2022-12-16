/**
 * @file Implementação baseada no serviço Hekura da interface Xapiripe
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { Enroll, Sign, Verify, PromiseRejected, urlHekura } from './api.js';
import { Base64 } from './fittings.js';

const INVALID_JSON_RESPONSE = 'Ocorreu a seguinte falha ao converter a resposta [%r] recebida do serviço no objeto Javascript: %e';

class HTTPResponse {
	constructor(code, statusText) {
		this.statusCode = code;
		this.statusText = statusText;
	}
}
function retrieve(path, init) {
	return new Promise((resolve, reject) => {
		window.fetch(urlHekura + path, init).then((response) => {
			if (response.ok) {
				response.text().then((value) => { return resolve(new HTTPResponse(response.status, value)); })
				.catch((reason) => { return reject(new PromiseRejected(2, reason)); });
			}
			else return reject(new PromiseRejected(response.status, response.statusText));
		})
		.catch((reason) => { return reject(new PromiseRejected(2, reason)); });
	});
}
function returnObject(contents, resolve, reject) {
	try { return resolve(JSON.parse(contents.statusText)); }
	catch (e) { return reject(new PromiseRejected(2, INVALID_JSON_RESPONSE.replace('%r', contents.statusText).replace('%e', e))); }
}
function get(path) {
	return new Promise((resolve, reject) => {
		retrieve(path, {
			method: 'GET',
			mode: 'cors',
			cache: 'no-store'
		})
		.then((contents) => { return returnObject(contents, resolve, reject); })
		.catch((reason) => { return reject(reason); });
	});
}
function post(path, argument) {
	return new Promise((resolve, reject) => {
		let body;
		try { body = JSON.stringify(argument); }
		catch (e) { return reject(new PromiseRejected(1, 'Argumento inválido')); }
		retrieve(path, {
			method: 'POST',
			mode: 'cors',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/json' },
			body: new TextEncoder().encode(body)
		})
		.then((contents) => { return resolve(contents.statusText); })
		.catch((reason) =>  { return reject(reason); });
	});
}

export class HekuraEnroll extends Enroll {
	enumerateDevices() {
		return get('/enroll');
	}
	generateCSR(options) {
		let params = {
			device: null,
			keySize: 2048,
			signAlg: 0x00000040,
			rdn: {
				c: null,
				o: null,
				ou: null,
				cn: null
			}
		};
		if (typeof(options) === 'object') {
			if (typeof(options.device) === 'string') params.device = options.device;
			if (typeof(options.keySize) === 'number') params.keySize = options.keySize;
			if (typeof(options.signAlg) === 'number') params.signAlg = options.signAlg;
			if (typeof(options.rdn) === 'object') {
				if (typeof(options.rdn.c) === 'string') params.rdn.c = options.rdn.c;
				if (typeof(options.rdn.o) === 'string') params.rdn.o = options.rdn.o;
				if (typeof(options.rdn.ou) === 'string') params.rdn.ou = options.rdn.ou;
				if (typeof(options.rdn.cn) === 'string') params.rdn.cn = options.rdn.cn;
			}
		}
		return post('/enroll', params);
	}
	installCertificates(pkcs7) {
		return new Promise((resolve, reject) => {
			retrieve('/enroll', {
				method: 'PUT',
				mode: 'cors',
				cache: 'no-store',
				headers: { 'Content-Type': 'application/json' },
				body: new TextEncoder().encode(JSON.stringify({ pkcs7: pkcs7 }))
			})
			.then((contents) => { return resolve(contents.statusCode === 201 ? true : false); })
			.catch((reason) =>  { return reject(reason); });
		});
	}
}

export class HekuraSign extends Sign {
	enumerateCerts() {
		return get('/sign');
	}
	sign(options) {
		let params = {
			handle: 0,
			toBeSigned: null,
			attach: true,
			algorithm: 0x00000040,
			cades: {
				policy: 'CAdES-BES',
				addSigningTime: true,
				commitmentType: '1.2.840.113549.1.9.16.6.4'
			}
		};
		let altString = { data: null, binary: false };
		if (typeof(options) === 'object') {
			if (typeof(options.certificate) === 'object' && typeof(options.certificate.handle) === 'number') params.handle = options.certificate.handle;
			if (typeof(options.toBeSigned) === 'string') altString.data = options.toBeSigned;
			else {
				let cv = new Base64();
				altString.data = cv.btoa(options.toBeSigned);
				altString.binary = true;
			}
			params.toBeSigned = altString;
			if (typeof(options.attach) === 'boolean') params.attach = options.attach;
			if (typeof(options.algorithm) === 'number') params.algorithm = options.algorithm;
			if (typeof(options.cades) === 'object') {
				if (typeof(options.cades.policy) === 'string') params.cades.policy = options.cades.policy;
				if (typeof(options.cades.addSigningTime) === 'boolean') params.cades.addSigningTime = options.cades.addSigningTime;
				if (typeof(options.cades.commitmentType) === 'string') params.cades.commitmentType = options.cades.commitmentType;
			}
		}
		return post('/sign', params);
	}
}

export class HekuraVerify extends Verify {
	verify(options) {
		return new Promise((resolve, reject) => {
			let params = {
				pkcs7: { data: null, binary: false },
				signingCert: undefined,
				eContent: undefined,
				verifyTrustworthy: false,
				getSignerIdentifier: false,
				getSignedContent: false,
				getSigningTime: false
			};
			if (typeof(options) === 'object') {
				if (typeof(options.pkcs7) === 'object') {
					if (typeof(options.pkcs7.data) !== 'undefined') params.pkcs7.data = options.pkcs7.data;
					if (typeof(options.pkcs7.binary) === 'boolean') params.pkcs7.binary = options.pkcs7.binary;
				}
				if (typeof(options.signingCert) === 'object' && typeof(options.signingCert.data) !== 'undefined') params.signingCert = options.signingCert;
				if (typeof(options.eContent) === 'object' && typeof(options.eContent.data) !== 'undefined')params.eContent = options.eContent;
				if (typeof(options.verifyTrustworthy) === 'boolean') params.verifyTrustworthy = options.verifyTrustworthy;
				if (typeof(options.getSignerIdentifier) === 'boolean') params.getSignerIdentifier = options.getSignerIdentifier;
				if (typeof(options.getSignedContent) === 'boolean') params.getSignedContent = options.getSignedContent;
				if (typeof(options.getSigningTime) === 'boolean') params.getSigningTime = options.getSigningTime;
			}
			let body;
			try { body = JSON.stringify(params); }
			catch (e) { return reject(new PromiseRejected(1, 'Argumento inválido')); }
			retrieve('/verify', {
				method: 'POST',
				mode: 'cors',
				cache: 'no-store',
				headers: { 'Content-Type': 'application/json' },
				body: new TextEncoder().encode(body)
			})
			.then((contents) => { return returnObject(contents, resolve, reject); })
			.catch((reason) =>  { return reject(reason); });
		});
	}
}