/**
 * @file Implementação baseada no serviço Hekura da interface Xapiripe
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { Enroll, Sign, Verify, PromiseRejected, urlHekura } from './api.js';

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

export class HekuraEnroll extends Enroll {
	enumerateDevices() {
		return new Promise((resolve, reject) => {
			retrieve('/enroll', {
				method: 'GET',
				mode: 'cors',
				cache: 'no-store'
			})
			.then((contents) => {
				try { return resolve(JSON.parse(contents.statusText)); }
				catch (e) { return reject(new PromiseRejected(2, INVALID_JSON_RESPONSE.replace('%r', contents.statusText).replace('%e', e))); }
			})
			.catch((reason) => { return reject(reason); });
		});
	}
	generateCSR({ device, keySize = 2048, signAlg = 0x00000040, rdn = {c, o, ou, cn }}) {
		return new Promise((resolve, reject) => {
			let body;
			try { body = JSON.stringify(arguments[0]); }
			catch (e) { return reject(new PromiseRejected(1, 'Argumento inválido')); }
			retrieve('/enroll', {
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
	installCertificates(pkcs7) {
		retrieve('/enroll', {
			method: 'POST',
			mode: 'cors',
			cache: 'no-store',
			headers: { 'Content-Type': 'application/json' },
			body: new TextEncoder().encode(JSON.stringify({ pkcs7: pkcs7 }))
		})
		.then((contents) => { return resolve(contents.statusCode === 201 ? true : false); })
		.catch((reason) =>  { return reject(reason); });
	}
}

export class HekuraSign extends Sign {
	enumerateCerts() {
		return Promise.resolve([ { subject: new String(), issuer: new String(), serial: new String(), handle: Number.MIN_VALUE } ]);
	}
	sign({
		handle,
		toBeSigned,
		attach = true,
		algorithm = 0x00000040,
		cades = { policy: 'CAdES-BES', addSigningTime: true, commitmentType: '1.2.840.113549.1.9.16.6.4' }
	}) {
		return Promise.resolve(new String('PKCS#7 codificado em base64 no formato PEM'));
	}
}

export class HekuraVerify extends Verify {
	verify({
		pkcs7 = { data: null, binary: false },
		signingCert = { data: null, binary: false },
		eContent = { data: null, binary: false },
		verifyTrustworthy = true,
		getSignerIdentifier = true,
		getSignedContent = true,
		getSigningTime = true
	}) {
		return Promise.resolve({
			signatureVerification: true,
			messageDigestVerification: true,
			signingCertVerification: true,
			certChainVerification: true,
			eContent: { data: null, binary: false },
			signerIdentifier: { issuer: null, serial: null, subjectKeyIdentifier:  null },
			signingTime: new Date()
		});
	}
}