/**
 * @file Implementação baseada no cliente Kryptonite da interface Xapiripe
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { Enroll, Sign, Verify, PromiseRejected } from './api.js';

export class KryptoniteEnroll extends Enroll {

	constructor(kryptoObject) {
		super();
		this.enroll = kryptoObject;
	}
	enumerateDevices() {
		return Promise.resolve([ new String('array de nomes de CSP') ]);
	}
	generateCSR({ device, keySize = 2048, signAlg = 0x00000040, rdn = {c, o, ou, cn }}) {
		return Promise.resolve(new String('PKCS #10 codificado em Base64 no formato PEM'));
	}
	installCertificates(pkcs7) {
		return Promise.resolve(new Boolean());
	}
}

export class KryptoniteSign extends Sign {

	constructor(kryptoObject) {
		super();
		this.sign = kryptoObject;
	}
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

export class KryptoniteVerify extends Verify {

	constructor(kryptoObject) {
		super();
		this.verify = kryptoObject;
	}
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