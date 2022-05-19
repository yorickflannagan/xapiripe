/**
 * @file Implementação baseada no cliente Kryptonite da interface Xapiripe
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { Enroll, Sign, Verify, PromiseRejected } from './api.js';
import { Base64 } from './fittings.js';

const ENUM_DEVICES_FAILURE = 'Falha ao enumerar os dispositivos criptográficos através da extensão Kryptonite Enroll';
const GENERATE_CSR_FAILURE = 'Falha ao assinar uma requisição de certificado através da extensão Kryptonite Enroll';
const INSTALL_CHAIN_FAILURE = 'Falha ao instalar o certificado assinado através da extensão Kryptonite Enroll';
const ENUM_CERTS_FAILURE = 'Falha ao enumerar os certificados de assinatura através da extensão Kryptonite Sign';
const SIGN_FAILURE = 'Falha ao assinar o conteúdo através da extensão Kryptonite Sign';

export class KryptoniteEnroll extends Enroll {

	constructor(kryptoObject) {
		super();
		this.krypton = kryptoObject;
	}
	enumerateDevices() {
		return new Promise((resolve, reject) => {
			let enroll = new this.krypton.Enroll();
			enroll.enumerateDevices().then((value) => {
				if (value.result != this.krypton.KPTAError.KPTA_OK) return reject(new PromiseRejected(value.result, ENUM_DEVICES_FAILURE));
				else return resolve(value.payload);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
	generateCSR({ device, keySize = 2048, signAlg = 0x00000040, rdn = {c, o, ou, cn }}) {
		return new Promise((resolve, reject) => {
			let enroll = new this.krypton.Enroll();
			enroll.generateCSR(arguments[0].device, arguments[0].rdn.cn, true).then((value) => {
				if (value.result != this.krypton.KPTAError.KPTA_OK) return reject(new PromiseRejected(value.result, GENERATE_CSR_FAILURE));
				else return resolve(value.payload);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
	installCertificates(pkcs7) {
		return new Promise((resolve, reject) => {
			let enroll = new this.krypton.Enroll();
			enroll.installCertificate(pkcs7).then((value) => {
				if (value.result != this.krypton.KPTAError.KPTA_OK) return reject(new PromiseRejected(value.result, INSTALL_CHAIN_FAILURE));
				else return resolve(true);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
}

export class KryptoniteSign extends Sign {

	constructor(kryptoObject) {
		super();
		this.krypton = kryptoObject;
	}
	enumerateCerts() {
		return new Promise((resolve, reject) => {
			let sign = new this.krypton.Sign();
			sign.enumerateCerts().then((value) => {
				if (value.result != this.krypton.KPTAError.KPTA_OK) return reject(new PromiseRejected(value.result, ENUM_CERTS_FAILURE));
				else return resolve(value.payload);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
	sign({ certificate, toBeSigned, attach = true, algorithm = 0x00000040, cades = { policy: 'CAdES-BES', addSigningTime: true, commitmentType: '1.2.840.113549.1.9.16.6.4' }}) {
		return new Promise((resolve, reject) => {
			let sign = new this.krypton.Sign();
			sign.sign(arguments[0].certificate, arguments[0].toBeSigned, true).then((value) => {
				if (value.result != this.krypton.KPTAError.KPTA_OK) return reject(new PromiseRejected(value.result, SIGN_FAILURE));
				else return resolve(value.payload);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
}

export class KryptoniteVerify extends Verify {

	constructor(kryptoObject) {
		super();
		this.krypton = kryptoObject;
	}
	#getSignerIdentifier(vrfy, cms) {
		return new Promise((resolve, reject) => {
			vrfy.getSignerId(cms).then((value) => {
				let ret = null;
				if (value.reason == this.krypton.KPTAError.KPTA_OK) ret = value.payload;
				return resolve(ret);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
	#getSignedContent(vrfy, cms) {
		return new Promise((resolve, reject) => {
			vrfy.getContent(cms).then((value) => {
				let ret =  null;
				if (value.reason == this.krypton.KPTAError.KPTA_OK) ret = value.payload;
				return resolve(ret);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
	/**
	 * A implementação ignora os parâmetros verifyTrustworthy e getSigningTime, não suportados pela
	 * extensão Kryptonite Verify. Do mesmo modo, a verificação de confiabilidade somente do certificado
	 * do assinante não é suportada por esta API.
	 */
	verify({
		pkcs7 = { data: null, binary: false },
		signingCert = { data: null, binary: false },
		eContent = { data: null, binary: false },
		verifyTrustworthy,
		getSignerIdentifier = false,
		getSignedContent = false,
		getSigningTime 
	}) {
		return new Promise((resolve, reject) => {
			let ret = { signatureVerification: null, messageDigestVerification: null, signerIdentifier: null, eContent: null };
			let cv = new Base64();
			let cms;
			let content;
			let cert;
			try {
				if (!arguments[0].pkcs7.data) throw new Error('Argumento inválido');
				if (arguments[0].pkcs7.binary) cms = cv.atob(arguments[0].pkcs7.data);
				else cms = arguments[0].pkcs7.data;
				if (arguments[0].eContent.data) {
					if (arguments[0].eContent.binary) content = cv.atob(arguments[0].eContent.data);
					else content = arguments[0].eContent.data;
				}
				if (arguments[0].signingCert.data) {
					if (arguments[0].signingCert.binary) cert = cv.atob(arguments[0].signingCert.data);
					else cert = arguments[0].signingCert.data;
				}
			}
			catch (e) { return reject(new PromiseRejected(1, e.message));}

			let vrfy = new this.krypton.Verify();
			vrfy.verify(cms, content, cert).then((value) => {
				ret.signatureVerification = value.reason == this.krypton.KPTAError.KPTA_OK;
				ret.messageDigestVerification = ret.signatureVerification;
				if (!ret.signatureVerification) return resolve(ret);
				let stack = new Array();
				if (arguments[0].getSignerIdentifier) stack.push({ ret: 'signerIdentifier', execute: this.#getSignerIdentifier.bind(this) });
				if (arguments[0].getSignedContent) stack.push({ ret: 'eContent', execute: this.#getSignedContent.bind(this) });
				while (stack.length > 0) {
					let task = stack.pop();
					task.execute(vrfy, cms).then((value) => { ret[task.ret] = value;
					})
					.catch((reason) => { return PromiseRejected(2, reason.toString()); });
				}
				return resolve(ret);
			})
			.catch((reason) => { return PromiseRejected(2, reason.toString()); });
		});
	}
}