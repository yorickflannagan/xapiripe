'use strict';

const Hamahiri = require('../lib/hamahiri.js');
const assert = require('assert');
const process = require('process');
const crypto = require('crypto');


const LOG = process.stdout;
const PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';

class EnrollTest
{
	constructor()
	{
		this.__tests = 0;
		this.__keyPair = null;
		this.__csr = null;
		this.__pkcs7 = null;

		LOG.write('Testing certificate enrollment initialization...');
		this.__enroll = new Hamahiri.Enroll();
		assert(this.__enroll, 'Failure on Hamahiri.Enroll initialization');
		LOG.write(' done!\n');
		this.__tests++;
	}
	checkEnumDevices() {
		LOG.write('Testing cryptographic devices enumeration...');
		assert(this.__enroll.enumerateDevices, 'The expected Enroll.enumerateDevices() method is undefined');
		const devices = this.__enroll.enumerateDevices();
		let found = devices.find((value) => { return value ===  PROVIDER; });
		assert(found, 'The minimum required provider is not present');
		LOG.write(' done!\n');
		this.__tests++;
	}
	checkGenKeyPair() {
		LOG.write('Testing RSA key pair generation...');
		assert(this.__enroll.generateKeyPair, 'The expected Enroll.generateKeyPair() method is undefined');
		this.__keyPair = this.__enroll.generateKeyPair(PROVIDER, 2048);
		assert(this.__keyPair, 'Failed to generate key pair');
		assert(this.__keyPair.privKey && this.__keyPair.pubKey, 'The required members of KeyPair object are not defined');
		assert.equal(isNaN(this.__keyPair.privKey), false, 'privKey member of KeyPair object must be a number');
		assert(this.__keyPair.privKey > 0, 'privKey member of KeyPair object must be positive number');
		assert(this.__keyPair.pubKey instanceof Uint8Array, 'pubKey member of KeyPair object must be an instance of Uint8Array');
		this.__tests++;
		LOG.write(' done!\n');
	}
	#makeCertificationRequestInfo() {
		// TODO: implement with PKI.js
		return new TextEncoder().encode('Similação de CertificationRequestInfo');
	}
	#makeCertificationRequest(requestInfo, signature, algorithm)
	{
		// TODO: implement with PKI.js
		let alg = new TextEncoder().encode(algorithm);
		let request = new Uint8Array(requestInfo.length + signature.length + alg.length);
		request.set(requestInfo);
		request.set(signature, requestInfo.length);
		request.set(alg, requestInfo.length + signature.length);
		return request;
	}
	checkSignRequest() {
		LOG.write('Testing certicate request signature...');
		assert(this.__keyPair, 'This test requires that checkGenKeyPair test succeeds');
		assert(this.__enroll.sign, 'The expected Enroll.sign() method is undefined');
		let requestInfo = this.#makeCertificationRequestInfo();
		let hash = crypto.createHash('sha256');
		hash.update(requestInfo);
		let signature = this.__enroll.sign(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, this.__keyPair.privKey);
		assert(signature, 'Failure on sign document hash');
		assert(signature instanceof Uint8Array, 'Signature must be an instance of Uint8Array');
		this.__csr = this.#makeCertificationRequest(requestInfo, signature, '1.2.840.113549.1.1.11');
		this.__tests++;
		LOG.write(' done!\n');
	}
	checkReleaseKey() {
		LOG.write('Testing release private key handle...');
		assert(this.__keyPair, 'This test requires that checkGenKeyPair test succeeds');
		assert(this.__enroll.releaseKeyHandle, 'The expected Enroll.releaseKeyHandle() method is undefined');
		assert(this.__enroll.releaseKeyHandle(this.__keyPair.privKey), 'Failure on release key handle');
		this.__keyPair = null;
		this.__tests++;
		LOG.write(' done!\n');
	}
	#signRequest(csr) {
		// TODO: Sign request with OpenSSL PKI
		return new TextEncoder().encode('Pretend this is a pkcs #7');
	}
	#getSignerCertificate(pkcs7) {
		// TODO: parse with PKI.js
		return new TextEncoder().encode('Pretend this is a signer certificate');
	}
	#getCAChain(pkcs7) {
		// TODO: parse with PKI.js
		let ret = new Array();
		ret.push(new TextEncoder().encode('Pretend this is an end user CA certificate'));
		ret.push(new TextEncoder().encode('Pretend this is an intermediate CA certificate'));
		ret.push(new TextEncoder().encode('Pretend this is a root CA certificate'));
		return ret;
	}
	checkInstallCert() {
		LOG.write('Testing install user certificate...');
		assert(!this.__keyPair && this.__csr, 'This test requires that checkReleaseKey test succeeds');
		this.__pkcs7 = this.#signRequest(this.__csr);
		let userCert = this.#getSignerCertificate(this.__pkcs7);
		assert(this.__enroll.installCertificate, 'The expected Enroll.installCertificate() method is undefined');
		assert(this.__enroll.installCertificate(userCert), 'Failure on install user certificate');
		this.__tests++;
		LOG.write(' done!\n');
	}
	checkInstallChain() {
		LOG.write('Testing install CA certificates chain...');
		assert(this.__pkcs7, 'This test requires that checkInstallCert test succeeds');
		let chain = this.#getCAChain(this.__pkcs7);

		assert(this.__enroll.installChain, 'The expected Enroll.installChain() method is undefined');
		let done = this.__enroll.installChain(chain);
		let msg = done ? ' done!' : ' Chain already installed.';
		this.__tests++;
		LOG.write(msg);
		LOG.write('\n');
	}
	static test() {
		LOG.write('Tests battery of certificate enrollment:\n');
		let test = new EnrollTest();
		test.checkEnumDevices();
		test.checkGenKeyPair();
		test.checkSignRequest();
		test.checkReleaseKey();
		test.checkInstallCert();
		test.checkInstallChain();
		LOG.write(test.__tests.toString());
		LOG.write(' test cases performed.\n')
	}
}

class SignTest
{
	constructor() {
		this.__tests = 0;
		this.__certificates = null;
		this.__signature = null;

		LOG.write('Testing digital signature initialization...');
		this.__sign = new Hamahiri.Sign();
		assert(this.__sign, 'Failure on Hamahiri.Sign initialization');
		LOG.write(' done!\n');
		this.__tests++;
	}
	checkEnumCerts() {
		LOG.write('Testing signing certificates enumeration...');
		assert(this.__sign.enumerateCertificates, 'The expected Sign.enumerateCertificates() method is undefined');
		let certs = this.__sign.enumerateCertificates();
		assert(certs, 'Signing certificates enumeration failed');
		assert(Array.isArray(certs), 'Sign.enumerateCertificates() must return an array of Xapiripe.Certificate');
		assert(certs.length > 0, 'There are no signing certificates installed. Cannot proceed with test.');
		certs.forEach(value => {
			assert(value.subject && value.issuer && value.serial && value.handle, 'Sign.enumerateCertificates() must return an array of Xapiripe.Certificate objects');
			assert(!isNaN(value.handle && value.handle > 0), 'Certificate.handle member must be a positive integer');
		});
		this.__certificates = certs;
		LOG.write(' done!\n');
		this.__tests++;
	}
	checkSign() {
		LOG.write('Testing signing with sha256WithRSAEncryption algorithm...');
		assert(this.__certificates, 'This test requires that checkEnumCerts test case succeeds');
		assert(this.__sign.sign, 'The expected Sign.sign() method is undefined');
		let hash = crypto.createHash('sha256');
		hash.update('Transaction to sign');
		let signature = this.__sign.sign(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, this.__certificates[0].handle);
		assert(signature, 'Failure on sign transaction hash');
		assert(signature instanceof Uint8Array, 'Signature must be an instance of Uint8Array');
		this.__signature = signature;
		LOG.write(' done!\n');
		this.__tests++;
	}
	checkSignature() {
		LOG.write('Validating Hamahiri signature against OpenSSL...');
		assert(this.__signature, 'This test requires that checkSign test case succeeds');
		// TODO: Check signature using OpenSSL (see openssl dgst -verify)
		LOG.write(' done!\n');
		this.__tests++;
	}
	checkReleaseKey() {
		LOG.write('Testing release certificate handle...');
		assert(this.__signature, 'This test requires that checkSignature test cases succeeds');
		assert(this.__sign.releaseKeyHandle, 'The expected Sign.releaseKeyHandle() method is undefined');
		this.__certificates.forEach(value => {
			assert(this.__sign.releaseKeyHandle(value.handle), 'Failure on release certificcates handle');
		});
		
		this.__keyPair = null;
		this.__tests++;
		LOG.write(' done!\n');
	}
	static test() {
		LOG.write('Tests battery of certificate enrollment:\n');
		let test = new SignTest();
		test.checkEnumCerts();
		test.checkSign();
		test.checkSignature();
		test.checkReleaseKey();
		LOG.write(test.__tests.toString());
		LOG.write(' test cases performed.\n')
	}
}


EnrollTest.test();
SignTest.test();
