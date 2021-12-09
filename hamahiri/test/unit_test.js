'use strict';

const Hamahiri = require('../lib/hamahiri.js');
const assert = require('assert');
const process = require('process');
const crypto = require('crypto');
const asn1js = require('asn1js');
const path = require('path');
const fs = require('fs');

const LOG = process.stdout;
const LEGACY_PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
const CNG_PROVIDER = "Microsoft Software Key Storage Provider";
let indexCN = 0;

class EnrollTest
{
	constructor()
	{
		this.__tests = 0;
		this.__legacyKeyPair = null;
		this.__cngKeyPair = null;

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
		let found = devices.find((value) => { return value ===  LEGACY_PROVIDER; });
		assert(found, 'The minimum required legacy provider is not present');

		LOG.write(' done!\n');
		console.log('Installed providers:');
		console.log(devices);
		this.__tests++;
	}
	checkLegacyGenKeyPair() {
		LOG.write('Testing legacy RSA key pair generation...');
		assert(this.__enroll.generateKeyPair, 'The expected Enroll.generateKeyPair() method is undefined');
		this.__legacyKeyPair = this.__enroll.generateKeyPair(LEGACY_PROVIDER, 2048);
		assert(this.__legacyKeyPair, 'Failed to generate key pair');
		assert(this.__legacyKeyPair.privKey && this.__legacyKeyPair.pubKey, 'The required members of KeyPair object are not defined');
		assert.equal(isNaN(this.__legacyKeyPair.privKey), false, 'privKey member of KeyPair object must be a number');
		assert(this.__legacyKeyPair.privKey > 0, 'privKey member of KeyPair object must be positive number');
		assert(this.__legacyKeyPair.pubKey instanceof Uint8Array, 'pubKey member of KeyPair object must be an instance of Uint8Array');
		this.__tests++;
		LOG.write(' done!\n');
	}
	checkCNGGenKeyPair() {
		LOG.write('Testing CNG RSA key pair generation...');
		assert(this.__enroll.generateKeyPair, 'The expected Enroll.generateKeyPair() method is undefined');
		this.__cngKeyPair = this.__enroll.generateKeyPair(CNG_PROVIDER, 2048);
		assert(this.__cngKeyPair, 'Failed to generate key pair');
		assert(this.__cngKeyPair.privKey && this.__cngKeyPair.pubKey, 'The required members of KeyPair object are not defined');
		assert.equal(isNaN(this.__cngKeyPair.privKey), false, 'privKey member of KeyPair object must be a number');
		assert(this.__cngKeyPair.privKey > 0, 'privKey member of KeyPair object must be positive number');
		assert(this.__cngKeyPair.pubKey instanceof Uint8Array, 'pubKey member of KeyPair object must be an instance of Uint8Array');
		this.__tests++;
		LOG.write(' done!\n');
	}
	#makeCertificationRequestInfo(rawPubKey, cn) {
		let ver = new asn1js.Integer({ value: 1 });
		let name = new asn1js.Sequence({ value: [
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.6'}),
					new asn1js.Utf8String({ value: 'BR' })
				]})
			]}),
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.10'}),
					new asn1js.Utf8String({ value: 'PKI Brazil' })
				]})
			]}),
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.11'}),
					new asn1js.Utf8String({ value: 'Common Name for All Cats End User CA' })
				]})
			]}),
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.3'}),
					new asn1js.Utf8String({ value: cn })
				]})
			]})
		]});
		let decoded = asn1js.fromBER(rawPubKey.buffer);
		if (decoded.offset === (-1)) throw 'Invalid public key info';
		let pubKeyInfo = new asn1js.Sequence({ value: [
			decoded.result.valueBlock.value[0],
			decoded.result.valueBlock.value[1]
		]});
		let attrs = new asn1js.Constructed({ 
			idBlock: { tagClass: 3, tagNumber: 0 },
			value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.20'}),
					new asn1js.Utf8String({ value: cn })
				]})
			]
		});
		return new asn1js.Sequence({ value: [ ver, name, pubKeyInfo, attrs ]});
	}
	#makeCertificationRequest(certificateRequestInfo, signed) {
		let request = new asn1js.Sequence({ value: [
			certificateRequestInfo,
			new asn1js.Sequence({ value: [
				new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.1.11' }),
				new asn1js.Null()
			]}),
			new asn1js.BitString({ valueHex: signed.buffer })
		] });
		return request.toBER(false);
	}
	checkSignLegacyRequest() {
		LOG.write('Testing a certificate request signature with a legacy key...');
		let cn = 'Unit test user certificate common name number ' + ++indexCN;
		let certificateRequestInfo = this.#makeCertificationRequestInfo(this.__legacyKeyPair.pubKey, cn);
		let toBeSigned = Buffer.from(certificateRequestInfo.toBER(false));
		let hash = crypto.createHash('sha256');
		hash.update(toBeSigned);
		assert(this.__enroll.sign, 'The expected Enroll.sign() method is undefined');
		let signed = this.__enroll.sign(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, this.__legacyKeyPair.privKey);
		assert(signed, 'Signature failure');
		assert(signed instanceof Uint8Array, 'The signed buffer must be an instance of Uint8Array');
		this.__csr = this.#makeCertificationRequest(certificateRequestInfo, signed);
		this.__tests++;
		LOG.write(' done!\n');
	}
	checkSignCNGRequest() {
		LOG.write('Testing a certificate request signature with a CNG key...');
		let cn = 'Unit test user certificate common name number ' + ++indexCN;
		let certificateRequestInfo = this.#makeCertificationRequestInfo(this.__cngKeyPair.pubKey, cn);
		let toBeSigned = Buffer.from(certificateRequestInfo.toBER(false));
		let hash = crypto.createHash('sha256');
		hash.update(toBeSigned);
		assert(this.__enroll.sign, 'The expected Enroll.sign() method is undefined');
		let signed = this.__enroll.sign(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, this.__cngKeyPair.privKey);
		assert(signed, 'Signature failure');
		assert(signed instanceof Uint8Array, 'The signed buffer must be an instance of Uint8Array');
		this.__csr = this.#makeCertificationRequest(certificateRequestInfo, signed);
		this.__tests++;
		LOG.write(' done!\n');
	}
	#signLegacyRequest(csr) {
		fs.writeFileSync(path.resolve(__dirname, 'legacy-request.der'), Buffer.from(csr));
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
	checkInstallLegacyCert() {
		LOG.write('Testing install user certificate...');
		this.__pkcs7 = this.#signLegacyRequest(this.__csr);
		let userCert = this.#getSignerCertificate(this.__pkcs7);
		assert(this.__enroll.installCertificate, 'The expected Enroll.installCertificate() method is undefined');
		assert(this.__enroll.installCertificate(userCert), 'Failure on install user certificate');
		this.__tests++;
		LOG.write(' done!\n');
	}
	checkInstallChain() {
		LOG.write('Testing install CA certificates chain...');
		assert(this.__pkcs7, 'This test requires that checkInstallLegacyCert test succeeds');
		let chain = this.#getCAChain(this.__pkcs7);

		assert(this.__enroll.installChain, 'The expected Enroll.installChain() method is undefined');
		let done = this.__enroll.installChain(chain);
		let msg = done ? ' done!' : ' Chain already installed.';
		this.__tests++;
		LOG.write(msg);
		LOG.write('\n');
	}
	checkDeleteLegacyKey() {
		LOG.write('Testing legacy RSA key pair removal...');
		assert(this.__legacyKeyPair, 'This test requires that checkLegacyGenKeyPair test succeeds');
		assert(this.__enroll.deleteKeyPair, 'The expected Enroll.deleteKeyPair() method is undefined');
		assert(this.__enroll.deleteKeyPair(this.__legacyKeyPair.privKey), 'Failed to remove RSA key pair');
		this.__tests++;
		LOG.write(' done!\n');
	}
	checkDeleteCNGKey() {
		LOG.write('Testing Windows CNG RSA key pair removal...');
		assert(this.__cngKeyPair, 'This test requires that checkCNGGenKeyPair test succeeds');
		assert(this.__enroll.deleteKeyPair, 'The expected Enroll.deleteKeyPair() method is undefined');
		assert(this.__enroll.deleteKeyPair(this.__cngKeyPair.privKey), 'Failed to remove RSA key pair');
		this.__tests++;
		LOG.write(' done!\n');
	}
	static test() {
		LOG.write('Tests battery of certificate enrollment:\n');
		let test = new EnrollTest();
		test.checkEnumDevices();
		test.checkLegacyGenKeyPair();
		test.checkSignLegacyRequest();
		test.checkInstallLegacyCert();
		test.checkDeleteLegacyKey();
/*		test.checkCNGGenKeyPair();
		test.checkSignCNGRequest();
		test.checkInstallChain();
		test.checkDeleteCNGKey();  */
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
		console.log('Installed signing certificates:')
		console.log(certs);
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
		LOG.write('Tests battery of digital signature:\n');
		let test = new SignTest();
		test.checkEnumCerts();
		test.checkSign();
		test.checkSignature();
		test.checkReleaseKey();
		LOG.write(test.__tests.toString());
		LOG.write(' test cases performed.\n')
	}
}

let dir = path.dirname(process.argv[1]);
let indexFile = path.join(dir, 'index.txt');
if (fs.existsSync(indexFile)) indexCN = fs.readFileSync(indexFile)
else fs.writeFileSync(indexFile, indexCN.toString());
EnrollTest.test();
// SignTest.test();
fs.writeFileSync(indexFile, indexCN.toString());
