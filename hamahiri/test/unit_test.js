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
const CNG_PROVIDER = 'Microsoft Software Key Storage Provider';
let indexCN = 0;
const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function toBase64(bytes)
{
	var base64        = '';
	var byteLength    = bytes.byteLength;
	var byteRemainder = byteLength % 3;
	var mainLength    = byteLength - byteRemainder;
	var a, b, c, d;
	var chunk;
	for (var i = 0; i < mainLength; i = i + 3)
	{
		chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
		a = (chunk & 16515072) >> 18;
		b = (chunk & 258048)   >> 12;
		c = (chunk & 4032)     >>  6;
		d = chunk & 63;
		base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
	}
	if (byteRemainder == 1)
	{
		chunk = bytes[mainLength];
		a = (chunk & 252) >> 2;
		b = (chunk & 3)   << 4;
		base64 += encodings[a] + encodings[b] + '==';
	}
	else if (byteRemainder == 2)
	{
		chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
		a = (chunk & 64512) >> 10;
		b = (chunk & 1008)  >>  4;
		c = (chunk & 15)    <<  2;
		base64 += encodings[a] + encodings[b] + encodings[c] + '=';
	}
	return base64;
}

class EnrollTest
{
	constructor()
	{
		this.tests = 0;
		this.legacyKeyPair = null;
		this.cngKeyPair = null;

		this.legacyCSR = null;
		this.cngCSR = null;
		this.pkcs7 = null;

		LOG.write('Testing certificate enrollment initialization...');
		this.enroll = new Hamahiri.Enroll();
		assert(this.enroll, 'Failure on Hamahiri.Enroll initialization');
		LOG.write(' done!\n');
		this.tests++;
	}
	checkEnumDevices() {
		LOG.write('Testing cryptographic devices enumeration...');
		assert(this.enroll.enumerateDevices, 'The expected Enroll.enumerateDevices() method is undefined');
		const devices = this.enroll.enumerateDevices();
		let found = devices.find((value) => { return value ===  LEGACY_PROVIDER; });
		assert(found, 'The minimum required legacy provider is not present');
		LOG.write(' done!\n');
		console.log('Installed providers:');
		console.log(devices);
		this.tests++;
	}
	#assertGenKeyPair(provider)
	{
		assert(this.enroll.generateKeyPair, 'The expected Enroll.generateKeyPair() method is undefined');
		let keyPair = this.enroll.generateKeyPair(provider, 2048);
		assert(keyPair, 'Failed to generate key pair');
		assert(keyPair.privKey && keyPair.pubKey, 'The required members of KeyPair object are not defined');
		assert.equal(isNaN(keyPair.privKey), false, 'privKey member of KeyPair object must be a number');
		assert(keyPair.privKey > 0, 'privKey member of KeyPair object must be positive number');
		assert(keyPair.pubKey instanceof Uint8Array, 'pubKey member of KeyPair object must be an instance of ArrayBuffer');
		let decoded = asn1js.fromBER(keyPair.pubKey.buffer);
		assert(decoded.offset != -1, 'pubKey member of KeyPair object must be a DER encoded SubjectPublicKeyInfo');
		let pubKeyInfo = decoded.result;
		assert(pubKeyInfo instanceof asn1js.Sequence, 'pubKeyInfo must be an ASN.1 SEQUENCE');
		assert(pubKeyInfo.valueBlock.value.length == 2, 'SubjectPublicKeyInfo must have two child nodes');
		let algorithm = pubKeyInfo.valueBlock.value[0];
		assert(algorithm instanceof asn1js.Sequence, 'AlgorithmIdentifier field must be an ASN.1 SEQUENCE');
		assert(algorithm.valueBlock.value.length == 2, 'AlgorithmIdentifier must have two child nodes');
		let oid = algorithm.valueBlock.value[0];
		assert(oid instanceof asn1js.ObjectIdentifier, 'algorithm must be an ASN.1 OBJECT IDENTIFIER');
		assert(oid.valueBlock.toString() === '1.2.840.113549.1.1.1', 'AlgorithmIdentifier must be rsaEncription OID');
		let param = algorithm.valueBlock.value[1];
		assert(param instanceof asn1js.Null, 'AlgorithmIdentifier parameter field must be an ASN.1 NULL');
		let subjectPublicKey = pubKeyInfo.valueBlock.value[1];
		assert(subjectPublicKey instanceof asn1js.BitString, 'subjectPublicKey field must be an ASN.1 BIT STRING');
		assert(subjectPublicKey.valueBlock.valueHex.byteLength == 270, 'subjectPublicKey must have the proper size');
		return keyPair;
	}
	checkLegacyGenKeyPair() {
		LOG.write('Testing legacy RSA key pair generation...');
		this.legacyKeyPair = this.#assertGenKeyPair(LEGACY_PROVIDER);
		this.tests++;
		LOG.write(' done!\n');
	}
	checkCNGGenKeyPair() {
		LOG.write('Testing CNG RSA key pair generation...');
		this.cngKeyPair = this.#assertGenKeyPair(CNG_PROVIDER);
		this.tests++;
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
					new asn1js.Set({ value: [
						new asn1js.Utf8String({ value: cn })
					]})
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
		return new Uint8Array(request.toBER(false));
	}
	#assertSignRequest(keyPair)
	{
		let cn = 'Unit test user certificate common name number ' + ++indexCN;
		let certificateRequestInfo = this.#makeCertificationRequestInfo(keyPair.pubKey, cn);
		let toBeSigned = Buffer.from(certificateRequestInfo.toBER(false));
		let hash = crypto.createHash('sha256');
		hash.update(toBeSigned);
		assert(this.enroll.sign, 'The expected Enroll.sign() method is undefined');
		let signed = this.enroll.sign(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, keyPair.privKey);
		assert(signed, 'Signature failure');
		assert(signed instanceof Uint8Array, 'Data returned member must be a Uint8Array');
		return this.#makeCertificationRequest(certificateRequestInfo, signed);
	}
	checkSignLegacyRequest() {
		LOG.write('Testing a certificate request signature with a legacy key...');
		this.legacyCSR = this.#assertSignRequest(this.legacyKeyPair);
		this.tests++;
		LOG.write(' done!\n');
	}
	checkSignCNGRequest() {
		LOG.write('Testing a certificate request signature with a CNG key...');
		this.cngCSR = this.#assertSignRequest(this.cngKeyPair);
		this.tests++;
		LOG.write(' done!\n');
	}
	#signRequest(csr, fname) {
		let pem = '-----BEGIN CERTIFICATE REQUEST-----\n' + toBase64(csr) + '\n-----END CERTIFICATE REQUEST-----';
		fs.writeFileSync(path.resolve(__dirname, fname), Buffer.from(pem));
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
		this.pkcs7 = this.#signRequest(this.legacyCSR, "legacy-request.req");
		let userCert = this.#getSignerCertificate(this.pkcs7);
		assert(this.enroll.installCertificate, 'The expected Enroll.installCertificate() method is undefined');
		assert(this.enroll.installCertificate(userCert), 'Failure on install user certificate');
		this.tests++;
		LOG.write(' done!\n');
	}
	checkInstallCNGCert() {
		LOG.write('Testing install user certificate...');
		this.pkcs7 = this.#signRequest(this.cngCSR, "cng-request.req");
		let userCert = this.#getSignerCertificate(this.pkcs7);
		assert(this.enroll.installCertificate, 'The expected Enroll.installCertificate() method is undefined');
		assert(this.enroll.installCertificate(userCert), 'Failure on install user certificate');
		this.tests++;
		LOG.write(' done!\n');
	}
	checkInstallChain() {
		LOG.write('Testing install CA certificates chain...');
		assert(this.pkcs7, 'This test requires that checkInstallLegacyCert test succeeds');
		let chain = this.#getCAChain(this.pkcs7);

		assert(this.enroll.installChain, 'The expected Enroll.installChain() method is undefined');
		let done = this.enroll.installChain(chain);
		let msg = done ? ' done!' : ' Chain already installed.';
		this.tests++;
		LOG.write(msg);
		LOG.write('\n');
	}
	checkDeleteLegacyKey() {
		LOG.write('Testing legacy RSA key pair removal...');
		assert(this.legacyKeyPair, 'This test requires that checkLegacyGenKeyPair test succeeds');
		assert(this.enroll.deleteKeyPair, 'The expected Enroll.deleteKeyPair() method is undefined');
		assert(this.enroll.deleteKeyPair(this.legacyKeyPair.privKey), 'Failed to remove RSA key pair');
		this.tests++;
		LOG.write(' done!\n');
	}
	checkDeleteCNGKey() {
		LOG.write('Testing Windows CNG RSA key pair removal...');
		assert(this.cngKeyPair, 'This test requires that checkCNGGenKeyPair test succeeds');
		assert(this.enroll.deleteKeyPair, 'The expected Enroll.deleteKeyPair() method is undefined');
		assert(this.enroll.deleteKeyPair(this.cngKeyPair.privKey), 'Failed to remove RSA key pair');
		this.tests++;
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

		test.checkCNGGenKeyPair();
		test.checkSignCNGRequest();
		test.checkInstallCNGCert();
		test.checkInstallChain();
		test.checkDeleteCNGKey();

		LOG.write(test.tests.toString());
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
