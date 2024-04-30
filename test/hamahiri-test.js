'use strict';

const path = require('path');
const assert = require('assert');
const process = require('process');
const crypto = require('crypto');
const asn1js = require('asn1js');
const fs = require('fs');
const yargs = require('yargs');
const argv = yargs(process.argv).argv;

const Hamahiri = require('../components/hamahiri');
const Base64  = require('../components/global').Base64Conveter
const OpenSSLWrapper = require('../pki/pki').OpenSSLWrapper;

const LOG = process.stdout;
const LEGACY_PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
const CNG_PROVIDER = 'Microsoft Software Key Storage Provider';
const END_CA_NAME = 'Common Name for All Cats End User CA';
const INTER_CA_NAME = 'Common Name for All Cats Intermediate CA';
const ROOT_CA_NAME = 'Common Name for All Cats Root CA';
let indexCN = 0;
let PKIDir = __dirname;
let verbose = false;

function checkError(err, expectedCode) {
	assert(err instanceof Error, 'Must throw an Error subclass');
	assert(
		typeof err.component != 'undefined' &&
		typeof err.method != 'undefined' &&
		typeof err.errorCode != 'undefined' &&
		typeof err.apiError != 'undefined',
		'Invalid Error subclass'
	);
	assert(err.errorCode === expectedCode, 'Unexpected error code');
}

class EnrollTest
{
	constructor(verbose) {
		LOG.write('Testing certificate enrollment initialization...');
		this.tests = 0;
		this.verbose = verbose;
		this.enroll = new Hamahiri.Enroll();
		assert(this.enroll, 'Failure on Hamahiri.Enroll initialization');
		LOG.write(' done!\n');
		this.tests++;
	}
	genKeyPair(provider)
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
	makeCertificationRequestInfo(rawPubKey, cn) {
		let ver = new asn1js.Integer({ value: 0 });
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
	makeCertificationRequest(certificateRequestInfo, signed) {
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
	signRequest(keyPair, cn)
	{
		let certificateRequestInfo = this.makeCertificationRequestInfo(keyPair.pubKey, cn);
		let toBeSigned = Buffer.from(certificateRequestInfo.toBER(false));
		let hash = crypto.createHash('sha256');
		hash.update(toBeSigned);
		assert(this.enroll.signRequest, 'The expected Enroll.sign() method is undefined');
		let signed = this.enroll.signRequest(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, keyPair.privKey);
		assert(signed, 'Signature failure');
		assert(signed instanceof Uint8Array, 'Data returned member must be a Uint8Array');
		return this.makeCertificationRequest(certificateRequestInfo, signed);
	}
	signCertificate(csr, fname) {
		let pem = '-----BEGIN CERTIFICATE REQUEST-----\n' + Base64.btoa(csr, true) + '\n-----END CERTIFICATE REQUEST-----';
		let request = path.resolve(__dirname, fname);
		fs.writeFileSync(request, Buffer.from(pem));
		let openSSL = new OpenSSLWrapper(this.verbose);
		let cert = openSSL.signCert(request);
		let p7b = openSSL.mountPKCS7(cert);
		let p7PEM = fs.readFileSync(p7b, { encoding: 'utf8'});
		let b64 = p7PEM.replace('-----BEGIN PKCS7-----', '').replace('-----END PKCS7-----', '').replace(/\r?\n|\r/g, '');
		let ret = Base64.atob(b64);
		fs.unlinkSync(request);
		fs.unlinkSync(cert);
		fs.unlinkSync(p7b);
		return ret;
	}
	getCertificates(pkcs7) {
		let contentInfo = asn1js.fromBER(pkcs7.buffer);
		if (contentInfo.offset == -1) throw 'Invalid PKCS #7 format';
		let content = contentInfo.result.valueBlock.value[1];
		assert(content, 'Invalid PKCS #7 file: missing content');
		let signedData = content.valueBlock.value[0];
		assert(signedData && signedData instanceof asn1js.Sequence, 'Invalid PKCS #7: missing signed data');
		assert(signedData.valueBlock.value[3] && signedData.valueBlock.value[3].valueBlock.value, 'Invalid PKCS #7: missing certificates field');
		let certificates = signedData.valueBlock.value[3].valueBlock.value;

		let i = 0;
		let ret = { signer: null, chain: [] };
		while (i < certificates.length)
		{
			let tbs = certificates[i].valueBlock.value[0];
			assert(tbs instanceof asn1js.Sequence, 'Invalid X.509 certificate format: TBSCertificate');
			assert(tbs.valueBlock.value[7], 'Could not find extensions field');
			assert(Array.isArray(tbs.valueBlock.value[7].valueBlock.value), 'Invalid extensions field');
			let extensions = tbs.valueBlock.value[7].valueBlock.value[0].valueBlock.value;
			assert(Array.isArray(extensions, 'Invalid extensions field'));
			let j = 0;
			let caCert = false;
			while (!caCert && j < extensions.length)
			{
				let oid = extensions[j].valueBlock.value[0];
				assert(oid instanceof asn1js.ObjectIdentifier, 'Invalid extension content');
				if (oid.valueBlock.toString() === '2.5.29.19')
				{
					caCert = true;
					ret.chain.push(new Uint8Array(certificates[i].valueBeforeDecode));
				}
				j++;
			}
			if (!caCert) ret.signer = new Uint8Array(certificates[i].valueBeforeDecode);
			i++;
		}
		assert(ret.signer && ret.signer instanceof Uint8Array, 'Invalid certificates chain: missing signer certificate');
		assert(ret.chain.length > 0, 'Invalid certificates chain: missing issuer certificate');
		return ret;
	}


	enumDevicesTestCase() {
		LOG.write('Testing cryptographic devices enumeration...');
		assert(this.enroll.enumerateDevices, 'The expected Enroll.enumerateDevices() method is undefined');
		const devices = this.enroll.enumerateDevices();
		let found = devices.find((value) => { return value ===  LEGACY_PROVIDER; });
		assert(found, 'The minimum required legacy provider is not present');
		LOG.write(' done!\n');
		this.tests++;
		return devices;
	}
	keyGenFewArgumentsTestCase() {
		LOG.write('Testing RSA key pair generation with few arguments... ');
		try { this.enroll.generateKeyPair(2048); }
		catch (err) { checkError(err, 1); }
		LOG.write(' done!\n');
		this.tests++;
	}
	keyGenInvalidProviderTestCase() {
		LOG.write('Testing RSA key pair generation with a wrong provider... ');
		try { this.enroll.generateKeyPair('Microsoft Base Cryptographic Provider', 2048); }
		catch (err) { checkError(err, 1); }
		LOG.write(' done!\n');
		this.tests++;
	}
	keyGenTestCase(provider) {
		LOG.write('Testing RSA key pair generation with provider ');
		LOG.write(provider);
		LOG.write('...');
		let keyPair = this.genKeyPair(provider);
		this.tests++;
		LOG.write(' done!\n');
		return keyPair;
	}
	signCSRTestCase(keyPair, cn) {
		LOG.write('Testing signature of a certificate request to ');
		LOG.write(cn);
		LOG.write('...');
		let csr = this.signRequest(keyPair, cn);
		this.tests++;
		LOG.write(' done!\n');
		return csr;
	}
	installCertTestCase(csr, requestFile) {
		LOG.write('Testing install user certificate...');
		let pkcs7 = this.signCertificate(csr, requestFile);
		let certs = this.getCertificates(pkcs7);
		assert(this.enroll.installCertificate, 'The expected Enroll.installCertificate() method is undefined');
		let added = this.enroll.installCertificate(certs.signer);
		let msg = added ? '  done!\n' :' certificate already installed\n';
		this.tests++;
		LOG.write(msg);
		return certs.chain;
	}
	installChainTestCase(chain) {
		LOG.write('Testing install CA certificates chain...');
		assert(this.enroll.installChain, 'The expected Enroll.installChain() method is undefined');
		let done = this.enroll.installChain(chain);
		let msg = done ? ' done!\n' : ' at least one CA certificate is already installed\n';
		this.tests++;
		LOG.write(msg);
	}
	deleteKeyTestCase(privKey) {
		LOG.write('Testing RSA key pair removal...');
		assert(this.enroll.deleteKeyPair, 'The expected Enroll.deleteKeyPair() method is undefined');
		assert(this.enroll.deleteKeyPair(privKey), 'Failed to remove RSA key pair');
		this.tests++;
		LOG.write(' done!\n');
	}
	deleteCertificateTestCase(subject, issuer) {
		LOG.write('Testing certificate issued to ');
		LOG.write(subject);
		LOG.write(' by ');
		LOG.write(issuer)
		LOG.write(' removal...');
		assert(this.enroll.deleteCertificate, 'The expected Enroll.deleteCertificate() method is undefined');
		let removed = this.enroll.deleteCertificate(subject, issuer);
		let msg = removed ? ' done!\n' : ' could not remove certificate\n';
		this.tests++;
		LOG.write(msg);
	}
}

class SignTest
{
	constructor() {
		this.tests = 0;

		LOG.write('Testing digital signature initialization...');
		this.sign = new Hamahiri.Sign();
		assert(this.sign, 'Failure on Hamahiri.Sign initialization');
		LOG.write(' done!\n');
		this.tests++;
	}
	enumCertsTestCase() {
		LOG.write('Testing signing certificates enumeration...');
		assert(this.sign.enumerateCertificates, 'The expected Sign.enumerateCertificates() method is undefined');
		let certs = this.sign.enumerateCertificates();
		assert(certs, 'Signing certificates enumeration failed');
		assert(Array.isArray(certs), 'Sign.enumerateCertificates() must return an array of Xapiripe.Certificate');
		assert(certs.length > 0, 'There are no signing certificates installed. Cannot proceed with test.');
		certs.forEach(value => {
			assert(value.subject && value.issuer && value.serial && value.handle, 'Sign.enumerateCertificates() must return an array of Xapiripe.Certificate objects');
			assert(!isNaN(value.handle) && value.handle > 0, 'Certificate.handle member must be a positive integer');
		});
		LOG.write(' done!\n');
		this.tests++;
		return certs;
	}
	repeatedEnumCertsTestCase() {
		LOG.write('Checking certificates enumeration bug correction...');
		let certs = this.sign.enumerateCertificates();
		let len = certs.length;
		certs = this.sign.enumerateCertificates();
		assert(certs.length == len, 'Sign.enumerateCertificates() must not enumerate certificates more than once');
		LOG.write(' done!\n');
		this.tests++;
		return certs;
	}
	incorrectCNTestCase() {
		LOG.write('Checking certificates bad DN bug correction...');
		let certs = this.sign.enumerateCertificates();
		assert(
			certs[0].subject.includes('C=') &&
			certs[0].subject.includes('O=') &&
			certs[0].subject.includes('OU=') &&
			certs[0].subject.includes('CN=') &&
			certs[0].issuer.includes('C=BR') &&
			certs[0].issuer.includes('O=') &&
			certs[0].issuer.includes('OU=') &&
			certs[0].issuer.includes('CN='),
			'Sign.enumerateCertificates() must return complete DN for subjec and issuer'
		);
		LOG.write(' done!\n');
		this.tests++;
		return certs;

	}
	selectCert(certs, expression) {
		let i = 0;
		while (i < certs.length)
		{
			if (certs[i].subject.match(expression)) return certs[i];
			i++;
		}
		return null;
	}
	assertSign(cert) {
		assert(this.sign.sign, 'The expected Sign.sign() method is undefined');
		let hash = crypto.createHash('sha256');
		hash.update('Transaction to sign');
		let signature = this.sign.sign(hash.digest(), Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS, cert.handle);
		assert(signature, 'Failure on sign transaction hash');
		assert(signature instanceof Uint8Array, 'Signature must be an instance of Uint8Array');
		return signature;
	}
	signWithLegacyKeyTestCase(cert) {
		LOG.write('Testing sign with legacy CryptoAPI key...');
		let signature = this.assertSign(cert);
		LOG.write(' done!\n');
		this.tests++;
		return signature;
	}
	signWithCNGKeyTestCase(cert) {
		LOG.write('Testing sign with CNG key...');
		let signature = this.assertSign(cert);
		LOG.write(' done!\n');
		this.tests++;
		return signature;
	}
	getChainTestCase(cert) {
		LOG.write('Testing get certificate chain...');
		assert(this.sign.getCertificateChain, 'The expected Sign.getCertificateChain() method is undefined');
		let chain = this.sign.getCertificateChain(cert.handle);
		assert(chain, 'Failure on get certificate chain');
		assert(Array.isArray(chain) && chain.length > 0, 'getCertificateChain() must return an array');
		let i = 0;
		while (i < chain.length) assert(chain[i++] instanceof Uint8Array, 'Certificate must be an instance of Uint8Array');
		if (chain.length < 4) LOG.write(' Warning: incomplete certificate chain, but basic test succeeded!\n');
		else LOG.write(' done!\n');
		this.tests++;
		return chain;
	}
	validateIssuerTestCase(cert) {
		LOG.write('Testing certificate issuer validation... ');
		assert(this.sign.getIssuerOf, 'The expected Sign.getIssuerOf() method is undefined');
		let issuers = this.sign.getIssuerOf(cert);
		assert(issuers.length > 0, 'No issuers found! Test case has failed');
		let i = 0;
		let verified = false;
		let certSubject = new crypto.X509Certificate(cert);
		while (i < issuers.length && !verified)
		{
			let certIssuer = new crypto.X509Certificate(issuers[i]);
			verified = certSubject.verify(certIssuer.publicKey);
			i++;
		}
		assert(verified, 'None of the issuers certificates found in Windows repository has signed this certificate');
		this.tests++;
		LOG.write(' done!\n');
	}
}

function testHamahiri() {
	if (argv.verbose) verbose = true;
	if (argv.pki) PKIDir = path.resolve(argv.pki);
	let indexFile = path.join(PKIDir, 'CNindex.txt');
	if (fs.existsSync(indexFile)) indexCN = fs.readFileSync(indexFile);
	else fs.writeFileSync(indexFile, indexCN.toString());

	// Enroll tests
	LOG.write('Tests battery of certificate enrollment:\n');
	let enroll = new EnrollTest(verbose);
	let devices = enroll.enumDevicesTestCase();
	if (verbose) {
		console.log("Installed devices:");
		console.log(devices);
	}
	enroll.keyGenFewArgumentsTestCase();
	enroll.keyGenInvalidProviderTestCase();
	let capiKeyPair = enroll.keyGenTestCase(LEGACY_PROVIDER);
	++indexCN;
	let capiCN = 'User CN to legacy CryptoAPI ' + indexCN;
	let capiCSR = enroll.signCSRTestCase(capiKeyPair, capiCN);
	let chain = enroll.installCertTestCase(capiCSR, 'legacy-request.req');
	enroll.installChainTestCase(chain);
	let cngKeyPair = enroll.keyGenTestCase(CNG_PROVIDER);
	++indexCN;
	let cngCN = 'User CN to Windows CNG ' + indexCN;
	let cngCSR = enroll.signCSRTestCase(cngKeyPair, cngCN);
	chain = enroll.installCertTestCase(cngCSR, 'cng-request.req');
	enroll.installChainTestCase(chain);

	// Signing tests
	LOG.write('Tests battery of digital signature:\n');
	let sign = new SignTest();
	let certs = sign.enumCertsTestCase();
	certs = sign.incorrectCNTestCase();
	certs = sign.repeatedEnumCertsTestCase();
	if (verbose) {
		console.log('Installed signing certificates:');
		console.log(certs);
	}
	let signCert = sign.selectCert(certs, /CryptoAPI/gi);
	chain = null;
	if (signCert) {
		LOG.write('Selected signing certificate issued to ' + signCert.subject + '\n');
		let signature = sign.signWithLegacyKeyTestCase(signCert);
		if (!signature) LOG.write('Warning! Signature Uint8Array did not return!\n');
		chain = sign.getChainTestCase(signCert);
	}
	else LOG.write('Warning! Could not find a signing legacy certificate. Cannot complete test battery!\n');
	if (chain) sign.validateIssuerTestCase(chain[0]);
	signCert = sign.selectCert(certs, /CNG/gi);
	chain = null;
	if (signCert) {
		LOG.write('Selected signing certificate issued to ' + signCert.subject + '\n');
		let signature = sign.signWithCNGKeyTestCase(signCert);
		if (!signature) LOG.write('Warning! Signature Uint8Array did not return!\n');
		chain = sign.getChainTestCase(signCert);
	}
	else LOG.write('Warning! Could not find a signing CNG certificate. Cannot complete test battery!\n');
	if (chain) sign.validateIssuerTestCase(chain[0]);

	// Clean-up
	LOG.write('Clean-up basic tests:\n');
	enroll.deleteKeyTestCase(capiKeyPair.privKey);
	enroll.deleteCertificateTestCase(capiCN, END_CA_NAME);
	enroll.deleteKeyTestCase(cngKeyPair.privKey);
	enroll.deleteCertificateTestCase(cngCN, END_CA_NAME);
	enroll.deleteCertificateTestCase(END_CA_NAME, INTER_CA_NAME);
	enroll.deleteCertificateTestCase(INTER_CA_NAME, ROOT_CA_NAME);
	enroll.deleteCertificateTestCase(ROOT_CA_NAME, ROOT_CA_NAME);

	let tests = enroll.tests + sign.tests;
	LOG.write(tests.toString());
	LOG.write(' test cases performed.\n');
	fs.writeFileSync(indexFile, indexCN.toString());
}  //testHamahiri();

if (argv.check) testHamahiri();

module.exports = { testHamahiri };