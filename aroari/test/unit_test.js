'use strict';

const fs = require('fs');
const path = require('path');
const Aroari = require('../src/aroari');
const assert = require('assert');
const cp = require('child_process');
const LOG = process.stdout;

let PKIDir = __dirname;
let indexCN = 0;

class OpenSSLWrapper
{
	constructor() {
		this.pki = PKIDir
		this.openSSL = path.resolve(this.pki, 'openssl.exe');
		this.caConf = path.resolve(this.pki, 'caend.cnf');
		this.signConf = path.resolve(this.pki, 'sign.cnf');
		this.options = {cwd: this.pki, windowsHide: false };
		this.endCert = path.resolve(this.pki, 'endcert.pem');
		this.interCert = path.resolve(this.pki, 'intercert.pem');
		this.rootCert = path.resolve(this.pki, 'caroot.pem');
		if (!(
			fs.existsSync(this.openSSL) &&
			fs.existsSync(this.caConf) &&
			fs.existsSync(this.signConf) &&
			fs.existsSync(this.endCert) &&
			fs.existsSync(this.interCert) &&
			fs.existsSync(this.rootCert)
		))	throw 'Some of the PKI required files does not found';
	}
	execOpenSSL(args) {
		let ret = cp.spawnSync(this.openSSL, args, this.options);
		if (ret.status != 0)
		{
			if (ret.stderr) console.log(new TextDecoder().decode(ret.stderr));
			throw 'OpenSSL has exited with status code ' + ret.status.toString();
		}
		if (ret.stdout) console.log(new TextDecoder().decode(ret.stdout));
		if (ret.stderr) console.log(new TextDecoder().decode(ret.stderr));
		return ret.status;
	}
	verifyCMS(cms) {
		if (!fs.existsSync(cms)) throw 'CMS SignedData file must exists at current directory';
		let args = [
			'smime',
			'-verify',
			'-in',
			cms,
			'-inform',
			'PEM',
			'-CAfile',
			this.rootCert
		];
		return this.execOpenSSL(args);
	}
	signCert(request) {
		let req = path.resolve(__dirname, request);
		let out = path.format({
			dir: __dirname,
			name: path.basename(request, path.extname(request)),
			ext: '.pem'
		});
		let args = [
			'ca',
			'-config',
			this.caConf,
			'-notext',
			'-passin',
			'pass:secret',
			'-batch',
			'-in',
			req,
			'-out',
			out,
			'-days',
			'1825',
			'-extfile',
			this.signConf,
			'-extensions',
			'altv3sign'
		];
		if (!fs.existsSync(req)) throw 'Request file must exists at current directory';
		if (fs.existsSync(out)) throw 'Request file must not have extension .pem';
		this.execOpenSSL(args);
		return out;
	}
	mountPKCS7(cert) {
		let out = path.format({
			dir: __dirname,
			name: path.basename(cert, path.extname(cert)),
			ext: '.p7b'
		});
		if (!fs.existsSync(cert)) throw 'End user certificate file must be at current directory';
		if (fs.existsSync(out)) throw 'A PKCS #7 file with certificate base name must not exists at current directory';
		let args = [
			'crl2pkcs7',
			'-nocrl',
			'-certfile',
			cert,
			'-certfile',
			this.endCert,
			'-certfile',
			this.interCert,
			'-certfile',
			this.rootCert,
			'-out',
			out
		];
		this.execOpenSSL(args);
		return out;
	}
}

const LEGACY_PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
const CNG_PROVIDER = 'Microsoft Software Key Storage Provider';
const CA_COUNTRY = 'BR';
const CA_ORGANIZATION = 'PKI Brazil';
const CA_ORG_UNIT = 'Common Name for All Cats End User CA';
class EnrollTest
{
	constructor()
	{
		LOG.write('Testing certificate enrollment initialization...');
		this.tests = 0;
		this.component = new Aroari.Enroll();
		assert(this.component, 'Failure on Aroari.Enroll initialization');
		LOG.write(' done!\n');
		this.tests++;
	}
	enumDevicesTestCase() {
		LOG.write('Testing cryptographic devices enumeration...');
		assert(this.component.enumerateDevices, 'The expected Aroari.enumerateDevices() method is undefined');
		let devices = this.component.enumerateDevices();
		let found = devices.find((value) => { return value ===  LEGACY_PROVIDER; });
		assert(found, 'The minimum required legacy provider is not present');
		found = devices.find((value) => { return value ===  CNG_PROVIDER; });
		assert(found, 'The minimum required CNG provider is not present');
		LOG.write(' done!\n');
		this.tests++;
		return devices;
	}
	generateCSRTestCase(device, cn) {
		LOG.write('Testing generate key pair and sign a certificate request for provider ');
		LOG.write(device);
		LOG.write('...');
		assert(this.component.generateCSR, 'The expected Aroari.generateCSR method is undefined');
		let csr = this.component.generateCSR({
			device: device,
			rdn : {
				c: CA_COUNTRY,
				o: CA_ORGANIZATION,
				ou: CA_ORG_UNIT,
				cn: cn
			}
		});
		LOG.write(' done!\n');
		this.tests++;
		return csr;
	}
	#signRequest(csr, fName) {
		let request = path.resolve(__dirname, fName);
		fs.writeFileSync(request, Buffer.from(csr));
		let openSSL = new OpenSSLWrapper();
		let cert = openSSL.signCert(request);
		let p7b = openSSL.mountPKCS7(cert);
		let p7PEM = fs.readFileSync(p7b, { encoding: 'utf8'});
		fs.unlinkSync(request);
		fs.unlinkSync(cert);
		fs.unlinkSync(p7b);
		return p7PEM;
	}
	installChainTestCase(csr, fName) {
		LOG.write('Testing install signed certificate chain...');
		let pkcs7 = this.#signRequest(csr, fName);
		let b64 = pkcs7.replace('-----BEGIN PKCS7-----', '').replace('-----END PKCS7-----', '').replace('-----BEGIN CMS-----', '').replace('-----END CMS-----', '').replace(/\r?\n|\r/g, '');
		let derPKCS7 = Aroari.Base64.atob(b64);
		assert(this.component.installCertificates, 'The expected Enroll.installCertificates method is undefined');
		let done = this.component.installCertificates(derPKCS7);
		let msg = done ? ' done!\n' : ' at least one CA certificate is already installed\n';
		this.tests++;
		LOG.write(msg);
	}
}
const TO_BE_SIGNED = 'Text transaction to be signed';
class SignTest
{
	constructor()
	{
		LOG.write('Testing digital signature initialization...');
		this.tests = 0;
		this.component = new Aroari.Sign();
		assert(this.component, 'Failure on Aroari.Sign() initialization');
		LOG.write(' done!\n');
		this.tests++;
	}
	enumerateCertificatesTestCase() {
		LOG.write('Testing signing certificates enumeration...');
		assert(this.component.enumerateCertificates, 'The expected Sign.enumerateCertificates() is undefined');
		let certs = this.component.enumerateCertificates();
		assert(Array.isArray(certs), 'Method must return an array of Xapiripe.Certificate objects');
		assert(certs.length >= 2, 'At least two certificates generated by Enroll tests must be returned');
		let i = 0;
		while (i < certs.length)
		{
			assert(typeof certs[i].subject === 'string', 'Xapiripe.Certificate.subject member must exist as a string');
			assert(typeof certs[i].issuer  === 'string', 'Xapiripe.Certificate.issuer member must exist as a string');
			assert(typeof certs[i].serial  === 'string', 'Xapiripe.Certificate.serial member must exist as a string');
			assert(typeof certs[i].handle != 'undefined' && !isNaN(certs[i].handle) & certs[i].handle > 0, 'Xapiripe.Certificate.handle must be a positive number');
			i++;
		}
		LOG.write(' done!\n');
		this.tests++;
		return certs;		
	}
	#selectCert(certs, expression) {
		let i = 0;
		while (i < certs.length)
		{
			if (certs[i].subject.match(expression)) return certs[i];
			i++;
		}
		return null;
	}
	basicSignTestCase(certs, expression) {
		let cert = this.#selectCert(certs, expression);
		assert(cert, 'Certificate select expression does not return a value. Cannot execute test');
		LOG.write('Testing basic CAdES signature by certificate ');
		LOG.write(cert.subject);
		LOG.write('...');
		assert(this.component.sign, 'The expected method Sign.Sign() is undefined');
		let pkcs7 = this.component.sign({
			handle: cert.handle,
			toBeSigned: TO_BE_SIGNED
		});
		assert(pkcs7, 'Return value is undefined');
		assert(typeof pkcs7 === 'string', 'Return value must be a string');
		assert(pkcs7.startsWith('-----BEGIN PKCS7-----'), 'Return value must be a PKCS #7, PEM encoded document');
		LOG.write(' done!\n');
		this.tests++;
		return pkcs7;
	}
	signCommitmentTypeTestCase(certs, expression) {
		let cert = this.#selectCert(certs, expression);
		assert(cert, 'Certificate select expression does not return a value. Cannot execute test');
		LOG.write('Testing CAdES signature with CommitmentType by certificate ');
		LOG.write(cert.subject);
		LOG.write('...');
		assert(this.component.sign, 'The expected method Sign.Sign() is undefined');
		let pkcs7 = this.component.sign({
			handle: cert.handle,
			toBeSigned: TO_BE_SIGNED,
			cades: {
				commitmentType: Aroari.CommitmentType.proofOfCreation
			}
		});
		assert(pkcs7, 'Return value is undefined');
		assert(typeof pkcs7 === 'string', 'Return value must be a string');
		assert(pkcs7.startsWith('-----BEGIN PKCS7-----'), 'Return value must be a PKCS #7, PEM encoded document');
		LOG.write(' done!\n');
		this.tests++;
		return pkcs7;
	}
	verifyWithOpenSSL(pkcs7, fname) {
		LOG.write('Using OpenSSL to verify generated CMS Signed Data...\n');
		let cms = path.resolve(__dirname, fname);
		fs.writeFileSync(cms, Buffer.from(pkcs7));
		let openSSL = new OpenSSLWrapper();
		let ret = openSSL.verifyCMS(cms);
		fs.unlinkSync(cms);
		let msg = ret == 0 ? ' done!\n' : ' verification failed!\n';
		LOG.write(msg);
	}
	parseCMSTestCase(pkcs7) {
		LOG.write('Testing parse of CMS Signed Data document...');
		let cms = new Aroari.CMSSignedData(pkcs7);
		assert(cms.signedData, 'CMS SignedData parsing failed');
		LOG.write(' done!\n');
		this.tests++;
		return cms;
	}
	verifySignatureTestCase(cms) {
		LOG.write('Testing CMS SignedData cryptographic signature validation...');
		assert(cms.verify, 'The expected CMSSignedData.verify() method is undefined');
		cms.verify();
		LOG.write(' done!\n');
		this.tests++;
	}
	verifyTrustworthyTestCase(cms) {
		LOG.write('Testing signing certificate trustworthy validation...');
		assert(cms.verifyTrustworthy, 'The expected CMSSignedData.verifyTrustworthy() method is undefined');
		cms.verifyTrustworthy();
		LOG.write(' done!\n');
		this.tests++;
	}
	getSidTestCase(cms) {
		LOG.write('Testing get signer identifier...');
		assert(cms.getSignerIdentifier, 'The expected CMSSignedData.getSignerIdentifier() method is undefined');
		let sid = cms.getSignerIdentifier();
		assert(sid, 'Could not get sid');
		assert(sid.issuer, 'The returned object lacks the issuer field');
		assert(sid.serialNumber, 'The returned object lacks the serialNumber field');
		LOG.write(' done!\n');
		this.tests++;
		return sid;
	}
	getEncapsulatedContentTestCase(cms) {
		LOG.write('Testing get encapsulated content info...')
		assert(cms.getSignedContent, 'The expected CMSSignedData.getSignedContent() method is undefined');
		let eContent = cms.getSignedContent();
		assert(eContent, 'Returned value is undefined');
		assert(eContent.byteLength > 0, 'Invalid returned value');
		let value = new TextDecoder().decode(eContent);
		assert(value.match(TO_BE_SIGNED), 'Unexpected return value');
		LOG.write(' done!\n');
		this.tests++;
		return value;
	}
}

function main() {
	// Initialization
	if (process.argv.length > 2) PKIDir = path.resolve(process.argv[2]);
	let indexFile = path.join(PKIDir, 'CNindex.txt');
	if (fs.existsSync(indexFile)) indexCN = fs.readFileSync(indexFile)
	else fs.writeFileSync(indexFile, indexCN.toString());
	new OpenSSLWrapper();

	// Enrollment tests
	console.log('Enrollment test case battery');
	let enrollTest = new EnrollTest();
	let devices = enrollTest.enumDevicesTestCase();
	console.log('Installed devices:')
	console.log(devices);
	let capiCN = 'User CN to legacy CryptoAPI ' + ++indexCN;
	let capiCSR = enrollTest.generateCSRTestCase(LEGACY_PROVIDER, capiCN);
	console.log('Request generated:');
	console.log(capiCSR);
	enrollTest.installChainTestCase(capiCSR, 'capi-request.req');
	let cngCN = 'User CN to CNG API ' + ++indexCN;
	let cngCSR = enrollTest.generateCSRTestCase(CNG_PROVIDER, cngCN);
	console.log('Request generated:');
	console.log(cngCSR);
	enrollTest.installChainTestCase(cngCSR, 'cng-request.req');

	// Signature tests
	console.log('Signature test case battery');
	let signTest = new SignTest();
	let certs = signTest.enumerateCertificatesTestCase();
	console.log('Installed certificates:');
	console.log(certs);
	
	let pkcs7 = signTest.basicSignTestCase(certs, /CryptoAPI/gi);
	console.log('Signed document:');
	console.log(pkcs7);
	let cms = signTest.parseCMSTestCase(pkcs7);
	signTest.verifySignatureTestCase(cms);
	signTest.verifyTrustworthyTestCase(cms);
	signTest.verifyWithOpenSSL(pkcs7, 'capi-cms.pem');
	let sid = signTest.getSidTestCase(cms);
	console.log('Signer identifier:');
	console.log(sid.issuer);
	console.log(sid.serialNumber);
	let eContent = signTest.getEncapsulatedContentTestCase(cms);
	console.log('Signed content: ' + eContent);

	pkcs7 = signTest.basicSignTestCase(certs, /CNG/gi);
	console.log('Signed document:');
	console.log(pkcs7);
	cms = signTest.parseCMSTestCase(pkcs7);
	signTest.verifySignatureTestCase(cms);
	signTest.verifyTrustworthyTestCase(cms);
	signTest.verifyWithOpenSSL(pkcs7, 'cng-cms.pem');
	sid = signTest.getSidTestCase(cms);
	console.log('Signer identifier:');
	console.log(sid.issuer);
	console.log(sid.serialNumber);
	eContent = signTest.getEncapsulatedContentTestCase(cms);
	console.log('Signed content: ' + eContent);

	pkcs7 = signTest.signCommitmentTypeTestCase(certs, /CryptoAPI/gi);
	console.log('Signed document:');
	console.log(pkcs7);
	cms = signTest.parseCMSTestCase(pkcs7);
	signTest.verifySignatureTestCase(cms);
	signTest.verifyTrustworthyTestCase(cms);
	signTest.verifyWithOpenSSL(pkcs7, 'capi-cms.pem');
	sid = signTest.getSidTestCase(cms);
	console.log('Signer identifier:');
	console.log(sid.issuer);
	console.log(sid.serialNumber);
	eContent = signTest.getEncapsulatedContentTestCase(cms);
	console.log('Signed content: ' + eContent);

	pkcs7 = signTest.signCommitmentTypeTestCase(certs, /CNG/gi);
	console.log('Signed document:');
	console.log(pkcs7);
	cms = signTest.parseCMSTestCase(pkcs7);
	signTest.verifySignatureTestCase(cms);
	signTest.verifyTrustworthyTestCase(cms);
	signTest.verifyWithOpenSSL(pkcs7, 'cng-cms.pem');
	sid = signTest.getSidTestCase(cms);
	console.log('Signer identifier:');
	console.log(sid.issuer);
	console.log(sid.serialNumber);
	eContent = signTest.getEncapsulatedContentTestCase(cms);
	console.log('Signed content: ' + eContent);

	let tests = enrollTest.tests;
	tests += signTest.tests;
	LOG.write(tests.toString());
	LOG.write(' test cases performed.\n')
	fs.writeFileSync(indexFile, indexCN.toString());
}	main();
