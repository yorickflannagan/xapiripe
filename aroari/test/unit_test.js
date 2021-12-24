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
		let b64 = pkcs7.replace('-----BEGIN PKCS7-----', '').replace('-----END PKCS7-----', '').replace(/\r?\n|\r/g, '');
		let derPKCS7 = Aroari.Base64.atob(b64);
		assert(this.component.installCertificates, 'The expected Enroll.installCertificates method is undefined');
		let done = this.component.installCertificates(derPKCS7);
		let msg = done ? ' done!\n' : ' at least one CA certificate is already installed\n';
		this.tests++;
		LOG.write(msg);
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

	let tests = enrollTest.tests;
	LOG.write(tests.toString());
	LOG.write(' test cases performed.\n')
	fs.writeFileSync(indexFile, indexCN.toString());
}	main();