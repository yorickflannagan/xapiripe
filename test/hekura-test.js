/**
 * @file Testes de unidade do serviço Hekura
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';

const path = require('path');
const assert = require('assert');
const LOG = process.stdout;
const http = require('http');
const fs = require('fs');
const yargs = require('yargs');
const argv = yargs(process.argv).argv;

const Aroari = require('../components/aroari');
const Wanhamou = require('../components/wanhamou');
const OpenSSLWrapper = require('../pki/pki').OpenSSLWrapper;
const Hekura = require('../components/hekura');

let PKIDir = __dirname;
let indexCN = 0;

const ORIGINS = [ 'http://192.168.0.3:8080', 'http://10.0.2.15:8080', 'http://localhost:8080' ];
const ORIGIN = 'http://10.0.2.15:8080';
const LEGACY_PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
const CNG_PROVIDER = 'Microsoft Software Key Storage Provider';
const TO_BE_SIGNED = 'Transaction to be signed';
class TestService
{
	constructor() {
		LOG.write('Testing HTTPServer initialization...');
		assert(Hekura.HTTPServer, 'The exepected Hekura.HTTPServer class is undefined');
		this.tests = 0;
		this.service = new Hekura.HTTPServer(undefined, undefined, new Hekura.CORSBlockade(ORIGINS));
		this.tests++;
		LOG.write(' done!\n');
	}

	startServerTestCase() {
		LOG.write('Testing HTTPServer start-up...');
		assert(this.service.start, 'The expected Hekura.HTTPServer#start() method is undefined');
		return this.service.start();
	}

	getAPISpecificationTestCase() {
		LOG.write('Testing GET service API JSON object...');
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty',
				},
				host: '127.0.0.1',
				method: 'GET',
				path: '/',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject(res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'application/json') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => {
					try {
						let api = JSON.parse(body);
						if (!(
							api &&
							api.openapi &&
							api.openapi === '3.0.3' &&
							api.info &&
							api.info.title &&
							api.info.title === 'Hekura'
						))	return reject('Returned JSON object is not the Hekura specification');
					}
					catch (err) { return reject('Invalid JSON object ' + err); }
					return resolve(body);
				});
			});
			request.on('error', (e) => { return reject(e); });
			request.end();
		});
	}

	untrustedRequestTestCase() {
		LOG.write('Testing send a request from an untrusted origin...');
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: '127.0.0.1:8080',
					Referer: '127.0.0.1:8080'
				},
				host: '127.0.0.1',
				method: 'GET',
				path: '/',
				port: 9171
			}, (res) => {
				if (res.statusCode == 403) return resolve(true);
				else return reject('Unexpected HTTP status code: ' + res.statusCode);
			});
			request.on('error', (e) => { return reject(e); });
			request.end();
		});
	}

	localRequestTestCase() {
		LOG.write('Testing send a request from the same origin...');
		return new Promise((resolve, reject) => {
			let request = http.request({
				host: '127.0.0.1',
				method: 'GET',
				path: '/',
				port: 9171
			}, (res) => {
				if (res.statusCode == 403) return resolve(true);
				else return reject('Unexpected HTTP status code: ' + res.statusCode);
			});
			request.on('error', (e) => { return reject(e); });
			request.end();
		});
	}

	enumerateDevicesTestCase() {
		LOG.write('Testing enumerate cryptographic devices...');
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty'
				},
				host: '127.0.0.1',
				method: 'GET',
				path: '/enroll',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'application/json') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => {
					try {
						let devices = JSON.parse(body);
						if (!Array.isArray(devices) || devices.length == 0) return reject('Server returned an invalid JSON object');
						let found = devices.find((value) => { return value ===  LEGACY_PROVIDER; });
						if (!found) return reject('The minimum required legacy provider is not present');
						found = devices.find((value) => { return value ===  CNG_PROVIDER; });
						if (!found) return reject('The minimum required CNG provider is not present');
						return resolve(devices);
					}
					catch (err) { return reject('Invalid JSON object ' + err); }
				});
			});
			request.on('error', (e) => { return reject(e); });
			request.end();
		});
	}

	generateCSRTestCase(device, cn) {
		LOG.write('Testing generate key pair and sign a certificate request for provider ');
		LOG.write(device);
		LOG.write('...');
		let arg = JSON.stringify({ device: device, rdn: { cn: cn }});
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty',
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(arg)
				},
				host: '127.0.0.1',
				method: 'POST',
				path: '/enroll',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'text/plain') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => { return resolve(body); });
			});
			request.on('error', (e) => { return reject(e); });
			request.write(arg);
			request.end();
		});
	}

	signRequest(csr, fName) {
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

	installChainTestCase(pkcs7) {
		LOG.write('Testing install a signed certificate chain...');
		let arg = JSON.stringify({ pkcs7: pkcs7});
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty',
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(arg)
				},
				host: '127.0.0.1',
				method: 'PUT',
				path: '/enroll',
				port: 9171
			}, (res) => {
				if (res.statusCode != 200 && res.statusCode != 201) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				return resolve(res.statusCode);
			});
			request.on('error', (e) => { return reject(e); });
			request.write(arg);
			request.end();
		});
	}

	enumerateCertificatesTestCase() {
		LOG.write('Testing enumerate signing certificates...');
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty'
				},
				host: '127.0.0.1',
				method: 'GET',
				path: '/sign',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'application/json') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => {
					try {
						let certs = JSON.parse(body);
						if (!Array.isArray(certs) || certs.length == 0) return reject('Server returned an invalid JSON object');
						if (certs.length < 2) return reject('At least two certificates generated by Enroll tests must be returned');
						let i = 0;
						while (i < certs.length)
						{
							if (typeof certs[i].subject !== 'string') return reject('Xapiripe.Certificate.subject member must exist as a string');
							if (typeof certs[i].issuer  !== 'string') return reject('Xapiripe.Certificate.issuer member must exist as a string');
							if (typeof certs[i].serial  !== 'string') return reject('Xapiripe.Certificate.serial member must exist as a string');
							if (typeof certs[i].handle === 'undefined' || isNaN(certs[i].handle) || certs[i].handle <= 0) return reject('Xapiripe.Certificate.handle must be a positive number');
							i++;
						}
						return resolve(certs);
					}
					catch (err) { return reject('Invalid JSON object ' + err); }
				});
			});
			request.on('error', (e) => { return reject(e); });
			request.end();
		});
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
	signTestCase(cert) {
		LOG.write('Testing signing a document with certificate ');
		LOG.write(cert.subject);
		LOG.write('...');
		let arg = JSON.stringify({ handle: cert.handle, toBeSigned : { data: TO_BE_SIGNED }});
		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty',
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(arg)
				},
				host: '127.0.0.1',
				method: 'POST',
				path: '/sign',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'text/plain') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => { return resolve(body); });
			});
			request.on('error', (e) => { return reject(e); });
			request.write(arg);
			request.end();
		});
	}

	basicVerifyTestCase(pkcs7) {
		LOG.write('Testing CMS SignedData document verification...');
		let arg = JSON.stringify({ pkcs7: { data: pkcs7 }});

		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty',
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(arg)
				},
				host: '127.0.0.1',
				method: 'POST',
				path: '/verify',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'application/json') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => {
					let report;
					try { report = JSON.parse(body); }
					catch (err) { return reject('Invalid JSON object in response'); }
					if (!report.signatureVerification) return reject('Cryptographic validation failure');
					if (!report.messageDigestVerification) return reject('Message Digest signed attribute validation failure');
					if (!report.signingCertVerification) return reject('Signing Certificate signed attribute validation failure');
					return resolve(body);
				});
			});
			request.on('error', (e) => { return reject(e); });
			request.write(arg);
			request.end();
		});
	}

	completeVerifyTestCase(pkcs7) {
		LOG.write('Testing CMS SignedData document complete verification...');
		let arg = JSON.stringify({ pkcs7: { data: pkcs7 }, verifyTrustworthy: true, getSignerIdentifier: true, getSignedContent: true});

		return new Promise((resolve, reject) => {
			let request = http.request({
				headers: {
					'User-Agent': 'Node.js/16.3.0',
					Accept: '*/*',
					Origin: ORIGIN,
					Referer: ORIGIN,
					'Sec-Fetch-Site': 'cross-site',
					'Sec-Fetch-Mode': 'cors',
					'sec-Fetch-Dest': 'empty',
					'Content-Type': 'application/json',
					'Content-Length': Buffer.byteLength(arg)
				},
				host: '127.0.0.1',
				method: 'POST',
				path: '/verify',
				port: 9171
			}, (res) => {
				let body = '';
				if (res.statusCode != 200) return reject('Unexpected HTTP status code: ' + res.statusCode);
				let allowHeader = res.headers['access-control-allow-origin'];
				if (!allowHeader || allowHeader !== ORIGIN) return reject('Invalid Access-Control-Allow-Origin header in response');
				let ctypeHeader = res.headers['content-type'];
				if (!ctypeHeader || ctypeHeader !== 'application/json') return reject('Invalid Content-Type header in response');
				res.on('data', (chunk) => { body += chunk; });
				res.on('end', () => {
					let report;
					try { report = JSON.parse(body); }
					catch (err) { return reject('Invalid JSON object in response'); }
					if (!report.signatureVerification) return reject('Cryptographic validation failure');
					if (!report.messageDigestVerification) return reject('Message Digest signed attribute validation failure');
					if (!report.signingCertVerification) return reject('Signing Certificate signed attribute validation failure');
					if (!report.certChainVerification) return reject('Signing certificate trustworthy validation failure');
					if (!report.signerIdentifier || typeof report.signerIdentifier.issuer !== 'string' || typeof report.signerIdentifier.serialNumber !== 'string') return reject('Could not get Signer Identifier field');
					if (!report.eContent || typeof report.eContent.data !== 'string' || !report.eContent.binary) return reject('Could not get Encapsulated Content Info field');
					let eContent = new TextDecoder().decode(Aroari.Base64.atob(report.eContent.data));
					if (eContent !== TO_BE_SIGNED) return reject('Signed content does not match');
					return resolve(body);
				});
			});
			request.on('error', (e) => { return reject(e); });
			request.write(arg);
			request.end();
		});
	}

	stopServerTestCase() {
		LOG.write('Testing HTTPServer shutdown...');
		assert(this.service.stop, 'The expected Hekura.HTTPServer#stop() method is undefined');
		return this.service.stop();
	}
}

async function unit_test() {
	try {
		// Initialization
		let indexFile = path.join(PKIDir, 'CNindex.txt');
		if (fs.existsSync(indexFile)) indexCN = fs.readFileSync(indexFile);
		else fs.writeFileSync(indexFile, indexCN.toString());
		new OpenSSLWrapper();
		let current = path.resolve(__dirname);
		Wanhamou.Logger.logConfig({ path: current, level: Wanhamou.LogLevel.DEBUG });

		console.log('Hekura test case battery');
		let test = new TestService();
		await test.startServerTestCase();
		test.tests++;
		LOG.write(' done!\n');

		// REST basic
		let api = await test.getAPISpecificationTestCase();
		test.tests++;
		LOG.write(' done!\n');
		console.log('API specification:');
		console.log(api);
		
		await test.untrustedRequestTestCase();
		test.tests++;
		LOG.write(' done!\n');

		await test.localRequestTestCase();
		test.tests++;
		LOG.write(' done!\n');

		let devices = await test.enumerateDevicesTestCase();
		test.tests++;
		LOG.write(' done!\n');
		console.log('Cryptographic devices:');
		console.log(devices);

		// Enroll tests
		++indexCN;
		let capiCN = 'User CN to legacy CryptoAPI ' + indexCN;
		let capiCSR = await test.generateCSRTestCase(LEGACY_PROVIDER, capiCN);
		test.tests++;
		LOG.write(' done!\n');
		console.log('Certificate signing request:');
		console.log(capiCSR);

		let pkcs7 = test.signRequest(capiCSR, 'capi-request.req');
		let statusCode = await test.installChainTestCase(pkcs7);
		let msg = statusCode == 201 ? ' done!\n' : ' at least one certificate was already installed\n';
		LOG.write(msg);

		++indexCN;
		let cngCN = 'User CN to CNG API ' + indexCN;
		let cngCSR = await test.generateCSRTestCase(CNG_PROVIDER, cngCN);
		test.tests++;
		LOG.write(' done!\n');
		console.log('Certificate signing request:');
		console.log(cngCSR);

		pkcs7 = test.signRequest(cngCSR, 'cng-request.req');
		statusCode = await test.installChainTestCase(pkcs7);
		msg = statusCode == 201 ? ' done!\n' : ' at least one certificate was already installed\n';
		LOG.write(msg);

		// Sign tests
		let certificates = await test.enumerateCertificatesTestCase();
		test.tests++;
		LOG.write(' done!\n');
		console.log('Available signing certificates:');
		console.log(certificates);

		let signingCert = test.selectCert(certificates, capiCN);
		let cms = await test.signTestCase(signingCert);
		test.tests++;
		LOG.write(' done!\n');
		console.log('CMS Signed Data document:');
		console.log(cms);

		let body = await test.basicVerifyTestCase(cms);
		test.tests++;
		LOG.write(' done!\n');
		console.log('Report object in response:');
		console.log(body);

		body = await test.completeVerifyTestCase(cms);
		test.tests++;
		LOG.write(' done!\n');
		console.log('Report object in response:');
		console.log(body);
		
		signingCert = test.selectCert(certificates, cngCN);
		cms = await test.signTestCase(signingCert);
		test.tests++;
		LOG.write(' done!\n');
		console.log('CMS Signed Data document:');
		console.log(cms);

		body = await test.basicVerifyTestCase(cms);
		test.tests++;
		LOG.write(' done!\n');
		console.log('Report object in response:');
		console.log(body);

		body = await test.completeVerifyTestCase(cms);
		test.tests++;
		LOG.write(' done!\n');
		console.log('Report object in response:');
		console.log(body);

		// Finalization
		await test.stopServerTestCase();
		test.tests++;
		LOG.write(' done!\n');

		LOG.write(test.tests.toString());
		LOG.write(' test cases performed.\n');
		fs.unlinkSync(path.join(current, 'xapiripe-0.log'));
	}
	catch (e) {
		console.error('Erro inesperado ao executar o teste de unidade:');
		console.error(e);
		process.exit(1);
	}
}

function testHekura() {
	let runService = false;
	if (argv.pki) {
		PKIDir = path.resolve(argv.pki);
		if (!fs.existsSync(PKIDir)) throw new Error('Argument pki must be an existing directory');
	}
	if (typeof argv.service !== 'undefined') {
		runService = argv.service === 'true' ? true: false;
	}
	if (runService) {
		Wanhamou.Logger.logConfig({ path: path.resolve(__dirname), level: Wanhamou.LogLevel.DEBUG });
		let service = new Hekura.HTTPServer(undefined, undefined, new Hekura.CORSBlockade(ORIGINS));
		service.start();
		console.log('Running Hekura service at http://127.0.0.1:9171');
		console.log('Logging at debug level to ' + path.resolve(__dirname));
		console.log('Hit CTRL-C to stop the server');
	}
	else unit_test();
}

if (argv.check) testHekura();

module.exports = { testHekura };