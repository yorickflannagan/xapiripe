/**
 * @file Testes de unidade do serviço Hekura
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';

const path = require('path');
const Hekura = require(path.join(__dirname, '..', 'src', 'hekura'));
const assert = require('assert');
const LOG = process.stdout;
const http = require('http');
const fs = require('fs');
const cp = require('child_process');

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

const ORIGINS = [ 'http://192.168.0.3:8080', 'http://10.0.2.15:8080' ];
const ORIGIN = 'http://10.0.2.15:8080';
const LEGACY_PROVIDER = 'Microsoft Enhanced RSA and AES Cryptographic Provider';
const CNG_PROVIDER = 'Microsoft Software Key Storage Provider';

class TestService
{
	constructor() {
		LOG.write('Testing HTTPServer initialization...');
		assert(Hekura.HTTPServer, 'The exepected Hekura.HTTPServer class is undefined');
		this.tests = 0;
		this.service = new Hekura.HTTPServer({ cors: new Hekura.CORSBlockade(ORIGINS) });
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
		LOG.write('Testing enumerate cryptographi devices...');
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

	stopServerTestCase() {
		LOG.write('Testing HTTPServer shutdown...');
		assert(this.service.stop, 'The expected Hekura.HTTPServer#stop() method is undefined');
		return this.service.stop();
	}
}

async function main() {
	// Initialization
	if (process.argv.length > 2) PKIDir = path.resolve(process.argv[2]);
	let indexFile = path.join(PKIDir, 'CNindex.txt');
	if (fs.existsSync(indexFile)) indexCN = fs.readFileSync(indexFile)
	else fs.writeFileSync(indexFile, indexCN.toString());
	new OpenSSLWrapper();

	console.log('Hekura test case battery')
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
	console.log(devices);

	// Enroll tests
	let capiCN = 'User CN to legacy CryptoAPI ' + ++indexCN;
	let capiCSR = await test.generateCSRTestCase(LEGACY_PROVIDER, capiCN);
	test.tests++;
	LOG.write(' done!\n');
	console.log(capiCSR);

	let pkcs7 = test.signRequest(capiCSR, 'capi-request.req');
	let statusCode = await test.installChainTestCase(pkcs7);
	let msg = statusCode == 201 ? ' done!\n' : ' at least one certificate was already installed\n';
	LOG.write(msg);

	let cngCN = 'User CN to CNG API ' + ++indexCN;
	let cngCSR = await test.generateCSRTestCase(CNG_PROVIDER, cngCN);
	test.tests++;
	LOG.write(' done!\n');
	console.log(cngCSR);

	pkcs7 = test.signRequest(cngCSR, 'cng-request.req');
	statusCode = await test.installChainTestCase(pkcs7);
	msg = statusCode == 201 ? ' done!\n' : ' at least one certificate was already installed\n';
	LOG.write(msg);

	// Finalization
	await test.stopServerTestCase();
	test.tests++;
	LOG.write(' done!\n');

	LOG.write(test.tests.toString());
	LOG.write(' test cases performed.\n')
}	main();
