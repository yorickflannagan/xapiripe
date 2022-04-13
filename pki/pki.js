/**
 * @file Autoridade Certificadora de linha de comando
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

 'use strict';

 const path = require('path');
const fs = require('fs');
const cp = require('child_process');


class OpenSSLWrapper
{
	constructor() {
		this.pki = path.resolve(__dirname);
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
		let input = path.parse(request);
		let out = path.format({
			dir: input.dir,
			name: input.name,
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
			request,
			'-out',
			out,
			'-days',
			'1825',
			'-extfile',
			this.signConf,
			'-extensions',
			'altv3sign'
		];
		if (!fs.existsSync(request)) throw 'Request file must exists at working directory';
		if (fs.existsSync(out)) throw 'Request file must not have extension .pem';
		this.execOpenSSL(args);
		return out;
	}
	mountPKCS7(cert) {
		let input = path.parse(cert);
		let out = path.format({
			dir: input.dir,
			name: input.name,
			ext: '.p7b'
		});
		if (!fs.existsSync(cert)) throw 'End user certificate file must be at working directory';
		if (fs.existsSync(out)) throw 'A PKCS #7 file with certificate base name must not exists at working directory';
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


function main() {
	if (process.argv.length > 3 && process.argv[2].localeCompare('--issue', 'en', { sensitivity: 'base' }) == 0) {
		let request = path.resolve(process.argv[3]);
		console.log('Issuing certificate to request file ' + request);
		let ca = new OpenSSLWrapper();
		let pkcs7 = ca.mountPKCS7(ca.signCert(request));
		console.log('Issued a certificate to file ' + pkcs7);
	}
}	main();

module.exports = {
	OpenSSLWrapper: OpenSSLWrapper
}

