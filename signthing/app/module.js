/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 * 		diego.sohsten@gmail.com
 *
 * Signithing - desktop application UI
 * See https://bitbucket.org/yorick-flannagan/signithing/src/master/
 * module.js - Javascript modules
 * 
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3.0 of
 * the License, or (at your option) any later version.
 *
 * This application is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See https://opensource.org/licenses/LGPL-3.0
 *
 */
'use strict';

const fs = require('fs');

/**
 * App configuration
 * 	SignatureOptions: Sign wizard options
 * 		step: initial step of wizard
 * 		certificate: signing certificates array selected index
 * 		algorithm: signing algorithm
 * 		format: signed envelope format
 * 	lastFolder: last open file
 * 	attach: attached signed data indicator
 */
class SignatureOptions
{
	constructor()
	{
		this.step = 1;
		this.certificate = -1;
		this.algorithm = -1;
		this.format = -1;
	}
}
class Config
{
	constructor()
	{
		this.signatureOptions = new SignatureOptions();
		this.lastFolder = '';
		this.attach = true;
	}
	/**
	 * Save current object state
	 * @param { string } options: complete path to JSON file
	 */
	store(options) { fs.writeFileSync(options, JSON.stringify(this)); }
	/**
	 * Load configuration file, if it exists
	 * @param { string } options: complete path to JSON file
	 * @returns an instance of Config object
	 */
	static load(options)
	{
		let ret;
		if (fs.existsSync(options)) ret = Object.setPrototypeOf(JSON.parse(fs.readFileSync(options, 'utf-8')), Config.prototype)
		else ret = new Config();
		return ret;
	}
}

/**
 * Signature wizard selected data
 * 	signingCert: signing certificae
 * 	signingAlgorithm: signature algorithm
 * 	envelopeFormat: CAdES format
 * 	signedContents: signed data (file)
 * 	signedEnvelope: CMS file to be created
 * 	attachContents: attached signed data indicator
 * 	saveChoices: save choices to next time indicator
 */
const CKM_SHA1_RSA_PKCS   = 0x00000006;
const CKM_SHA256_RSA_PKCS = 0x00000040;
const CKM_SHA384_RSA_PKCS = 0x00000041;
const CKM_SHA512_RSA_PKCS = 0x00000042;
class SigningData
{
	constructor()
	{
		this.signingCert = '';
		this.signingAlgorithm = '';
		this.envelopeFormat = '';
		this.signedContents = '';
		this.signedEnvelope = '';
		this.attachContents = true;
		this.saveChoices = false;
	}
	/**
	 * Get signature algorithm as a PKCS #11 constant
	 * @returns cryptoki algorithm number
	 */
	algorithmAsNumber()
	{
		if (this.signingAlgorithm.localeCompare('sha1WithRSAEncryption',   { sensitivity: 'base' }) == 0) return CKM_SHA1_RSA_PKCS;
		if (this.signingAlgorithm.localeCompare('sha256WithRSAEncryption', { sensitivity: 'base' }) == 0) return CKM_SHA256_RSA_PKCS;
		if (this.signingAlgorithm.localeCompare('sha384WithRSAEncryption', { sensitivity: 'base' }) == 0) return CKM_SHA384_RSA_PKCS;
		if (this.signingAlgorithm.localeCompare('sha512WithRSAEncryption', { sensitivity: 'base' }) == 0) return CKM_SHA512_RSA_PKCS;
	}
}

/**
 * Returned as a report of an operation
 * - success: success indicator
 * - message: general report
 * - detail: detailed information
 */
class OperationResult
{
	constructor(success, message, detail)
	{
		this.success = success;
		this.message = message;
		this.detail = detail;
	}
}

/**
 * Files required to verify a signature
 *	- pkcs7: complete path to CMS Signed Data envelope;
 *	- contents: if the signed content is not attached to the envelope, this field must
 * be the complete path to it.
 */
class VerifyData
{
	constructor()
	{
		this.pkcs7 = '';
		this.contents = '';
	}
	loadEnvelope()
	{
		if (!fs.existsSync(this.pkcs7)) throw new Error('PKCS #7 file does not exists');
		return fs.readFileSync(this.pkcs7);
	}
	loadContents()
	{
		if (!fs.existsSync(this.contents)) throw new Error('Contentss file does not exists');
		return fs.readFileSync(this.contents);
	}
}

/**
 * CMS Signer Info signed identifier field
 * SignerIdentifier ::= CHOICE {
 *		issuerAndSerialNumber IssuerAndSerialNumber,
 *		subjectKeyIdentifier [0] SubjectKeyIdentifier
 * }
 * IssuerAndSerialNumber ::= SEQUENCE {
 *		issuer Name,
 *		serialNumber CertificateSerialNumber
 * }
 * CertificateSerialNumber ::= INTEGER
 * SubjectKeyIdentifier ::= OCTET STRING
 */
class SignerIdentifier
{
	constructor(cn, sn, kid)
	{
		this.commonName = cn;
		this.serialNumber = sn;
		this.keyIdentifier = kid;
	}
}

let tfHandle = 0;
class TempFile
{
	constructor(tmp)
	{
		this.tmp = tmp;
		this.handle = ++tfHandle;
	}
}

module.exports = { 
	Config,
	SigningData,
	OperationResult,
	VerifyData,
	SignerIdentifier,
	TempFile
}