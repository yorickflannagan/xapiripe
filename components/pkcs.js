/**
 * @file Implementação das RFC 2986 e da seção 5 da RFC 5652
 * @copyright Copyleft &copy; 2021-2024 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const asn1js = require('asn1js');
const crypto = require('crypto');
const Hamahiri = require('./hamahiri');
const Enroll = Hamahiri.Enroll;
const SignMechanism = Hamahiri.SignMechanism;
const Global = require('./global');
const APIError = Global.APIError;
const Base64Conveter = Global.Base64Conveter;

const x500AttributeTypes = new Map([
	['C', '2.5.4.6' ],
	['O', '2.5.4.10'],
	['OU', '2.5.4.11'],
	['CN', '2.5.4.3' ],
	['L', '2.5.4.7' ],
	['ST', '2.5.4.8' ],
	['STREET', '2.5.4.9' ],
	['DC', '0.9.2342.19200300.100.1.25'],
	['UID', '0.9.2342.19200300.100.1.1']
]);
const pkcs9Attributes = new Map([
	['emailAddress', '1.2.840.113549.1.9.1'],
	['challengePassword', '1.2.840.113549.1.9.7'],
	['friendlyName', '1.2.840.113549.1.9.20']
]);

/**
 * Implementações de envelopes criptográficos
 * @namespace PKCS
 */

/**
 * Utilitário para a criação de objetos CertificationRequestInfo
 * @memberof PKCS
 */
class CertificationRequestInfoBuilder {

	/**
	 * Cria uma nova instância do utilitário
	 */
	constructor() {
		this.version = new asn1js.Integer({ value: 0 });
		this.subject = new asn1js.Sequence({ value: [] });
		this.subjectPKInfo = new asn1js.Sequence({ value: [] });
		this.attributes = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [] });
	}

	/**
	 * Adiciona um atributo X.500 ao DistinguishedName do titular
	 * @param { String } type	Representação string do OID desejado. Deve ser um dos valores definidos na RFC 2253
	 * @param { String } value	Valor do atributo
	 * @returns { CertificationRequestInfoBuilder } Instância corrente do builder
	 */
	addName(type, value) {
		let oid;
		if (typeof type !== 'string' || !(oid = x500AttributeTypes.get(type.toUpperCase())))
			throw new APIError('CertificationRequestInfoBuilder', 'Argument type must be a valid X.500 DN attribute', 'addName');
		if (typeof value !== 'string')
			throw new APIError('CertificationRequestInfoBuilder', 'Argument value must be a string', 'addName');

		this.subject.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: oid }),
					new asn1js.Utf8String({ value: value })
				]})
			]})
		);
		return this;
	}

	/**
	 * Adiciona um atributo X.500 aos CRIAttributes da requisição
	 * @param { String } type	Representação string do OID desejado. Somente os atributos friendlyName, emailAddress e challengePassword, definidos na RFC 2985, são suportados.
	 * @param { String } value	Valor do atributo
	 * @returns { CertificationRequestInfoBuilder } Instância corrente do builder
	 */
	addAttribute(type, value) {
		let oid;
		if (typeof type !== 'string' || !(oid = pkcs9Attributes.get(type.toUpperCase())))
			throw new APIError('CertificationRequestInfoBuilder', 'Argument type must be a valid PKCS #9 attribute', 'addAttribute');
		if (typeof value !== 'string')
			throw new APIError('CertificationRequestInfoBuilder', 'Argument value must be a string', 'addAttribute');

		this.attributes.valueBlock.value.push(
			new asn1js.Sequence({ value: [
				new asn1js.ObjectIdentifier({ value: oid }),
				new asn1js.Set({ value: [
					new asn1js.Utf8String({ value: value })
				]})
			]})
		);
		return this;
	}

	/**
	 * Informações sobre a chave pública gerada
	 * @param { Uint8Array } rawPubKey	Codificação DER da chave pública gerada
	 * @returns { CertificationRequestInfoBuilder } Instância corrente do builder
	 */
	setPublicKey(rawPubKey) {
		if (!(rawPubKey instanceof Uint8Array))
			throw new APIError('CertificationRequestInfoBuilder', 'Argument rawPubKey must be of type Uint8Array', 'setPublicKey');
		let decoded = asn1js.fromBER(keyPair.pubKey.buffer);
		if (decoded.offset == -1 || !(decoded.result instanceof asn1js.Sequence))
			new APIError('CertificationRequestInfoBuilder', 'Argument rawPubKey must be of ASN.1 SEQUENCE type', 'setPublicKey');

		this.subjectPKInfo.valueBlock.value.push(decoded.result.valueBlock.value[0]);
		this.subjectPKInfo.valueBlock.value.push(decoded.result.valueBlock.value[1]);
		return this;
	}

	/**
	 * Constrói o objeto CertificationRequestInfo
	 * @returns { asn1js.Sequence } Requisição a ser assinada
	 */
	build() {
		return new asn1js.Sequence({ value: [
			this.version,
			this.subject,
			this.subjectPKInfo,
			this.attributes 
		]});
	}
}

/**
 * Implementa um PKCS #10 tal como especificado na RFC 2986
 */
class CertificationRequest {

	/**
	 * Instância um novo PKCS #10 para a emissão de um certificado
	 * @param { asn1js.Sequence } csrInfo	Objeto retornado pelo CertificationRequestInfoBuilder
	 */
	constructor(csrInfo) {
		if (!(csrInfo instanceof asn1js.Sequence))
			throw new APIError ('CertificationRequest', 'Argument csrInfo must be an instance of asn1js.Sequence', 'constructor');
		this.certificationRequestInfo = csrInfo;
		this.signatureAlgorithm = new asn1js.Sequence({ value: [] });
		this.signature = new asn1js.BitString({ valueHex: null });
		this.addon = new Enroll();
		this.signed = false;
	}

	/**
	 * Assina o objeto CertificationRequestInfo
	 * @param { Number } privKeyHandle	Handle para a chave privada (@see Hamahiri.KeyPair )
	 * @param { Number } signAlg		Algoritmo de assinatura. Deve ser uma das constantes definidas por @link Hamahiri.SignMechanism
	 */
	signRequest(privKeyHandle, signAlg) {
		if (isNaN(privKeyHandle))
			throw new APIError ('CertificationRequest', 'Argument privKeyHandle must be a number', 'signRequest');
		if (isNaN(signAlg))
			throw new APIError('CertificationRequest', 'Argument signAlg must be a number', 'signRequest');
		let hashAlg;
		let signOID;
		switch (signAlg) {
		case SignMechanism.CKM_SHA1_RSA_PKCS:
			hashAlg = 'sha1';
			signOID = AlgorithmOID.sha1WithRSAEncryption;
			break;
		case SignMechanism.CKM_SHA256_RSA_PKCS:
			hashAlg = 'sha256';
			signOID = AlgorithmOID.sha256WithRSAEncryption;
			break;
		case SignMechanism.CKM_SHA384_RSA_PKCS:
			hashAlg = 'sha384';
			signOID = AlgorithmOID.sha384WithRSAEncryption;
			break;
		case SignMechanism.CKM_SHA512_RSA_PKCS:
			hashAlg = 'sha512';
			signOID = AlgorithmOID.sha512WithRSAEncryption;
			break;
		default: throw new APIError('CertificationRequest', 'Argument signAlg must be a supported signature algorithm', 'signRequest');
		}

		let toBeSigned = Buffer.from(this.certificationRequestInfo.toBER(false));
		if (this.certificationRequestInfo.error !== '' && toBeSigned.length == 0)
			throw new APIError('CertificationRequest', this.certificationRequestInfo.error, 'signRequest');
		let hash = crypto.createHash(hashAlg);
		hash.update(toBeSigned);
		let signature;
		try { signature = this.addon.signRequest(hash.digest(), signAlg, privKeyHandle); }
		catch (err) { throw new APIError('CertificationRequest', 'CSR signature failed', 'signRequest', 0, err); }
		this.signatureAlgorithm.valueBlock.value.push(new asn1js.ObjectIdentifier({ value: signOID }));
		this.signatureAlgorithm.valueBlock.value.push(new asn1js.Null());
		this.signature.valueBlock.valueHex = signature.buffer;
		this.signed = true;
	}

	/**
	 * Codifica em DER o objeto assinado
	 * @returns { Uint8Array } Codificação DER da requisição de certificado
	 */
	derEncode() {
		if (!this.signed) throw new APIError('CertificationRequest', 'Request must be signed first', 'encode');
		let request = new asn1js.Sequence({ value: [ this.certificationRequestInfo, this.signatureAlgorithm, this.signature ] });
		let encoded = new Uint8Array(request.toBER(false));
		if (request.error != '' && encoded.length == 0)
			throw new APIError('CertificationRequest', request.error, 'encode');
		return encoded;
	}

	/**
	 * Codifica em PEM o objeto assinado
	 * @returns { String } Codificação DER convertida para Base64 no formato PEM
	 */
	pemEncode() {
		let encoded = this.derEncode();
		return '-----BEGIN CERTIFICATE REQUEST-----\r\n' + Base64Conveter.btoa(encoded, true) + '\r\n-----END CERTIFICATE REQUEST-----';
	}
}

module.exports = {
	CertificationRequestInfoBuilder:	CertificationRequestInfoBuilder,
	CertificationRequest:				CertificationRequest
};