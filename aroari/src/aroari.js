/**
 * @file Módulo criptográfico de alto nível (implementa a RFC 2986 e a seção 5 da RFC 5652)
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';

const Hamahiri = require('../../hamahiri/lib/hamahiri');
const asn1js = require('asn1js');
const crypto = require('crypto');


/**
 * Objetos globais
 * @namespace Xapiripe
 */
/**
 * Referência um certificado digital
 * @class Certificate
 * @memberof Xapiripe
 * @property { string } subject - Titular do certificado
 * @property { string } issuer  - Emissor do certificado
 * @property { string } serial  - Número de série do certificado, onde os bytes são representados em hexadecimal
 * @property { Number } handle  - Handle para acesso à chave privada associada ao certificado
 */


/**
 * Referências ao módulo nativo
 * @namespace Hamahiri
 */
/**
 * Detalhamento dos erros ocorridos no processamento nativo
 * @class Failure
 * @extends Error
 * @memberof Hamahiri
 * @property { string } component - Componente que disparou o erro
 * @property { string } method    - Método ou função que disparou o erro
 * @property { Number } errorCode - Código Xapiripë do erro
 * @property { Number } apiError  - Código do erro gerado pela API de terceiros (por exemplo, a Windows CryptoAPI)
 */

/**
 * Módulo criptográfico de alto nível
 * @namespace Aroari
 */

/**
 * Detalhamento dos erros ocorridos no processamento do componente
 * @extends Error
 * @memberof Aroari
 * @property { string } component - Componente que disparou o erro
 * @property { string } method    - Método ou função que disparou o erro
 * @property { Number } errorCode - Código do erro
 * @property { Object } native    - Erro gerado no processamento nativo, se for o caso. Ver {@link Hamahiri.Failure}
 */
 class APIError extends Error
{
	/**
	 * Falha na enumeração de dispositivos criptográficos
	 * @member { Number }
	 * @default 64
	 */
	static ENUM_DEVICES_ERROR = 64;

	/**
	 * Argumento inválido
	 * @member { Number }
	 * @default 65
	 */
	static ARGUMENT_ERROR = 65;

	/**
	 * Falha na enumeração de certificados de assinatura
	 * @member { Number }
	 * @default 66
	 */
	static ENUM_CERTIFICATES_ERROR = 66;

	/**
	 * Falha na geração do par de chaves RSA
	 * @member { Number }
	 * @default 67
	 */
	static GENERATE_KEY_PAIR_ERROR = 67;

	/**
	 * Falha na decodificação DER da chave pública
	 * @member { Number }
	 * @default 68
	 */
	static DER_ENCODE_PUBKEY_ERROR = 68

	/**
	 * Falha na codificação DER da requisição de certificado
	 * @member { Number }
	 * @default 69
	 */
	static DER_ENCODE_REQUEST_INFO_ERROR = 69;

	/**
	 * Algoritmo de assinatura não suportado
	 * @member { Number }
	 * @default 70
	 */
	static UNSUPPORTED_ALGORITHM_ERROR = 70;

	/**
	 * Falha ao assinar a requisição de certificado
	 * @member { Number }
	 * @default 71
	 */
	static REQUEST_SIGN_ERROR = 71;

	/**
	 * Falha an codificar a requisição de certificado em DER
	 * @member { Number }
	 * @default = 72
	 */
	static DER_ENCODE_REQUEST_ERROR = 72;

	/**
	 * Falha ao codificar em DER a requisição de certificado
	 * @member { Number }
	 * @default 73
	 */
	static DER_DECODE_CMS_ERROR = 73;

	/**
	 * CMS ContentInfo inválido
	 * @member { Number }
	 * @default 74
	 */
	static INVALID_CONTENT_INFO_ERROR = 74;

	/**
	 * CMS SignedData inválido
	 * @member { Number }
	 * @default 75
	 */
	static INVALID_SIGNED_DATA_ERROR = 75;

	/**
	 * Falha na verificação criptográfica da cadeia de certificados
	 * @member { Number }
	 * @default 76
	 */
	static CERTIFICATE_CHAIN_VERIFY_ERROR = 76;

	/**
	 * Falha na instalação do certificado do assinante
	 * @member { Number }
	 * @default 77
	 */
	static INSTALL_SIGNER_CERT_ERROR = 77;

	/**
	 * Falha na instalação da cadeia de ACs
	 * @member { Number }
	 * @default 78
	 */
	static INSTALL_CA_CHAIN_ERROR = 78;

	/**
	 * Impossível instalar novamente o certificado do assinante
	 * @member { Number }
	 * @default 79
	 */
	static SIGNER_CERT_ALREADY_INSTALLED_ERROR = 79;

	/**
	 * Padrão de assinatura não suportado
	 * @member { Number }
	 * @default 80
	 */
	static UNSUPPORTED_CADES_SIGNATURE = 80;

	/**
	 * Tipo de compromisso CAdES desconhecido
	 * @member { Number }
	 * @default 81
	 */
	static UNSUPPORTED_COMMITMENT_TYPE = 81;

	/**
	 * Falha ao codificar os atributos assinados em DER
	 * @member { Number }
	 * @default 82
	 */
	static DER_ENCODE_SIGNED_ATTR_ERROR = 82;

	/**
	 * Falha ao obter a cadeia de certificados do assinante
	 * @member { Number }
	 * @default 83
	 */
	static GET_CHAIN_ERROR = 83;

	/**
	 * Falha ao assinar os atributos assinados do documento CMS
	 * @member { Number }
	 * @defaualt 84
	 */
	static SIGNED_ATTRS_SIGN_ERROR = 84;

	/**
	 * Falha geral na decodificação de um certificado
	 * @member { Number }
	 * @default 85
	 */
	static CERTIFICATE_DECODE_ERROR = 85;

	/**
	 * Falha geral ao codificar o documento CMS em DER
	 * @member { Number }
	 * @default 86
	 */
	static DER_ENCODE_CMS_ERROR = 86;

	constructor(msg, method, errorCode, native)
	{
		super(msg);
		this.component = 'Aroari';
		this.method = method;
		this.errorCode = errorCode;
		this.native = native ? native : null;
	}
}

/**
 * Nome distinto X.500 para a caracterização do titular do certificado a ser utilizado
 * @class X500Name
 * @memberof Aroari
 * @property { String } c  - País da AC (country). Opcional
 * @property { String } o  - Organização da Autoridade Certificadora (organization). Opcional
 * @property { String } ou - Unidade organizacional da Autoridade Certificadora (organization unit). Opcional
 * @property { String } cn - Nome comum do titular do certificado (common name). Obrigatório
 */

/**
 * Opções para a geração de request de certificados.
 * @class EnrollOptions
 * @memberof Aroari
 * @property { String } device  - Cryptographic Service Provider ou Key Storage Provider que a ser utilizado para gerar
 * as chaves RSA. Deve corresponder exatamente a um dos dispositivos retornados por
 * {@link Aroari.enumerateDevices}
 * @property { Number } keySize - Tamanho (em bits) das chaves RSA a serem geradas. Opcional. Default: 2048
 * @property { Number } signAlg - Algoritmo a ser utilizado na assinatura da requisição de certificado. Opcional.
 * Default: SignMechanism.CKM_SHA256_RSA_PKCS
 * @property { Object } rdn     - Nome distinto do titular do certificado, conforme {@link Aroari.X500Name}. Obrigatório
 */

/**
 * Políticas de assinatura, conforme RFC 5126. Atenção: somente a política CAdES-BES é presentemente suportada.
 * @memberof Aroari
 */
class Policy
{
	/**
	 * CAdES Basic Electronic Signature
	 * @member { String }
	 * @default CAdES-BES
	 */
	static typeBES = 'CAdES-BES';

	/**
	 *  CAdES Explicit Policy-based Electronic Signatures
	 * @member { String }
	 * @default CAdES-EPES
	 */
	static typeEPES = 'CAdES-EPES';

	/**
	 * Electronic Signature with Time
	 * @member { String }
	 * @default 'CAdES-T
	 */
	static typeT = 'CAdES-T'

	/**
	 * ES with Complete Validation Data Reference
	 * @member { String }
	 * @default CAdES-C
	 */
	static typeC = 'CAdES-C';

	/**
	 * EXtended Long Electronic Signature
	 * @member { String }
	 * @default CAdES-X Long
	 */
	static typeX = 'CAdES-X Long';

	/**
	 * EXtended Electronic Signature with Time Type 1
	 * @member { String }
	 * @default CAdES-X Type 1
	 */
	static type1 = 'CAdES-X Type 1';

	/**
	 * EXtended Electronic Signature with Time Type 2
	 * @member { String }
	 * @default CAdES-X Type 2
	 */
	static type2 = 'CAdES-X Type 2';

	/**
	 * Xtended Long Electronic Signature with Time Type 1
	 * @member { String }
	 * @default CAdES-X Long Type 1
	 */
	static typeX1 = 'CAdES-X Long Type 1';

	/**
	 * Xtended Long Electronic Signature with Time Type 2
	 * @member { String }
	 * @default CAdES-X Long Type 2
	 */
	static typeX2 = 'CAdES-X Long Type 2';

	/**
	 * Archival Electronic Signature
	 * @member { String }
	 * @default CAdES-A
	 */
	static typeA = 'CAdES-A';
}

/**
 * Identificador dos algoritmos criptográficos
 * @memberof Aroari
 */
class AlgorithmOID
{
	/**
	 * Assinatura RSA sobre hash SHA-1
	 * @member { String }
	 * @default 1.2.840.113549.1.1.5
	 */
	static sha1WithRSAEncryption = '1.2.840.113549.1.1.5';

	/**
	 * Assinatura RSA sobre hash SHA-256
	 * @member { String }
	 * @default 1.2.840.113549.1.1.11
	 */
	static sha256WithRSAEncryption = '1.2.840.113549.1.1.11';

	/**
	 * Assinatura RSA sobre hash SHA-384
	 * @member { String }
	 * @default 1.2.840.113549.1.1.12
	 */
	static sha384WithRSAEncryption = '1.2.840.113549.1.1.12';

	/**
	 * Assinatura RSA sobre hash SHA-512
	 * @member { String }
	 * @default 1.2.840.113549.1.1.13
	 */
	static sha512WithRSAEncryption = '1.2.840.113549.1.1.13';

	/**
	 * Hash SHA-1
	 * @member { String }
	 * @default 1.3.14.3.2.26
	 */
	static sha1 = '1.3.14.3.2.26';

	/**
	 * Hash SHA-256
	 * @member { String }
	 * @default 2.16.840.1.101.3.4.2.1
	 */
	static sha256 = '2.16.840.1.101.3.4.2.1';

	/**
	 * Hash SHA-384
	 * @member { String }
	 * @default 2.16.840.1.101.3.4.2.2
	 */
	static sha384 = '2.16.840.1.101.3.4.2.2';

	/**
	 * Hash SHA-512
	 * @member { String }
	 * @default 2.16.840.1.101.3.4.2.3
	 */
	static sha512 = '2.16.840.1.101.3.4.2.3';
}

const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const equals = "=".charCodeAt(0);
const dash = "-".charCodeAt(0);
const decodings = [
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
 ];
const equals_value	= -2;
const dash_value 	= -3;
decodings[equals]	= equals_value;
decodings[dash] 	= dash_value;
const pre = 0;
const content_1 = 1;
const content_2 = 2;
const content_3 = 3;
const content_4 = 4;
/**
 * Utilitário para conversão de e para Base64
 * @memberof Aroari
 */
class Base64
{
	/**
	 * Converte um array de bytes para Base64
	 * @param { Uint8Array } bytes Cadeia de bytes a ser convertida
	 * @param { Boolean } breakLines Se true, a linha é quebrada na coluna 64. Opcional. Valor default: false
	 * @returns { String } Argumento convertido para Base64
	 */
	static btoa(bytes, breakLines)
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
		let ret = base64;
		if (breakLines)
		{
			let pem = [];
			let start = 0;
			while (start < base64.length)
			{
				pem.push(base64.slice(start, start + 64));
				start += 64;
			}
			ret = pem.join('\r\n');
		}
		return ret;
	}

	/**
	 * Converte o argumento de Baser64 para um array de bytes
	 * @throws { Error } Dispara uma exceção caso a string não seja válida em Base64
	 * @param { String } base64 Array de bytes codificado em Base64
	 * @returns { Uint8Array } Array de bytes convertido
	 */
	static atob(base64)
	{
		var charlen = base64.length;
		var byteoff = 0;
		var byteLength = Math.round(((charlen) / 4 * 3)+1);
		var bytes = new Uint8Array(byteLength)
		var chunk = 0;
		var i = 0;
		var code;
		code = decodings[base64.charCodeAt(i)];
		if (code == dash_value)
		{
			while (code == dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			if (i!=0)
			{
				while(code != dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
				while(code == dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
			}
		}
		while(code<0 && code != dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
		if(code == dash_value || i >= charlen) throw new Error("A codificação recebida como base64 é inválida");
		var stage = pre; 
		while(i < charlen && code != dash_value) {
			while(i < charlen && stage != content_4 && code != dash_value)
			{
				stage++;
				switch(stage)
				{
					case content_1:
						chunk = code << 18;
						break;
					case content_2:
						chunk |= code << 12;
						break;
					case content_3:
						chunk |= code << 6;
						break;
					case content_4:
						chunk |= code;
						break;
				}
				code = decodings[base64.charCodeAt(++i)];
				while(code < 0 && code != dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			}
			switch(stage)
			{
				case content_1: throw new Error("A codificação recebida como base64 é inválida");
				case content_4:	bytes[byteoff + 2] = chunk &  255;
				case content_3:	bytes[byteoff + 1] = chunk >> 8;
				case content_2:	bytes[byteoff    ] = chunk >> 16;
			}
			byteoff += stage-1;
			stage = pre;
		}
		return bytes.subarray(0,byteoff);
	}
}

/**
 * Implementa a parte cliente da emissão de um certificado digital
 * @memberof Aroari
 */
class Enroll
{
	constructor() { this.addon = new Hamahiri.Enroll(); }

	/**
	 * Enumera os dispositivos criptográficos presentes (Cryptographic Services Providers para RSA)
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIError} em caso de falha
	 * @returns { Array } Lista de strings contendo os nomes dos dispositivos presentes
	 */
	enumerateDevices() {
		let ret = null;
		try { ret = this.addon.enumerateDevices(); }
		catch (err) { throw new APIError('Erro ao enumerar os dispositivos criptográficos', 'enumerateDevices', APIError.ENUM_DEVICES_ERROR, err); }
		return ret;
	}

	/**
	 * Gera um par de chaves RSA e assina uma requisição de certificado digital.
	 * @param   { Object   } options Parâmetros para operação conforme {@link Aroari.EnrollOptions}
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha
	 * @returns { String   } Requisição PKCS #10 codificada em Base64 de acordo com a convenção PEM
	 */
	generateCSR(options) {
		if (!options) throw new APIError('Argumento EnrollOptions obrigatório', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.device  == 'undefined' || !isNaN(options.device)) throw new APIError('Argumento EnrollOptions.device obrigatório', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.keySize != 'undefined' && isNaN(options.keySize)) throw new APIError('Argumento EnrollOptions.keySize, se presente, deve ser numérico', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.signAlg != 'undefined' && isNaN(options.signAlg)) throw new APIError('Argumento EnrollOptions.signAlg, se presente, deve ser numérico', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.rdn == 'undefined' || typeof options.rdn.cn == 'undefined') throw new APIError('Argumento EnrollOptions.rdn deve, obrigatoriamente, incluir pelo menos a propriedade cn', 'generateCSR', APIError.ARGUMENT_ERROR);

		let signAlg = typeof options.signAlg != 'undefined' ? options.signAlg : Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS;
		let hashAlg;
		let signOID;
		switch (signAlg)
		{
		case Hamahiri.SignMechanism.CKM_SHA1_RSA_PKCS:
			hashAlg = 'sha1';
			signOID = AlgorithmOID.sha1WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS:
			hashAlg = 'sha256'
			signOID = AlgorithmOID.sha256WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA384_RSA_PKCS:
			hashAlg = 'sha384';
			signOID = AlgorithmOID.sha384WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA512_RSA_PKCS:
			hashAlg = 'sha512';
			signOID = AlgorithmOID.sha512WithRSAEncryption;
			break;
		default: throw new APIError('Algoritmo de assinatura não suportado', 'generateCSR', APIError.UNSUPPORTED_ALGORITHM_ERROR);
		}

		let keySize = typeof options.keySize != 'undefined' ? options.keySize : 2048;
		let keyPair;
		try { keyPair = this.addon.generateKeyPair(options.device, keySize); }
		catch (err) { throw new APIError('Falha na geração do par de chaves RSA', 'generateCSR', APIError.GENERATE_KEY_PAIR_ERROR, err); }
		let decoded = asn1js.fromBER(keyPair.pubKey.buffer);
		if (decoded.offset == -1)
		{
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError('Falha na decodificação DER da chave púbica gerada', 'generateCSR', APIError.DER_ENCODE_PUBKEY_ERROR);
		}
		let pubKey = decoded.result;

		let ver = new asn1js.Integer({ value: 1 });
		let name = new asn1js.Sequence({ value: [] });
		if (options.rdn.c) name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.6'}),
					new asn1js.Utf8String({ value: options.rdn.c })
				]})
			]}));
		if (options.rdn.o) name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.10'}),
					new asn1js.Utf8String({ value: options.rdn.o })
				]})
			]}));
		if (options.rdn.ou) name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.11'}),
					new asn1js.Utf8String({ value: options.rdn.ou })
				]})
			]}));
		name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '2.5.4.3'}),
					new asn1js.Utf8String({ value: options.rdn.cn })
				]})
			]}));
		let pubKeyInfo = new asn1js.Sequence({ value: [
			pubKey.valueBlock.value[0],
			pubKey.valueBlock.value[1]
		]});
		let attrs = new asn1js.Constructed({ 
			idBlock: { tagClass: 3, tagNumber: 0 },
			value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: signOID }),
					new asn1js.Set({ value: [
						new asn1js.Utf8String({ value: options.rdn.cn })
					]})
				]})
			]
		});
		let certificateRequestInfo = new asn1js.Sequence({ value: [ ver, name, pubKeyInfo, attrs ]});
		let toBeSigned = Buffer.from(certificateRequestInfo.toBER(false));
		if (certificateRequestInfo.error != '' && toBeSigned.length == 0)
		{
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError(certificateRequestInfo.error, 'generateCSR', DER_ENCODE_REQUEST_INFO_ERROR);
		}
		let hash = crypto.createHash(hashAlg);
		hash.update(toBeSigned);
		let signature;
		try { signature = this.addon.sign(hash.digest(), signAlg, keyPair.privKey); }
		catch (err)
		{
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError('Falha ao assinar a requisição de certificado', 'generateCSR', APIError.REQUEST_SIGN_ERROR, err);
		}

		let request = new asn1js.Sequence({ value: [
			certificateRequestInfo,
			new asn1js.Sequence({ value: [
				new asn1js.ObjectIdentifier({ value: signOID }),
				new asn1js.Null()
			]}),
			new asn1js.BitString({ valueHex: signature.buffer })
		] });
		let csr = new Uint8Array(request.toBER(false));
		if (request.error != '' && csr.length == 0)
		{
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError(request.error, 'generateCSR', DER_ENCODE_REQUEST_ERROR);
		}
		this.addon.releaseKeyHandle(keyPair.privKey);
		return '-----BEGIN CERTIFICATE REQUEST-----\n' + Base64.btoa(csr, true) + '\n-----END CERTIFICATE REQUEST-----';
	}

	/**
	 * Instala o certificado assinado e sua cadeia. O certificado de usuário final somente é instalado se for
	 * encontrada uma chave privada associada à sua chave pública no repositório do Windows. Toda a cadeia de
	 * certificados é criptograficamente verificada antes de sua instalação, sendo requerido o certificado
	 * de uma AC raiz.
	 * @param   { String   } pkcs7 Documento PKCS #7 codificado em Base64 de acordo com a convenção PEM, emitido pela 
	 * AC para transporte do certificado do titular e a cadeia de Autoridades Certificadoras associada.
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns { Boolean  } Retorna true se toda a cadeia de certificados de AC for instalada; caso um dos certificados
	 * de AC já esteja presente no repositório do Windows, retorna false.
	 */
	installCertificates(pkcs7) {
		if (!pkcs7) throw new APIError('Argumento pkcs7 é obrigatório', 'installCertificates', APIError.ARGUMENT_ERROR);
		let decoded = asn1js.fromBER(pkcs7.buffer);
		if (decoded.offset == -1) throw new APIError('Falha ao decodificar de DER o documento PKCS #7', 'installCertificates', APIError.DER_DECODE_CMS_ERROR);
		let contentInfo = decoded.result;
		if 
		(!(
			contentInfo instanceof asn1js.Sequence &&
			contentInfo.valueBlock.value[0] instanceof asn1js.ObjectIdentifier &&
			contentInfo.valueBlock.value[0].valueBlock.toString() === '1.2.840.113549.1.7.2'
		))	throw new APIError('CMS ContentInfo inesperado para um PKCS #7', 'installCertificates', APIError.INVALID_CONTENT_INFO_ERROR);
		let signedData = contentInfo.valueBlock.value[1].valueBlock.value[0];
		if
		(!(
			signedData instanceof asn1js.Sequence &&
			signedData.valueBlock.value.length >= 4
		))	throw new APIError('Documento CMS SignedData inválido', 'installCertificates', APIError.INVALID_SIGNED_DATA_ERROR);
		
		let certificates = signedData.valueBlock.value[3];
		let i = 0;
		while (i < certificates.valueBlock.value.length)
		{
			let subject = certificates.valueBlock.value[i];
			let issuer = (i + 1 < certificates.valueBlock.value.length) ? certificates.valueBlock.value[i + 1] : subject;
			let certSubject = new crypto.X509Certificate(Buffer.from(subject.valueBeforeDecode));
			let certIssuer = new crypto.X509Certificate(Buffer.from(issuer.valueBeforeDecode));
			if (!certSubject.verify(certIssuer.publicKey)) throw new APIError('Assinatura de um emissor inválida na cadeia de certificados', 'installCertificates', APIError.CERTIFICATE_CHAIN_VERIFY_ERROR);
			i++;
		}

		let signer = certificates.valueBlock.value[0].valueBeforeDecode;
		let done;
		try { done = this.addon.installCertificate(new Uint8Array(signer)); }
		catch (err) { throw new APIError('Falha na instalação do certificado do assinante', 'installCertificates', APIError.INSTALL_SIGNER_CERT_ERROR, err); }
		if (!done) throw new APIError('Certificado do assinante já instalado', 'installCertificates', APIError.SIGNER_CERT_ALREADY_INSTALLED_ERROR);
		i = 1;
		let chain = [];
		while (i < certificates.valueBlock.value.length) chain.push(new Uint8Array(certificates.valueBlock.value[i++].valueBeforeDecode));
		try { done = this.addon.installChain(chain); }
		catch (err) { throw new APIError('Falha na instalação da cadeia de certificados de AC', 'installCertificates', APIError.INSTALL_CA_CHAIN_ERROR, err); }
		return done;
	}
}

/**
 * Tipos de compromisso da assinatura CAdES
 * @memberof Aroari
 */
 class CommitmentType
 {
	 /**
	  * Indica que o assinante reconhece a criação, a aprovação e o envio do documento assinado
	  * @member { String }
	  * @default 1.2.840.113549.1.9.16.6.1
	  */
	 static proofOfOrigin = '1.2.840.113549.1.9.16.6.1';
 
	 /**
	  * Indica que o assinante recebeu o conteúdo assinado
	  * @member { String }
	  * @default 1.2.840.113549.1.9.16.6.2
	  */
	 static proofOfReceipt = '1.2.840.113549.1.9.16.6.2';
 
	 /**
	  * Indica que um Trusted Service Provider sinalizou ao destinatário a entrega do conteúdo assinado
	  * @member { String }
	  * @default 1.2.840.113549.1.9.16.6.3
	  */
	 static proofOfDelivery = '1.2.840.113549.1.9.16.6.3';
 
	 /**
	  * Indica que o assinante enviou o conteúdo, mas não necessariamente o criou
	  * @member { String }
	  * @default 1.2.840.113549.1.9.16.6.4
	  */
	 static proofOfSender = '1.2.840.113549.1.9.16.6.4';
 
	 /**
	  * Indica que o assinante aprova o conteúdo assinado
	  * @member { String }
	  * @default 1.2.840.113549.1.9.16.6.5
	  */
	 static proofOfApproval = '1.2.840.113549.1.9.16.6.5';
 
	 /**
	  * Indica que o assinante criou o conteúdo, mas não necessariamente o enviou ou aprovou
	  * @member { String }
	  * @default 1.2.840.113549.1.9.16.6.6
	  */
	 static proofOfCreation = '1.2.840.113549.1.9.16.6.6';
 }
 
/**
 * Opções CAdES da assinatura. Atributos assinados obrigatórios: Content Type, Message Digest e ESS signing-certificate-v2
 * @class CAdES
 * @memberof Aroari
 * @property { String  } policy Padrão de assinatura escolhido conforme a RFC 5126. Opcional. Valor default: CAdES-BES
 * @property { Boolean } addSigningTime Incluir atributo assinado Signing Time. Opcional. Valor default: true
 * @property { String } commitmentType Se contiver um valor descritivo, inclui o OID do atributo assinado Commitment
 * Type Indication conforme {@link Aroari.CommitmentType}. Opcional. Valor default: CommitmentType.proofOfSender.
 */

/**
 * Opções para a operação de assinatura de documentos e transações
 * @class SignOptions
 * @memberof Aroari
 * @property { Number } handle Handle para o certificado, retornado por {@link Xapiripe.Certificate}
 * @property { String | ArrayBuffer } toBeSigned Documento ou transação a ser assinada
 * @property { Boolean } attach Indica se o documento toBeSigned deve ser anexado ao envelope CMS Signed Data. Opcional.
 * Valor default: true
 * @property { Number } algorithm Constante indicativa do algoritmo de assinatura a ser utilizado.
 * Valor default: SignMechanism.CKM_SHA256_RSA_PKCS
 * @property { Object } cades Oções CAdES da assinatura conforme {@link Aroari.CAdES}. Opcional
 */

/**
 * Representação ASN.1 de um certificado digital
 * @memberof Aroari
 */
 class X509Certificate
 {
	 constructor(encoded)
	 {
		 let decoded = asn1js.fromBER(encoded.buffer);
		 if (decoded.offset == -1) throw new APIError('Falha geral em efetuar o parsing do certificado', 'new X509Certificate()', APIError.CERTIFICATE_DECODE_ERROR);
		 this.root = decoded.result;
		 if (!this.root.valueBlock.value[0]) throw new APIError('Codificação DER inválida para um certificado digital', 'new X509Certificate()', APIError.CERTIFICATE_DECODE_ERROR);
		 this.tbs = this.root.valueBlock.value[0];
	 }
	 getIssuer() {
		 let issuer = this.tbs.valueBlock.value[3];
		 if (!(issuer instanceof asn1js.Sequence)) throw new APIError('Codificação DER inválida do campo Issuer', 'new X509Certificate()', APIError.CERTIFICATE_DECODE_ERROR);
		 return issuer;
	 }
	 getSerial() {
		let serial = this.tbs.valueBlock.value[1];
		if (!(serial instanceof asn1js.Integer)) throw new APIError('Codificação DER inválida do campo CertificateSerialNumber', 'new X509Certificate()', APIError.CERTIFICATE_DECODE_ERROR);
		return serial;

	 }
 }
 
/**
 * Implementa as funções de assinatura digital utilizando chaves RSA
 * @memberof Aroari
 */
class Sign
{
	constructor() { this.addon = new Hamahiri.Sign(); }

	/**
	 * Enumera os certificados em vigor que estejam associados a chaves privadas RSA nos repositórios criptográficos
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns { Array } Um array de objetos {@link Xapiripe.Certificate}
	 */
	enumerateCertificates() {
		let ret = null;
		try { ret = this.addon.enumerateCertificates(); }
		catch (err) { throw new APIError('Erro ao enumerar os certificados de assinatura presentes', 'enumerateCertificates', APIError.ENUM_CERTIFICATES_ERROR, err); }
		return ret;
	}

	/**
	 * Assina digitalmente um documento ou transação
	 * @param { Object } options Opções para a assinatura digital, conforme {@link Aroari.SignOptions}
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns { String } Envelope CMS Signed Data, conforme a RFC 5652, codificado em Base64 de acordo com a convenção PEM
	 */
	sign(options) {
		if (!options) throw new APIError('Argumento SignOptions obrigatório', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.handle == 'undefined' || isNaN(options.handle)) throw new APIError('Argumento SignOptions.handle deve ser obrigatoriamente numérico', 'sign', APIError.ARGUMENT_ERROR);
		if (!(typeof options.toBeSigned != 'undefined' && (typeof options.toBeSigned == 'string' || options.toBeSigned instanceof ArrayBuffer))) throw new APIError('Argumento SignOptions.toBeSigned must be an string or an instance of ArrayBuffer', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.attach != 'undefined' && typeof options.attach != 'boolean') throw new APIError('Argumento SignOptions.attach, se presente, deve ser um valor lógico', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.algorithm != 'undefined' && isNaN(options.algorithm)) throw new APIError('Argumento SignOptions.algorithm, se presente, deve ser numérico', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.cades != 'undefined')
		{
			if (typeof options.cades != 'object') throw new APIError('Argumento options.cades, se presente, deve ser um objeto do tipo Aroari.CAdES', 'sign', APIError.ARGUMENT_ERROR);
			if (typeof options.cades.policy != 'undefined')
			{
				if (typeof options.cades.policy != 'string') throw new APIError('Argumento options.cades.policy, se presente, deve ser do tipo string', 'sign', APIError.ARGUMENT_ERROR);
				if (options.cades.policy.localCompare(Policy.typeBES) != 0) throw new APIError('Padrão de assinatura CAdES não suportado', 'sign', APIError.UNSUPPORTED_CADES_SIGNATURE);
			}
			if (typeof options.cades.addSigningTime != 'undefined' && typeof options.cades.addSigningTime != 'boolean') throw new APIError('Argumento options.cades.addSigningTime, se presente, deve ser do tipo boolean', 'sign', APIError.ARGUMENT_ERROR);
			if (typeof options.cades.commitmentType != 'undefined')
			{
				if (typeof options.cades.commitmentType != 'string') throw new APIError('Argumento options.cades.commitmentType, se presente, deve ser do tipo string', 'sign', APIError.ARGUMENT_ERROR);
				if
				(
					options.cades.commitmentType != CommitmentType.proofOfOrigin &&
					options.cades.commitmentType != CommitmentType.proofOfReceipt &&
					options.cades.commitmentType != CommitmentType.proofOfDelivery &&
					options.cades.commitmentType != CommitmentType.proofOfSender &&
					options.cades.commitmentType != CommitmentType.proofOfApproval &&
					options.cades.commitmentType != CommitmentType.proofOfCreation
				)	throw new APIError('Tipo de compromisso com a assinatura não conhecido', 'sign', APIError.UNSUPPORTED_COMMITMENT_TYPE);
			}
		}

		let hHandle = options.handle;
		let chain;
		try { chain = this.addon.getCertificateChain(hHandle); }
		catch (err) { throw new APIError('Falha ao obter a cadeia de certificados do assinante', 'sign', APIError.GET_CHAIN_ERROR, err);}
		let toBeSigned = typeof options.toBeSigned == 'string' ? new TextEncoder().encode(options.toBeSigned) : new Uint8Array(options.toBeSigned);
		let attach = typeof options.attach != 'undefined' ? options.attach : true;
		let signAlg = typeof options.algorithm != 'undefined' ? options.algorithm : Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS;
		let policy = typeof options.cades != 'undefined' && typeof options.cades.policy != 'undefined' ? options.cades.policy : Policy.typeBES;
		let addSigningTime = typeof options.cades != 'undefined' && typeof options.cades.addSigningTime != 'undefined' ? options.cades.addSigningTime : true;
		let commitmentType = typeof options.cades != 'undefined' && typeof options.cades.commitmentType != 'undefined' ? options.cades.commitmentType : CommitmentType.proofOfSender;
		let hashAlg;
		let hashAlgOID;
		let signAlgOID;
		switch (signAlg)
		{
		case Hamahiri.SignMechanism.CKM_SHA1_RSA_PKCS:
			hashAlg = 'sha1'
			hashAlgOID = AlgorithmOID.sha1;
			signAlgOID = AlgorithmOID.sha1WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS:
			hashAlg = 'sha256';
			hashAlgOID = AlgorithmOID.sha256;
			signAlgOID = AlgorithmOID.sha256WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA384_RSA_PKCS:
			hashAlg = 'sha384';
			hashAlgOID = AlgorithmOID.sha384;
			signAlgOID = AlgorithmOID.sha384WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA512_RSA_PKCS:
			hashAlg = 'sha512';
			hashAlgOID = AlgorithmOID.sha512;
			signAlgOID = AlgorithmOID.sha512WithRSAEncryption;
			break;
		default: throw new APIError('Algoritmo de assinatura não suportado', 'sign', APIError.UNSUPPORTED_ALGORITHM_ERROR);
		}

		let contentTypeAttr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.3'}),
			new asn1js.Set({ value: [ new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }) ]})
		]});
		let hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(toBeSigned));
		let digest = hash.digest();
		let messageDigestAttr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.4'}),
			new asn1js.Set({ value: [ new asn1js.OctetString({ valueHex: digest.buffer }) ]})
		]});
		hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(chain[0]));
		let certHash = hash.digest();
		let essCertIDv2 = new asn1js.Sequence({ value: [] });
		if (hashAlg.localeCompare('sha256') != 0)
		{
			essCertIDv2.valueBlock.value.push(
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: hashAlgOID }),
					new asn1js.Null()
				]})
			);
		}
		essCertIDv2.valueBlock.value.push(new asn1js.OctetString({ valueHex: certHash.buffer }));
		let essSignCertv2Attr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.16.2.47'}),
			new asn1js.Set({ value: [ essCertIDv2 ]})
		]});
		let commitmentTypeAttr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.16.2.16'}),
			new asn1js.Set({ value: [ 
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: commitmentType })
				]})
			]})
		]});
		let signedAttrs = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [
			contentTypeAttr,
			messageDigestAttr,
			essSignCertv2Attr,
			commitmentTypeAttr
		]});
		if (addSigningTime)
		{
			signedAttrs.valueBlock.value.push(
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.9.5'}),
					new asn1js.Set({ value: [ new asn1js.GeneralizedTime({ valueDate: new Date() }) ]})
				]})
			);
		}

		// TODO: Support policies other than CAdES-BES
		if (policy === Policy.typeEPES);
		else if (policy === Policy.typeT);
		else if (policy === Policy.typeC);
		else if (policy === Policy.typeX);
		else if (policy === Policy.type1);
		else if (policy === Policy.type2);
		else if (policy === Policy.typeX1);
		else if (policy === Policy.typeX2);
		else if (policy === Policy.typeA);

		let siVer = new asn1js.Integer({ value: 1 });
		let signerCert = new X509Certificate(chain[0]);
		let sid = new asn1js.Sequence({ value: [
			signerCert.getIssuer(),
			signerCert.getSerial()
		]});
		let digestAlgorithm = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: hashAlgOID }),
			new asn1js.Null()
		]});
		let signatureAlgorithm = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: signAlgOID }),
			new asn1js.Null()
		]});
		let derSignedAttrs = signedAttrs.toBER(false);
		if (derSignedAttrs.byteLength == 0) throw new APIError('Falha na codificação em DER dos atributos assinados', 'sign', APIError.DER_ENCODE_SIGNED_ATTR_ERROR);
		let toSign = new Uint8Array(derSignedAttrs);
		toSign[0] = 0x31;
		hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(toSign));
		let signatureValue;
		try { signatureValue = this.addon.sign(hash.digest(), signAlg, hHandle); }
		catch (err) { throw new APIError('Falha ao assinar os atributos do documento CMS', 'sign', APIError.SIGNED_ATTRS_SIGN_ERROR, err); }
		let signature = new asn1js.OctetString({ valueHex: signatureValue.buffer });

		let version = new asn1js.Integer({ value: 1 });
		let digestAlgorithms = new asn1js.Set({ value: [ digestAlgorithm ]});
		let encapContentInfo = new asn1js.Sequence({ value: [ new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.1' }) ]});
		if (attach) encapContentInfo.valueBlock.value.push(
			new asn1js.Constructed({ 
				idBlock: { tagClass: 3, tagNumber: 0 },
				value: [ new asn1js.OctetString({ valueHex: toBeSigned.buffer })]})
		);
		let i = 0;
		let certificates = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: []});
		while (i < chain.length)
		{
			let decoded = asn1js.fromBER(chain[i].buffer);
			if 
			(
				decoded.offset == -1 ||
				typeof decoded.result === 'undefined' ||
				!(decoded.result instanceof asn1js.Sequence)
			)	throw new APIError('Falha geral em efetuar o parsing do certificado', 'sign', APIError.CERTIFICATE_DECODE_ERROR);
			certificates.valueBlock.value.push(decoded.result);
			i++;
		}
		let signerInfos = new asn1js.Set({ value: [ 
			new asn1js.Sequence({ value: [ siVer, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, signature ] })
		]});
		let signedData = new asn1js.Sequence({ value: [ version, digestAlgorithms, encapContentInfo, certificates, signerInfos ]});

		let contentInfo = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: '1.2.840.113549.1.7.2' }),
			new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [ signedData ]})
		]});
		let encoded = contentInfo.toBER(false);
		if (encoded.byteLength == 0) throw new APIError('Falha ao codificar o documento CMS em DER', 'sign', APIError.DER_ENCODE_CMS_ERROR);
		return '-----BEGIN PKCS7-----\n' + Base64.btoa(new Uint8Array(encoded), true) + '\n-----END PKCS7-----';
	}
}

module.exports = {
	SignMechanism: Hamahiri.SignMechanism,
	AroariError: APIError,
	Enroll: Enroll,
	Sign: Sign,
	Base64: Base64,
	CommitmentType: CommitmentType
}