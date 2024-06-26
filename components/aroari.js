/**
 * @file Módulo criptográfico de alto nível (implementa a RFC 2986 e a seção 5 da RFC 5652)
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const asn1js = require('asn1js');
const crypto = require('crypto');
const Hamahiri = require('./hamahiri');


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
class APIError extends Error {
	/* jshint ignore:start */
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
	 * Falha ao decodificar um documento PKCS #7
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

	/**
	 * O campo certificates do documento CMS SignedData não contém certificados
	 * @member { Number }
	 * @default 87
	 */
	static CMS_CERTIFICATES_FIELD_EMPTY = 87;

	/**
	 * O conteúdo eContent do campo EncapsulatedContentInfo não está presente
	 * @member { Number }
	 * @default 88
	 */
	static CMS_ECONTENT_FIELD_EMPTY = 88;

	/**
	 * O documento CMS não embarca nenhum campo SignerInfo
	 * @member { Number }
	 * @default 89
	 */
	static CMS_SIGNER_INFO_EMPTY = 89;

	/**
	 * O fragmento ASN.1 não corresponde à especificação sintática de um RDN
	 * @member { Number }
	 * @default 90;
	 */
	static DER_DECODE_RDN_ERROR = 90;

	/**
	 * A assinatura calculada com os atributos assinados não é válida
	 * @member { Number }
	 * @default 91;
	 */
	static CMS_SIGNATURE_DOES_NOT_MATCH = 91;

	/**
	 * O atributo assinado Message Digest não confere com o eContent fornecido
	 * @member { Number }
	 * @default 92;
	 */
	static CMS_MESSAGE_DIGEST_NOT_MATCH = 92;

	/**
	 * O valor do atributo assinado ESS Signing Certificate V2 não confere com o hash do certificado de assinatura fornecido
	 * @member { Number }
	 * @default 93
	 */
	static CMS_SIGNING_CERTIFICATEV2_NOT_MATCH = 93;

	/**
	 * Um dos membros da cadeia de certificados relacionada ao certificado do assinante não foi encontrado
	 * @member { Number }
	 * @default 94;
	 */
	static CMS_VRFY_NO_ISSUER_CERT_FOUND = 94;
	/* jshint ignore:end */

	/**
	 * Cria uma nova instância do relatório de erros
	 * @param { String } msg Mensagem descritiva
	 * @param { String } method Método ou função onde ocorreu o erro
	 * @param { Number } errorCode Código de erro no módulo
	 * @param { Object } native Objeto de erro do módulo nativo, ou null
	 */
	constructor(msg, method, errorCode, native) {
		super(msg);
		this.component = 'Aroari';
		this.method = method;
		this.errorCode = errorCode;
		if (typeof native !== 'undefined') this.native = native;
	}
	toString() {
		let value = 'Mensagem de erro: '.concat(
			this.message, '\r\n',
			'\tComponente: ', this.component, '\r\n',
			'\tMétodo: ', this.method, '\r\n',
			'\tCódigo de erro: ', this.errorCode.toString()
		);
		if (typeof this.native !== 'undefined') {
			value = value.concat('\r\n\tMensagem fornecida pelo componente nativo: ');
			if (this.native.message && this.native.component && this.native.method && this.native.errorCode) {
				value = value.concat(this.native.message, '\r\n',
				'\t\tComponente nativo: ', this.native.component, '\r\n',
				'\t\tMétodo nativo: ', this.native.method, '\r\n',
				'\t\tCódigo de erro nativo: ', this.native.errorCode.toString()
				);
				if (typeof this.native.apiError !== 'undefined')  value = value.concat('\r\n', '\t\tCódigo de erro Windows: ', this.native.apiError.toString());
			}
			else value = value.concat(this.native.toString());
		}
		return value;
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
class Policy {
	/* jshint ignore:start */
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
	 * EXtended Long Electronic Signature with Time Type 1
	 * @member { String }
	 * @default CAdES-X Long Type 1
	 */
	static typeX1 = 'CAdES-X Long Type 1';

	/**
	 * EXtended Long Electronic Signature with Time Type 2
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
	/* jshint ignore:end */
}

/**
 * Identificador dos algoritmos criptográficos
 * @memberof Aroari
 */
class AlgorithmOID {
	/* jshint ignore:start */
	/**
	 * 
	 */
	static rsaEncryption = '1.2.840.113549.1.1.1';

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
	/* jshint ignore:end */
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
class Base64 {
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
		for (var i = 0; i < mainLength; i = i + 3) {
			chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			a = (chunk & 16515072) >> 18;
			b = (chunk & 258048)   >> 12;
			c = (chunk & 4032)     >>  6;
			d = chunk & 63;
			base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
		}
		if (byteRemainder == 1) {
			 chunk = bytes[mainLength];
			 a = (chunk & 252) >> 2;
			 b = (chunk & 3)   << 4;
			 base64 += encodings[a] + encodings[b] + '==';
		 }
		 else if (byteRemainder == 2) {
			chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
			a = (chunk & 64512) >> 10;
			b = (chunk & 1008)  >>  4;
			c = (chunk & 15)    <<  2;
			base64 += encodings[a] + encodings[b] + encodings[c] + '=';
		}
		let ret = base64;
		if (breakLines) {
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
	static atob(base64)	{
		var charlen = base64.length;
		var byteoff = 0;
		var byteLength = Math.round(((charlen) / 4 * 3)+1);
		var bytes = new Uint8Array(byteLength);
		var chunk = 0;
		var i = 0;
		var code;
		code = decodings[base64.charCodeAt(i)];
		if (code == dash_value) {
			while (code == dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			if (i!=0) {
				while(code != dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
				while(code == dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
			}
		}
		while (code<0 && code != dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
		if (code == dash_value || i >= charlen) throw new Error("A codificação recebida como base64 é inválida");
		var stage = pre; 
		while (i < charlen && code != dash_value) {
			while (i < charlen && stage != content_4 && code != dash_value) {
				stage++;
				switch(stage) {
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
				while (code < 0 && code != dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			}
			switch(stage) {
			case content_1: throw new Error("A codificação recebida como base64 é inválida");
			case content_4:	bytes[byteoff + 2] = chunk &  255;
			/* falls through */
			case content_3:	bytes[byteoff + 1] = chunk >> 8;
			/* falls through */
			case content_2:	bytes[byteoff    ] = chunk >> 16;
			}
			byteoff += stage-1;
			stage = pre;
		}
		return bytes.subarray(0,byteoff);
	}
}

/**
 * Constantes úteis para a identificação de objetos ASN.1
 * @memberof Aroari
 */
class ASN1FieldOID {
	/* jshint ignore:start */
	/**
	 * Campo X.500 Country
	 * @member { String }
	 * @default '2.5.4.6
	 */
	static x500Country = '2.5.4.6';

	/**
	 * Campo X.500 Organization
	 * @member { String }
	 * @default '2.5.4.10
	 */
	static x500Organization = '2.5.4.10';

	/**
	 * Campo X.500 Organization Unit
	 * @member { String }
	 * @default '2.5.4.11
	 */
	static x500OrgUnit = '2.5.4.11';

	/**
	 * Campo X.500 Common Name
	 * @member { String }
	 * @default '2.5.4.3
	 */
	static x500CommonName = '2.5.4.3';

	/**
	 * Campo CMS id-signedData
	 * @member { String }
	 * @default 1.2.840.113549.1.7.2
	 */
	static cmsSignedData = '1.2.840.113549.1.7.2';

	/**
	 * Campo CMS id-contentType
	 * @member { String }
	 * @default 1.2.840.113549.1.9.3
	 */
	static cmsContentType = '1.2.840.113549.1.9.3';

	/**
	 * Campos CMS id-data
	 * @member { String }
	 * @default 1.2.840.113549.1.7.1
	 */
	static cmsDataContentType = '1.2.840.113549.1.7.1';

	/**
	 * Campo CMS id-messageDigest
	 * @member { String }
	 * @default 1.2.840.113549.1.9.4
	 */
	static cmsMessageDigest = '1.2.840.113549.1.9.4';

	/**
	 * Campo CMS id-aa-signingCertificateV2
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.2.47
	 */
	static cmsSigningCertificateV2 = '1.2.840.113549.1.9.16.2.47';

	/**
	 * Campo CMS id-aa-ets-commitmentType
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.2.16
	 */
	static cmsCommitmentType = '1.2.840.113549.1.9.16.2.16';

	/**
	 * Campo CMS id-signingTime
	 * @member { String }
	 * @default 1.2.840.113549.1.9.5
	 */
	static cmsSigningTime = '1.2.840.113549.1.9.5';

	/**
	 * Extensão Subject Key Identifier do certificado
	 * @member { Number }
	 * @default  2.5.29.14
	 */
	static x509SubjectKeyIdentifier = '2.5.29.14';

	static friendlyName = '1.2.840.113549.1.9.20';
	/* jshint ignore:end */
}

/**
 * Implementa a parte cliente da emissão de um certificado digital
 * @memberof Aroari
 */
class Enroll {
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

	makeCertificateRequestInfo(rdn, pubKey, signOID) {
		let ver = new asn1js.Integer({ value: 0 });
		let name = new asn1js.Sequence({ value: [] });
		if (rdn.c) name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: ASN1FieldOID.x500Country }),
					new asn1js.Utf8String({ value: rdn.c })
				]})
			]}));
		if (rdn.o) name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: ASN1FieldOID.x500Organization}),
					new asn1js.Utf8String({ value: rdn.o })
				]})
			]}));
		if (rdn.ou) name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: ASN1FieldOID.x500OrgUnit}),
					new asn1js.Utf8String({ value: rdn.ou })
				]})
			]}));
		name.valueBlock.value.push(
			new asn1js.Set({ value: [
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: ASN1FieldOID.x500CommonName }),
					new asn1js.Utf8String({ value: rdn.cn })
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
						new asn1js.Utf8String({ value: rdn.cn })
					]})
				]})
			]
		});
		return new asn1js.Sequence({ value: [ ver, name, pubKeyInfo, attrs ]});
	}

	/**
	 * Gera um par de chaves RSA e assina uma requisição de certificado digital.
	 * @param   { Object   } options Parâmetros para operação conforme {@link Aroari.EnrollOptions}
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha
	 * @returns { String   } Requisição PKCS #10 codificada em Base64 de acordo com a convenção PEM
	 */
	generateCSR(options) {
		if (!options) throw new APIError('Argumento EnrollOptions obrigatório', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.device  == 'undefined') throw new APIError('Argumento EnrollOptions.device obrigatório', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.keySize != 'undefined' && isNaN(options.keySize)) throw new APIError('Argumento EnrollOptions.keySize, se presente, deve ser numérico', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.signAlg != 'undefined' && isNaN(options.signAlg)) throw new APIError('Argumento EnrollOptions.signAlg, se presente, deve ser numérico', 'generateCSR', APIError.ARGUMENT_ERROR);
		if (typeof options.rdn == 'undefined' || typeof options.rdn.cn == 'undefined') throw new APIError('Argumento EnrollOptions.rdn deve, obrigatoriamente, incluir pelo menos a propriedade cn', 'generateCSR', APIError.ARGUMENT_ERROR);

		let signAlg = typeof options.signAlg != 'undefined' ? options.signAlg : Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS;
		let hashAlg;
		let signOID;
		switch (signAlg) {
		case Hamahiri.SignMechanism.CKM_SHA1_RSA_PKCS:
			hashAlg = 'sha1';
			signOID = AlgorithmOID.sha1WithRSAEncryption;
			break;
		case Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS:
			hashAlg = 'sha256';
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
		if (decoded.offset == -1 || !(decoded.result instanceof asn1js.Sequence)) {
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError('Falha na decodificação DER da chave púbica gerada', 'generateCSR', APIError.DER_ENCODE_PUBKEY_ERROR);
		}
		let certificateRequestInfo = this.makeCertificateRequestInfo(options.rdn, decoded.result, ASN1FieldOID.friendlyName);
		let toBeSigned = Buffer.from(certificateRequestInfo.toBER(false));
		if (certificateRequestInfo.error != '' && toBeSigned.length == 0) {
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError(certificateRequestInfo.error, 'generateCSR', APIError.DER_ENCODE_REQUEST_INFO_ERROR);
		}
		let hash = crypto.createHash(hashAlg);
		hash.update(toBeSigned);
		let signature;
		try { signature = this.addon.signRequest(hash.digest(), signAlg, keyPair.privKey); }
		catch (err) {
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
		if (request.error != '' && csr.length == 0) {
			this.addon.deleteKeyPair(keyPair.privKey);
			throw new APIError(request.error, 'generateCSR', APIError.DER_ENCODE_REQUEST_ERROR);
		}
		this.addon.releaseKeyHandle(keyPair.privKey);
		return '-----BEGIN CERTIFICATE REQUEST-----\r\n' + Base64.btoa(csr, true) + '\r\n-----END CERTIFICATE REQUEST-----';
	}

	/* Corrige o problema de só aceitar cadeias ordenadas
	 * Ver RFC 5652
	 * certificates [0] IMPLICIT CertificateSet OPTIONAL
	 * CertificateSet ::= SET OF CertificateChoices
	 */
	readChain(pkcs7) {
		if (!pkcs7) throw new APIError('Argumento pkcs7 é obrigatório', 'installCertificates', APIError.ARGUMENT_ERROR);
		let decoded = asn1js.fromBER(pkcs7.buffer);
		if (decoded.offset == -1) throw new APIError('Falha ao decodificar de DER o documento PKCS #7', 'installCertificates', APIError.DER_DECODE_CMS_ERROR);
		let contentInfo = decoded.result;
		if  (!(
			contentInfo instanceof asn1js.Sequence &&
			Array.isArray(contentInfo.valueBlock.value) &&
			contentInfo.valueBlock.value[0] instanceof asn1js.ObjectIdentifier &&
			contentInfo.valueBlock.value[0].valueBlock.toString() === ASN1FieldOID.cmsSignedData &&
			contentInfo.valueBlock.value[1] &&
			Array.isArray(contentInfo.valueBlock.value[1].valueBlock.value)
		))	throw new APIError('CMS ContentInfo inesperado para um PKCS #7', 'installCertificates', APIError.INVALID_CONTENT_INFO_ERROR);
		let signedData = contentInfo.valueBlock.value[1].valueBlock.value[0];
		if (!(
			signedData instanceof asn1js.Sequence &&
			Array.isArray(signedData.valueBlock.value) &&
			signedData.valueBlock.value.length >= 4 &&
			Array.isArray(signedData.valueBlock.value[3].valueBlock.value)
		))	throw new APIError('Documento CMS SignedData inválido', 'installCertificates', APIError.INVALID_SIGNED_DATA_ERROR);
		return signedData.valueBlock.value[3];
	}
	validateChain(certificates) {
		function findLeaf(chain) {
			let i = 0;
			while (i < chain.length) {
				if (!chain[i].ca) return i;
				i++
			}
			return -1;
		}
		function findIssuer(cert, chain) {
			let i = 0;
			while (i < chain.length) {
				if (chain[i] && cert.checkIssued(chain[i])) return i;
				i++;
			}
			return -1;
		}
		function isEmpty(chain) {
			let i = 0;
			while (i < chain.length) if (chain[i++]) return false;
			return true;
		}

		let chain = [];
		let i = 0;
		while (i < certificates.valueBlock.value.length) {
			chain.push(new crypto.X509Certificate(Buffer.from(certificates.valueBlock.value[i].valueBeforeDecode)));
			i++;
		}
		i = findLeaf(chain);
		if (i < 0) throw new APIError('Cadeia fornecida não contém certificado de entidade final', 'installCertificates', APIError.CERTIFICATE_CHAIN_VERIFY_ERROR);
		let leaf = chain[i];
		chain[i] = null;
		while (!isEmpty(chain)) {
			i = findIssuer(leaf, chain);
			if (i < 0) throw new APIError('Pelo menos um dos emissores não foi encontrado na cadeia', 'installCertificates', APIError.CERTIFICATE_CHAIN_VERIFY_ERROR);
			let issuer = chain[i];
			chain[i] = null; 
			if (!leaf.verify(issuer.publicKey)) throw new APIError('Pelo menos uma das assinaturas da cadeia nã confere', 'installCertificates', APIError.CERTIFICATE_CHAIN_VERIFY_ERROR);
			leaf = issuer;
		}
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
		let certificates = this.readChain(pkcs7);
		this.validateChain(certificates);
		let signer = certificates.valueBlock.value[0].valueBeforeDecode;
		let done;
		try { done = this.addon.installCertificate(new Uint8Array(signer)); }
		catch (err) { throw new APIError('Falha na instalação do certificado do assinante', 'installCertificates', APIError.INSTALL_SIGNER_CERT_ERROR, err); }
		if (!done) throw new APIError('Certificado do assinante já instalado', 'installCertificates', APIError.SIGNER_CERT_ALREADY_INSTALLED_ERROR);
		let i = 1;
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
class CommitmentType {
	/* jshint ignore:start */
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
	 /* jshint ignore:end */
 }
 
/**
 * Opções CAdES da assinatura. Atributos assinados obrigatórios: Content Type, Message Digest e ESS signing-certificate-v2
 * @class CAdES
 * @memberof Aroari
 * @property { String  } policy Padrão de assinatura escolhido conforme a RFC 5126. Opcional. Valor default: CAdES-BES
 * @property { Boolean } addSigningTime Incluir atributo assinado Signing Time. Opcional. Valor default: true
 * @property { String } commitmentType Se contiver um valor descritivo, inclui o OID do atributo assinado Commitment
 * Type Indication conforme {@link Aroari.CommitmentType}. Opcional.
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
class X509Certificate {
	/**
	 * Efetua o parsing de um certificado digital utilizando a biblioteca asn1js
	 * @param { Uint8Array } encoded Certificado encodado em DER
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 */
	constructor(encoded) {
		let decoded = asn1js.fromBER(encoded.buffer);
		if (decoded.offset == -1) throw new APIError('Falha geral em efetuar o parsing do certificado', 'X509Certificate constructor', APIError.CERTIFICATE_DECODE_ERROR);
		this.root = decoded.result;
		if (
			!(this.root instanceof asn1js.Sequence) ||
			!Array.isArray(this.root.valueBlock.value) ||
			!(this.root.valueBlock.value[0] instanceof asn1js.Sequence)
		)	throw new APIError('Codificação DER inválida para um certificado digital', 'X509Certificate constructor', APIError.CERTIFICATE_DECODE_ERROR);
		this.tbs = this.root.valueBlock.value[0];
	 }

	/**
	 * Obtém o emissor do certificado
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns { Object } Uma instância de asn1js.Sequence
	 */
	getIssuer() {
		let issuer = this.tbs.valueBlock.value[3];
		if (!(issuer instanceof asn1js.Sequence)) throw new APIError('Codificação DER inválida do campo Issuer', 'getIssuer', APIError.CERTIFICATE_DECODE_ERROR);
		return issuer;
	}

	getSubject() {
		let subject = this.tbs.valueBlock.value[5];
		if (!(subject instanceof asn1js.Sequence)) throw new APIError('Codificação DER inválida do campo Subject', 'getSubject', APIError.CERTIFICATE_DECODE_ERROR);
		return subject;
	}

	/**
	 * Obtém o número serial do certificado
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns { Object } Uma instância de asn1js.Integer
	 */
	getSerial() {
		let serial = this.tbs.valueBlock.value[1];
		if (!(serial instanceof asn1js.Integer)) throw new APIError('Codificação DER inválida do campo CertificateSerialNumber', 'getSerial', APIError.CERTIFICATE_DECODE_ERROR);
		return serial;
	}

	/**
	 * Obtém o valor OCTET STRING da extensão Subject Key Identifier
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns { Object } Uma instância de asn1js.OctetString com o valor da extensão ou null, caso não seja encontrada.
	 */
	getSubjectKeyIdentifier() {
		let idx = this.tbs.valueBlock.value.length - 1;
		if (
			!(this.tbs.valueBlock.value[idx] instanceof asn1js.Constructed) ||
			this.tbs.valueBlock.value[idx].idBlock.tagNumber != 3
		)	throw new APIError('Codificação DER inválida do campo extensions[3]', 'getSubjectKeyIdentifier', APIError.CERTIFICATE_DECODE_ERROR);
		let extensions = this.tbs.valueBlock.value[idx].valueBlock.value[0];
		if (
			!(extensions instanceof asn1js.Sequence) ||
			!Array.isArray(extensions.valueBlock.value)
		)	throw new APIError('Codificação DER inválida do campo extensions[3]', 'getSubjectKeyIdentifier', APIError.CERTIFICATE_DECODE_ERROR);
		let i = 0;
		while (i < extensions.valueBlock.value.length) {
			let ext = extensions.valueBlock.value[i];
			if (
				!(ext instanceof asn1js.Sequence) ||
				!(ext.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)
			)	throw new APIError('Codificação DER inválida do campo extensions[3]', 'getSubjectKeyIdentifier', APIError.CERTIFICATE_DECODE_ERROR);
			if (ext.valueBlock.value[0].valueBlock.toString() === ASN1FieldOID.x509SubjectKeyIdentifier) {
				if (!(ext.valueBlock.value[1] instanceof asn1js.OctetString));
				return ext.valueBlock.value[1];
			}
			i++;
		}
		return null;
	}
}
 
/**
 * Implementa as funções de assinatura digital utilizando chaves RSA
 * @memberof Aroari
 */
class Sign {
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

	getHashAlg(signAlg) {
		switch (signAlg) {
		case Hamahiri.SignMechanism.CKM_SHA1_RSA_PKCS:   return 'sha1';
		case Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS: return 'sha256';
		case Hamahiri.SignMechanism.CKM_SHA384_RSA_PKCS: return 'sha384';
		case Hamahiri.SignMechanism.CKM_SHA512_RSA_PKCS: return 'sha512';
		default: throw new APIError('Algoritmo de assinatura não suportado', 'getHashAlg', APIError.UNSUPPORTED_ALGORITHM_ERROR);
		}
	}
	getHashAlgOID(hashAlg) {
		if (hashAlg === 'sha1'  ) return AlgorithmOID.sha1;
		if (hashAlg === 'sha256') return AlgorithmOID.sha256;
		if (hashAlg === 'sha384') return AlgorithmOID.sha384;
		if (hashAlg === 'sha512') return AlgorithmOID.sha512;
		throw new APIError('Algoritmo de assinatura não suportado', 'getHashAlgOID', APIError.UNSUPPORTED_ALGORITHM_ERROR);
	}
	getSignAlgOID(signAlg) {
		switch (signAlg) {
		case Hamahiri.SignMechanism.CKM_SHA1_RSA_PKCS:   return AlgorithmOID.sha1WithRSAEncryption;
		case Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS: return AlgorithmOID.sha256WithRSAEncryption;
		case Hamahiri.SignMechanism.CKM_SHA384_RSA_PKCS: return AlgorithmOID.sha384WithRSAEncryption;
		case Hamahiri.SignMechanism.CKM_SHA512_RSA_PKCS: return AlgorithmOID.sha512WithRSAEncryption;
		default: throw new APIError('Algoritmo de assinatura não suportado', 'getSignAlgOID', APIError.UNSUPPORTED_ALGORITHM_ERROR);
		}
	}
	makeSignedAttributes(hashAlg, toBeSigned, signingCert, commitmentType, addSigningTime) {
		let hashAlgOID = this.getHashAlgOID(hashAlg);
		let contentTypeAttr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsContentType }),
			new asn1js.Set({ value: [ new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsDataContentType }) ]})
		]});
		let hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(toBeSigned));
		let digest = hash.digest();
		let messageDigestAttr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsMessageDigest }),
			new asn1js.Set({ value: [ new asn1js.OctetString({ valueHex: digest.buffer }) ]})
		]});
		hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(signingCert));
		let certHash = hash.digest();
		let essCertIDv2 = new asn1js.Sequence({ value: [] });
		if (hashAlg.localeCompare('sha256') != 0) {
			essCertIDv2.valueBlock.value.push(
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: hashAlgOID }),
					new asn1js.Null()
				]})
			);
		}
		essCertIDv2.valueBlock.value.push(new asn1js.OctetString({ valueHex: certHash.buffer }));
		let essSignCertv2Attr = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsSigningCertificateV2 }),
			new asn1js.Set({ value: [ essCertIDv2 ]})
		]});
		let signedAttrs = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [
			contentTypeAttr,
			messageDigestAttr,
			essSignCertv2Attr
		]});
		if (commitmentType) {
			signedAttrs.valueBlock.value.push(
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsCommitmentType }),
					new asn1js.Set({ value: [ 
						new asn1js.Sequence({ value: [
							new asn1js.ObjectIdentifier({ value: commitmentType })
						]})
					]})
				]})
			);
		}
		if (addSigningTime) {
			signedAttrs.valueBlock.value.push(
				new asn1js.Sequence({ value: [
					new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsSigningTime }),
					new asn1js.Set({ value: [ new asn1js.GeneralizedTime({ valueDate: new Date() }) ]})
				]})
			);
		}
		return signedAttrs;
	}
	makeSignerInfos(hHandle, signAlg, signingCert, signedAttrs) {
		let hashAlg = this.getHashAlg(signAlg);
		let signAlgOID = this.getSignAlgOID(signAlg);
		let hashAlgOID = this.getHashAlgOID(hashAlg);
		let signerCert = new X509Certificate(signingCert);
		let siVer = new asn1js.Integer({ value: 1 });
		let sid = new asn1js.Sequence({ value: [
			signerCert.getIssuer(),
			signerCert.getSerial()
		]});
		let digestAlgorithm = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: hashAlgOID })
		]});
		let signatureAlgorithm = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: signAlgOID })
		]});
		let derSignedAttrs = signedAttrs.toBER(false);
		if (derSignedAttrs.byteLength == 0) throw new APIError('Falha na codificação em DER dos atributos assinados', 'makeSignerInfos', APIError.DER_ENCODE_SIGNED_ATTR_ERROR);
		let toSign = new Uint8Array(derSignedAttrs);
		toSign[0] = 0x31;
		let hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(toSign));
		let signatureValue;
		try { signatureValue = this.addon.sign(hash.digest(), signAlg, hHandle); }
		catch (err) { throw new APIError('Falha ao assinar os atributos do documento CMS', 'makeSignerInfos', APIError.SIGNED_ATTRS_SIGN_ERROR, err); }
		let signature = new asn1js.OctetString({ valueHex: signatureValue.buffer });
		return new asn1js.Set({ value: [ 
			new asn1js.Sequence({ value: [ siVer, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, signature ] })
		]});
	}
	makeSignedData(hashAlg, chain, signerInfos, toBeSigned) {
		let hashAlgOID = this.getHashAlgOID(hashAlg);
		let attach = typeof toBeSigned != 'undefined';
		let digestAlgorithm = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: hashAlgOID })
		]});
		let version = new asn1js.Integer({ value: 1 });
		let digestAlgorithms = new asn1js.Set({ value: [ digestAlgorithm ]});
		let encapContentInfo = new asn1js.Sequence({ value: [ new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsDataContentType }) ]});
		if (attach) encapContentInfo.valueBlock.value.push(
			new asn1js.Constructed({ 
				idBlock: { tagClass: 3, tagNumber: 0 },
				value: [ new asn1js.OctetString({ valueHex: toBeSigned.buffer })]})
		);
		let i = 0;
		let certificates = new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: []});
		while (i < chain.length) {
			let decoded = asn1js.fromBER(chain[i].buffer);
			if (
				decoded.offset == -1 ||
				!(decoded.result instanceof asn1js.Sequence)
			)	throw new APIError('Falha geral em efetuar o parsing do certificado', 'makeSignedData', APIError.CERTIFICATE_DECODE_ERROR);
			certificates.valueBlock.value.push(decoded.result);
			i++;
		}
		return new asn1js.Sequence({ value: [ version, digestAlgorithms, encapContentInfo, certificates, signerInfos ]});
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
		if (
			typeof options.toBeSigned === 'undefined' ||
			(typeof options.toBeSigned !== 'string' && !(options.toBeSigned instanceof ArrayBuffer))
		)	throw new APIError('Argumento SignOptions.toBeSigned must be an string or an instance of ArrayBuffer', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.attach !== 'undefined' && typeof options.attach !== 'boolean') throw new APIError('Argumento SignOptions.attach, se presente, deve ser um valor lógico', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.algorithm !== 'undefined' && isNaN(options.algorithm)) throw new APIError('Argumento SignOptions.algorithm, se presente, deve ser numérico', 'sign', APIError.ARGUMENT_ERROR);
		if (typeof options.cades !== 'undefined') {
			if (typeof options.cades !== 'object') throw new APIError('Argumento options.cades, se presente, deve ser um objeto do tipo Aroari.CAdES', 'sign', APIError.ARGUMENT_ERROR);
			if (typeof options.cades.policy !== 'undefined') {
				if (typeof options.cades.policy !== 'string') throw new APIError('Argumento options.cades.policy, se presente, deve ser do tipo string', 'sign', APIError.ARGUMENT_ERROR);
				if (options.cades.policy.localeCompare(Policy.typeBES) != 0) throw new APIError('Padrão de assinatura CAdES não suportado', 'sign', APIError.UNSUPPORTED_CADES_SIGNATURE);
			}
			if (typeof options.cades.addSigningTime !== 'undefined' && typeof options.cades.addSigningTime !== 'boolean') throw new APIError('Argumento options.cades.addSigningTime, se presente, deve ser do tipo boolean', 'sign', APIError.ARGUMENT_ERROR);
			if (typeof options.cades.commitmentType !=='undefined')
			{
				if (typeof options.cades.commitmentType !== 'string') throw new APIError('Argumento options.cades.commitmentType, se presente, deve ser do tipo string', 'sign', APIError.ARGUMENT_ERROR);
				if (
					options.cades.commitmentType !== CommitmentType.proofOfOrigin &&
					options.cades.commitmentType !== CommitmentType.proofOfReceipt &&
					options.cades.commitmentType !== CommitmentType.proofOfDelivery &&
					options.cades.commitmentType !== CommitmentType.proofOfSender &&
					options.cades.commitmentType !== CommitmentType.proofOfApproval &&
					options.cades.commitmentType !== CommitmentType.proofOfCreation
				)	throw new APIError('Tipo de compromisso com a assinatura não conhecido', 'sign', APIError.UNSUPPORTED_COMMITMENT_TYPE);
			}
		}

		let hHandle = options.handle;
		let chain;
		try { chain = this.addon.getCertificateChain(hHandle); }
		catch (err) { throw new APIError('Falha ao obter a cadeia de certificados do assinante', 'sign', APIError.GET_CHAIN_ERROR, err);}
		let toBeSigned = typeof options.toBeSigned === 'string' ? new TextEncoder().encode(options.toBeSigned) : new Uint8Array(options.toBeSigned);
		let attach = typeof options.attach !== 'undefined' ? options.attach : true;
		let signAlg = typeof options.algorithm !== 'undefined' ? options.algorithm : Hamahiri.SignMechanism.CKM_SHA256_RSA_PKCS;
		let policy = typeof options.cades !== 'undefined' && typeof options.cades.policy != 'undefined' ? options.cades.policy : Policy.typeBES;
		let addSigningTime = typeof options.cades !== 'undefined' && typeof options.cades.addSigningTime !== 'undefined' ? options.cades.addSigningTime : true;
		let commitmentType = typeof options.cades !== 'undefined' && typeof options.cades.commitmentType !== 'undefined' ? options.cades.commitmentType : null;
		let hashAlg = this.getHashAlg(signAlg);
		let signedAttrs = this.makeSignedAttributes(hashAlg, toBeSigned, chain[0], commitmentType, addSigningTime);

		// TODO: Support policies other than CAdES-BES
		if (policy !== Policy.typeBES) {
			if (policy === Policy.typeEPES);
			else if (policy === Policy.typeT);
			else if (policy === Policy.typeC);
			else if (policy === Policy.typeX);
			else if (policy === Policy.type1);
			else if (policy === Policy.type2);
			else if (policy === Policy.typeX1);
			else if (policy === Policy.typeX2);
			else if (policy === Policy.typeA);
		}

		let signerInfos = this.makeSignerInfos(hHandle, signAlg, chain[0], signedAttrs);
		let attachment;
		if (attach) attachment = toBeSigned;
		let signedData = this.makeSignedData(hashAlg, chain, signerInfos, attachment);
		let contentInfo = new asn1js.Sequence({ value: [
			new asn1js.ObjectIdentifier({ value: ASN1FieldOID.cmsSignedData }),
			new asn1js.Constructed({ idBlock: { tagClass: 3, tagNumber: 0 }, value: [ signedData ]})
		]});
		let encoded = contentInfo.toBER(false);
		if (encoded.byteLength == 0) throw new APIError('Falha ao codificar o documento CMS em DER', 'sign', APIError.DER_ENCODE_CMS_ERROR);
		return '-----BEGIN PKCS7-----\r\n' + Base64.btoa(new Uint8Array(encoded), true) + '\r\n-----END PKCS7-----';
	}
}

/**
 * Argumentos opcionais para a verificação de assinaturas digitais
 * @class VerifyOptions
 * @memberof Aroari
 * @property { ArrayBuffer | undefined } signingCert Certificado supostamente associado à chave privada que assinou o documento CMS. Opcional.
 * Se não estiver presente, o certificado do assinante é procurado no campo certificates do documento CMS, a partir do valor do campo
 * SignerIdentifier.
 * @property { ArrayBuffer | undefined } eContent Contéudo digitalmente assinado para verificação. Opcional. Se não estiver presente, o
 * conteúdo é procurado no campo EncapsulatedContentInfo do documento CMS.
 */

/**
 * Implementa um Relative Distinguished Name para comparação com outro RDN (stringprep)
 * @memberof Aroari
 */
class RDN {
	/**
	 * Cria uma nova instância de um RDN. O objeto asn1js.Sequence recebido como argumento é validado contra
	 * a especificação
	 * @param { Object } rdn asn1js.Sequence
	 * @throws { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 */
	constructor(rdn) {
		if (!(rdn instanceof asn1js.Sequence)) throw new APIError('O argumento rdn deve ser uma instância de asn1js.Sequence', 'RDN constructor', APIError.ARGUMENT_ERROR);
		this.name = rdn.valueBlock.value;
		if (!Array.isArray(this.name)) throw new APIError('O argumento deve obedecer à especificação de um RDN', 'RDN constructor', APIError.DER_DECODE_RDN_ERROR);
		let i = 0;
		while (i < this.name.length) {
			if (
				!(this.name[i] instanceof asn1js.Set) ||
				this.name[i].valueBlock.value.length > 1 ||
				!(this.name[i].valueBlock.value[0] instanceof asn1js.Sequence)
			)	throw new APIError('O argumento deve obedecer à especificação de um RDN', 'RDN()', APIError.DER_DECODE_RDN_ERROR);
			let typeAndValue = this.name[i].valueBlock.value[0];
			if (
				typeAndValue.valueBlock.value.length != 2 ||
				!(typeAndValue.valueBlock.value[0] instanceof asn1js.ObjectIdentifier) ||
				typeof typeAndValue.valueBlock.value[1] !== 'object'
			)	throw new APIError('O argumento deve obedecer à especificação de um RDN', 'RDN()', APIError.DER_DECODE_RDN_ERROR);
			i++;
		}
	}
	stringPrep(inputString) {
		let isSpace = false;
		let cuttedResult = '';
		const result = inputString.trim();
		for (let i = 0; i < result.length; i++) {
			if (result.charCodeAt(i) === 32) { if(isSpace === false) isSpace = true; }
			else {
				if (isSpace) {
					cuttedResult += ' ';
					isSpace = false;
				}
				cuttedResult += result[i];
			}
		}
		return cuttedResult.toLowerCase();
	}

	/**
	 * Verifica se as duas instâncias correspondem a um mesmo RDN
	 * @param { Object } rdn RDN para verificar a igualdade nos termos da especificação RFC 3454 (stringprep)
	 * @returns { Boolean } Indicador de igualdade
	 */
	equalsTo(rdn) {
		if (!(rdn instanceof RDN)) return false;
		let myName = this.name;
		let otherName = rdn.name;
		if (myName.length != otherName.length) return false;
		let i = 0;
		while (i < myName.length) {
			let myTypeAndValue = myName[i].valueBlock.value[0];
			let otherTypeAndValue = otherName[i].valueBlock.value[0];
			if (myTypeAndValue.valueBlock.value[0].valueBlock.toString() !== otherTypeAndValue.valueBlock.value[0].valueBlock.toString()) return false;
			let myPrep = this.stringPrep(myTypeAndValue.valueBlock.value[1].valueBlock.value);
			let otherPrep = this.stringPrep(otherTypeAndValue.valueBlock.value[1].valueBlock.value);
			if (myPrep.localeCompare(otherPrep) !== 0) return false;
			i++;
		}
		return true;
	}

	toString() {
		let ret = [];
		let i = 0;
		while (i < this.name.length) {
			let typeAndValue = this.name[i].valueBlock.value[0];
			let type = typeAndValue.valueBlock.value[0].valueBlock.toString();
			let value;
			if      (type === ASN1FieldOID.x500Country)      value = 'C=';
			else if (type === ASN1FieldOID.x500Organization) value = 'O=';
			else if (type === ASN1FieldOID.x500OrgUnit)      value = 'OU=';
			else if (type === ASN1FieldOID.x500CommonName)   value = 'CN=';
			else value = type + '=';
			value += typeAndValue.valueBlock.value[1].valueBlock.value;
			ret.push(value);
			i++;
		}
		return ret.join(',');
	}
}

/**
 * Implementa as funções de parsing e verificação de documentos CMS assinados.
 * Note-se que o construtor da classe não efetua a validação completa do parsing do documento, tarefa realizada a cada método.
 * Caso o documento CMS embarque mais de um assinante, somente o primeiro é considerado.
 * @memberof Aroari
 */
class CMSSignedData {
	/**
	 * Efetua o parsing do documento CMS especificado e valida os campos necessários à verificação criptográfica da assinatura.
	 * @param { String | ArrayBuffer } cms Documento CMS SignedData, codificado em Base64 (seguindo as convenções PEM) ou DER.
	 * @throws { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 */
	constructor(cms) {
		let encoded;
		if (typeof cms === 'string') {
			let input = cms.replace('-----BEGIN PKCS7-----', '').replace('-----END PKCS7-----', '').replace('-----BEGIN CMS-----', '').replace('-----END CMS-----', '').replace(/\r?\n|\r/g, '');
			try { encoded = Base64.atob(input); }
			catch (err) { throw new APIError(err.toString(), 'CMSSignedData constructor', APIError.ARGUMENT_ERROR); }
		}
		else if (cms instanceof ArrayBuffer) {
			encoded = new Uint8Array(cms);
			if (encoded[0] != 0x30) throw new APIError('ArrayBuffer argument must be conforms CMS specification', 'CMSSignedData constructor', APIError.ARGUMENT_ERROR);
		}
		else throw new APIError('Argumento cms deve ser uma string ou um ArrayBuffer', 'CMSSignedData constructor', APIError.ARGUMENT_ERROR);
		let decoded = asn1js.fromBER(encoded.buffer);
		if (
			decoded.offset == -1 ||
			!(decoded.result instanceof asn1js.Sequence)
		)	throw new APIError('Falha geral em efetuar o parsing do documento CMS', 'CMSSignedData constructor', APIError.DER_DECODE_CMS_ERROR);
		let contentInfo = decoded.result;
		if (
			!(contentInfo.valueBlock.value[0] instanceof asn1js.ObjectIdentifier) ||
			contentInfo.valueBlock.value[0].valueBlock.toString() !== ASN1FieldOID.cmsSignedData
		)	throw new APIError('Documento não é um CMS SignedData', 'CMSSignedData constructor', APIError.DER_DECODE_CMS_ERROR);
		if (
			!(contentInfo.valueBlock.value[1] instanceof asn1js.Constructed) ||
			contentInfo.valueBlock.value[1].idBlock.tagNumber != 0
		)	throw new APIError('Documento não tem as características obrigatórias de um CMS', 'CMSSignedData constructor', APIError.DER_DECODE_CMS_ERROR);
		this.signedData = contentInfo.valueBlock.value[1].valueBlock.value[0];
		if (!(this.signedData instanceof asn1js.Sequence)) throw new APIError('Documento não tem as características de um CMS SignedData', 'CMSSignedData constructor', APIError.DER_DECODE_CMS_ERROR);
	}

	matchOctets(a, b) {
		if (a.length != b.length) return false;
		let i = 0;
		while (i < a.length) {
			if (a[i] != b[i]) return false;
			i++;
		}
		return true;
	}
	getSignerInfo() {
		let idx = this.signedData.valueBlock.value.length - 1;
		let signerInfos = this.signedData.valueBlock.value[idx];
		if (!(signerInfos instanceof asn1js.Set)) throw new APIError('O campo signerInfos do documento assinando não é válido', 'getSignerInfo', APIError.DER_DECODE_CMS_ERROR);
		if (!(signerInfos.valueBlock.value[0] instanceof asn1js.Sequence)) throw new APIError('Nenhuma assinatura foi encontrada no documento CMS', 'getSignerInfo', APIError.CMS_SIGNER_INFO_EMPTY);
		return signerInfos.valueBlock.value[0];
	}
	getSignatureAlgorithm() {
		let signerInfo = this.getSignerInfo();
		let signatureAlgorithm = signerInfo.valueBlock.value[4];
		if (!(signatureAlgorithm instanceof asn1js.Sequence)) throw new APIError('Documento não tem as características de um CMS SignedData', 'getSignatureAlgorithm', APIError.DER_DECODE_CMS_ERROR);
		let algId = signatureAlgorithm.valueBlock.value[0];
		if (!(algId instanceof asn1js.ObjectIdentifier)) throw new APIError('Documento não tem as características de um CMS SignedData', 'getSignatureAlgorithm', APIError.DER_DECODE_CMS_ERROR);
		let oid = algId.valueBlock.toString();
		if (oid === AlgorithmOID.sha1WithRSAEncryption)   return 'RSA-SHA1';
		if (oid === AlgorithmOID.sha256WithRSAEncryption) return 'RSA-SHA256';
		if (oid === AlgorithmOID.sha384WithRSAEncryption) return 'RSA-SHA384';
		if (oid === AlgorithmOID.sha512WithRSAEncryption) return 'RSA-SHA512';
		if (oid === AlgorithmOID.rsaEncryption)
		{
			let digestAlgorithm = signerInfo.valueBlock.value[2];
			if (!(digestAlgorithm instanceof asn1js.Sequence)) throw new APIError('Documento não tem as características de um CMS SignedData', 'getSignatureAlgorithm', APIError.DER_DECODE_CMS_ERROR);
			let hashId = digestAlgorithm.valueBlock.value[0];
			if (!(hashId instanceof asn1js.ObjectIdentifier)) throw new APIError('Documento não tem as características de um CMS SignedData', 'getSignatureAlgorithm', APIError.DER_DECODE_CMS_ERROR);
			let hashOID = hashId.valueBlock.toString();
			if (hashOID === AlgorithmOID.sha1)   return 'RSA-SHA1';
			if (hashOID === AlgorithmOID.sha256) return 'RSA-SHA256';
			if (hashOID === AlgorithmOID.sha384) return 'RSA-SHA384';
			if (hashOID === AlgorithmOID.sha512) return 'RSA-SHA512';
		}
		throw new APIError('Algoritmo de assinatura não suportado', 'getSignatureAlgorithm', APIError.UNSUPPORTED_ALGORITHM_ERROR);
	}
	getSignedAttributes() {
		let signerInfo = this.getSignerInfo();
		let signedAttrs = signerInfo.valueBlock.value[3];
		if (!(signedAttrs instanceof asn1js.Constructed)) throw new APIError('Campo SignedAttributes do documento CMS inválido', 'getSignedAttributes', APIError.DER_DECODE_CMS_ERROR);
		return signedAttrs;
	}
	getSignatureValue() {
		let signerInfo = this.getSignerInfo();
		let idx = signerInfo.valueBlock.value.length - 1;
		let signature = signerInfo.valueBlock.value[idx];
		if (!(signature instanceof asn1js.OctetString)) throw new APIError('Campo SignatureValue do documento CMS inválido', 'getSignatureValue', APIError.DER_DECODE_CMS_ERROR);
		return signature.valueBlock.valueHex;
	}
	matchSignature(signingCert, signedAttrs) {
		let pubKey;
		try {
			let x509Cert = new crypto.X509Certificate(new Uint8Array(signingCert));
			pubKey = x509Cert.publicKey;
			if (typeof pubKey !== 'object') throw new Error('X509Certificate Public Key field is undefined');
		}
		catch (err) { throw new APIError(err.toString(), 'matchSignature', APIError.CERTIFICATE_DECODE_ERROR); }
		let signAlg = this.getSignatureAlgorithm();
		let signed = new Uint8Array(signedAttrs.valueBeforeDecode);
		signed[0] = 0x31;
		let signature = this.getSignatureValue();
		let vrfy = crypto.createVerify(signAlg);
		vrfy.update(signed);
		let match = vrfy.verify(pubKey, new Uint8Array(signature));
		if (!match) throw new APIError('A verificação criptográfica da assinatura não confere', 'matchSignature', APIError.CMS_SIGNATURE_DOES_NOT_MATCH);
	}
	getCertificates() {
		let certField = this.signedData.valueBlock.value[3];
		if (
			!(certField instanceof asn1js.Constructed) ||
			certField.idBlock.tagNumber != 0
		)	throw new APIError('Não foi possível localizar o campo certificates do documento CMS', 'getCertificates', APIError.DER_DECODE_CMS_ERROR);
		let certificates = [];
		let i = 0;
		while (i < certField.valueBlock.value.length) {
			if (!(certField.valueBlock.value[i] instanceof asn1js.Sequence)) throw new APIError('Valor inválido para o campo certificates do documento CMS', 'getCertificates', APIError.DER_DECODE_CMS_ERROR);
			certificates.push(certField.valueBlock.value[i].valueBeforeDecode);
			i++;
		}
		return certificates;
	}
	getSid() {
		let signerInfo = this.getSignerInfo();
		let sid = signerInfo.valueBlock.value[1];
		if (sid instanceof asn1js.Sequence || (sid instanceof asn1js.Constructed && sid.idBlock.tagNumber === 0)) return sid;
		throw new APIError('O campo SignerIdentifier do documento CMS é inválido', 'getSid', APIError.DER_DECODE_CMS_ERROR);
	}
	findSigningCertificateByIssuerSerial(certificates, sid) {
		let i = 0;
		while (i < certificates.length) {
			let cert = new X509Certificate(new Uint8Array(certificates[i]));
			let serial = new Uint8Array(sid.valueBlock.value[1].valueBlock.valueHex);
			let issuer = new RDN(sid.valueBlock.value[0]);
			let searchedIssuer = new RDN(cert.getIssuer());
			if (issuer.equalsTo(searchedIssuer)) {
				let searchedSerial = new Uint8Array(cert.getSerial().valueBlock.valueHex);
				if (this.matchOctets(serial, searchedSerial)) return certificates[i];
			}
			i++;
		}
		return null;
	}
	findSigningCertificateBySKI(certificates, sid) {
		let octets = new Uint8Array(sid.valueBlock.valueHex);
		let i = 0;
		while (i < certificates.length) {
			let cert = new X509Certificate(new Uint8Array(certificates[i]));
			let ski = cert.getSubjectKeyIdentifier();
			if (ski instanceof asn1js.OctetString) {
				let searched = new Uint8Array(ski.valueBlock.valueHex);
				if (this.matchOctets(octets, searched)) return certificates[i];
			}
			i++;
		}
		return null;
	}
	findAttribute(signedAttrs, fetchedOID) {
		let i = 0;
		while (i < signedAttrs.valueBlock.value.length) {
			let attr = signedAttrs.valueBlock.value[i];
			let oid = attr.valueBlock.value[0];
			if (oid.valueBlock.toString() === fetchedOID) {
				if (!(attr.valueBlock.value[1] instanceof asn1js.Set)) throw new APIError('Falha ao desencodar o atributo assinado', 'findAttribute', APIError.DER_DECODE_CMS_ERROR);
				return attr.valueBlock.value[1].valueBlock.value[0];
			}
			i++;
		}
		return null;
	}
	getDigestAlgorithm() {
		let signerInfo = this.getSignerInfo();
		if (
			!(signerInfo.valueBlock.value[2] instanceof asn1js.Sequence) ||
			!(signerInfo.valueBlock.value[2].valueBlock.value[0] instanceof asn1js.ObjectIdentifier)
		)	throw new APIError('Falha ao desencodar o campo DigestAlgorithmIdentifier', 'getDigestAlgorithm', APIError.DER_DECODE_CMS_ERROR);
		let oid = signerInfo.valueBlock.value[2].valueBlock.value[0];
		let hashOID = oid.valueBlock.toString();
		if (hashOID === AlgorithmOID.sha1)   return 'sha1';
		if (hashOID === AlgorithmOID.sha256) return 'sha256';
		if (hashOID === AlgorithmOID.sha384) return 'sha384';
		if (hashOID === AlgorithmOID.sha512) return 'sha512';
		throw new APIError('Algoritmo de hash não suportado', 'getDigestAlgorithm', APIError.UNSUPPORTED_ALGORITHM_ERROR);
	}
	matchMessageDigest(signedAttrs, eContent) {
		let fetched = this.findAttribute(signedAttrs, ASN1FieldOID.cmsMessageDigest);
		if (!fetched || !(fetched instanceof asn1js.OctetString)) throw new APIError('Falha ao desencodar o atributo Message Digest', 'matchMessageDigest', APIError.DER_DECODE_CMS_ERROR);
		let octets = fetched.valueBlock.valueHex;
		let hashAlg = this.getDigestAlgorithm();
		let hash = crypto.createHash(hashAlg);
		hash.update(Buffer.from(eContent));
		let dgst = hash.digest();
		let match = this.matchOctets(new Uint8Array(octets), new Uint8Array(dgst.buffer));
		if (!match) throw new APIError('O hash criptográfico do argumento eContent não confere com o valor do atributo assinado Message Digest', 'matchMessageDigest', APIError.CMS_MESSAGE_DIGEST_NOT_MATCH);
	}
	matchSigningCertificate(signedAttrs, signingCert) {
		let fetch = this.findAttribute(signedAttrs, ASN1FieldOID.cmsSigningCertificateV2);
		if (fetch) {
			if (!(fetch instanceof asn1js.Sequence)) throw new APIError('Falha ao desencodar o atributo assinado signingCertificateV2 ', 'matchSigningCertificate', APIError.DER_DECODE_CMS_ERROR);
			let hashAlg = 'sha256';
			let idx = 0;
			if (fetch.valueBlock.value.length == 2) {
				if (!(fetch.valueBlock.value[idx] instanceof asn1js.Sequence)) throw new APIError('Falha ao desencodar o atributo assinado signingCertificateV2 ', 'matchSigningCertificate', APIError.DER_DECODE_CMS_ERROR);
				let digestAlgorithm = fetch.valueBlock.value[idx];
				if (!(digestAlgorithm.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)) throw new APIError('Falha ao desencodar o atributo assinado signingCertificateV2 ', 'matchSigningCertificate', APIError.DER_DECODE_CMS_ERROR);
				let hashOID = digestAlgorithm.valueBlock.value[0].valueBlock.toString();
				if      (hashOID === AlgorithmOID.sha1)   hashAlg = 'sha1';
				else if (hashOID === AlgorithmOID.sha256) hashAlg = 'sha256';
				else if (hashOID === AlgorithmOID.sha384) hashAlg = 'sha384';
				else if (hashOID === AlgorithmOID.sha512) hashAlg = 'sha512';
				else throw new APIError('Algoritmo de hash não suportado', 'matchSigningCertificate', APIError.UNSUPPORTED_ALGORITHM_ERROR);
				idx++;
			}
			if (!(fetch.valueBlock.value[idx] instanceof asn1js.OctetString)) throw new APIError('Falha ao desencodar o atributo assinado signingCertificateV2 ', 'findSigningCertificate', APIError.DER_DECODE_CMS_ERROR);
			let octets = fetch.valueBlock.value[idx];
			let hash = crypto.createHash(hashAlg);
			hash.update(new Uint8Array(signingCert));
			let dgst = hash.digest();
			let match = this.matchOctets(new Uint8Array(octets.valueBlock.valueHex), new Uint8Array(dgst.buffer));
			if (!match) throw new APIError('O valor do atributo assinado ESS Signing Certificate V2 não confere com o hash do certificado de assinatura fornecido', 'matchSigningCertificate', APIError.CMS_SIGNING_CERTIFICATEV2_NOT_MATCH);
		}
	}
	verifyCertChain(signingCert) {
		let addon = new Hamahiri.Sign();
		let verified = false;
		let subjectCert = signingCert;
		while (!verified) {
			let issuers = addon.getIssuerOf(subjectCert);
			if (!Array.isArray(issuers) || issuers.length == 0) throw new APIError('Um dos membros da cadeia de certificados relacionada ao certificado do assinante não foi encontrado nos repositórios do sistema', 'verifyCertChain', APIError.CMS_VRFY_NO_ISSUER_CERT_FOUND);
			let i = 0;
			let issuerFound = false;
			let subject = new crypto.X509Certificate(subjectCert);
			while (!verified && !issuerFound && i < issuers.length) {
				let issuer = new crypto.X509Certificate(issuers[i]);
				issuerFound = subject.verify(issuer.publicKey);
				if (!issuerFound) i++;
			}
			if (!issuerFound) throw new APIError('Um dos membros da cadeia de certificados relacionada ao certificado do assinante não foi encontrado nos repositórios do sistema', 'verifyCertChain', APIError.CMS_VRFY_NO_ISSUER_CERT_FOUND);
			let iss = new X509Certificate(issuers[i]);
			let rdn = new RDN(iss.getSubject());
			verified = rdn.equalsTo(new RDN(iss.getIssuer()));
			subjectCert = issuers[i];
		}
	}

	/**
	 * Efetua a verificação criptográfica da assinatura do documento CMS.
	 * @param   { Object   } options Definições para a verificação, conforme {@link Aroari.VerifyOptions}
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIError} em caso de falha na conferência da assinatura ou na
	 * obtenção dos requisitos necessários à verificação.
	 */
	verify(options) {
		let signingCert;
		let eContent;
		if (typeof options != 'undefined') {
			if (typeof options.signingCert != 'undefined') {
				if (options.signingCert instanceof ArrayBuffer) signingCert = options.signingCert;
				else throw new APIError('O argumento options.signingCert, se presente, deve ser do tipo ArrayBuffer', 'verify', APIError.ARGUMENT_ERROR);
			}
			if (typeof options.eContent != 'undefined') {
				if (options.eContent instanceof ArrayBuffer) eContent = options.eContent;
				else throw new APIError('O argumento options.eContent, se presente, deve ser do tipo ArrayBuffer', 'verify', APIError.ARGUMENT_ERROR);
			}
		}
		if (typeof signingCert === 'undefined') {
			let certificates = this.getCertificates();
			if (certificates.length == 0) throw new APIError('Não é possível executar este método: o certificado do assinante não foi embarcado no documento CMS', 'verify', APIError.CMS_CERTIFICATES_FIELD_EMPTY);
			let sid = this.getSid();
			if (sid instanceof asn1js.Sequence) signingCert = this.findSigningCertificateByIssuerSerial(certificates, sid);
			else signingCert = this.findSigningCertificateBySKI(certificates, sid);
			if (!signingCert) throw new APIError('O certificado digital do assinante é requerido para a verificação', 'verify', APIError.CMS_VRFY_NO_ISSUER_CERT_FOUND);
		}
		if (typeof eContent === 'undefined') eContent = this.getSignedContent();
		let signedAttrs = this.getSignedAttributes();
		this.matchSignature(signingCert, signedAttrs);
		this.matchMessageDigest(signedAttrs, eContent);
		this.matchSigningCertificate(signedAttrs, signingCert);
	}

	/**
	 * Verifica se o certificado fornecido no argumento foi assinado por uma Autoridade Certificadora confiável, isto é, instalada
	 * num dos repositórios do Windows. Caso o parâmetro não seja fornecido, é verificada a confiabilidade do certificado de
	 * assinatura embarcado no documento CMS.
	 * @param { ArrayBuffer | undefined } cert Certiticado utilizado para assinatura. Opcional. Se não definido, este certificado é
	 * buscado no próprio documento CMS a partir do seu campo SignerIdentifier
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIError} em caso de falha na verificação da confiabilidade do
	 * certificado ou na obtenção dos requisitos necessários à verificação.
	 */
	verifyTrustworthy(cert) {
		let signingCert;
		if (typeof cert != 'undefined') {
			if (cert instanceof ArrayBuffer) signingCert = cert;
			else throw new APIError('O argumento options.signingCert, se presente, deve ser do tipo ArrayBuffer', 'verify', APIError.ARGUMENT_ERROR);
		}
		if (typeof signingCert === 'undefined') {
			let certificates = this.getCertificates();
			if (certificates.length == 0) throw new APIError('Não é possível executar este método: o certificado do assinante não foi embarcado no documento CMS', 'verify', APIError.CMS_CERTIFICATES_FIELD_EMPTY);
			let sid = this.getSid();
			if (sid instanceof asn1js.Sequence) signingCert = this.findSigningCertificateByIssuerSerial(certificates, sid);
			else signingCert = this.findSigningCertificateBySKI(certificates, sid);
			if (!signingCert) throw new APIError('O certificado digital do assinante é requerido para a verificação', 'verify', APIError.CMS_VRFY_NO_ISSUER_CERT_FOUND);
		}
		this.verifyCertChain(new Uint8Array(signingCert));
	}

	toHex(data) {
		let ret = [];
		data.forEach((elem) => { ret.push(elem.toString(16).padStart(2, 0)); });
		return ret.join('');
	}

	/**
	 * Obtém o identificador do assinante do documento CMS.
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIError} em caso de falha
	 * @returns { Object   } O valor da CHOICE SignerIdentifier, a saber:<br>
	 * <ul>
	 * <li>issuer: se presente, contém o nome distinto do emissor do certificado;</li>
	 * <li>serialNumber: se presente, contém o número de série do certificado como uma string em hexadecimal;</li>
	 * <li>subjectKeyIdentifier: se presente, contém o identificador da chave pública do assinante como uma string em hexadecimal.</li>
	 * </ul>
	 */
	getSignerIdentifier() {
		let ret = {};
		let sid = this.getSid();
		if (sid instanceof asn1js.Sequence)
		{
			let issuer = new RDN(sid.valueBlock.value[0]);
			Object.defineProperty(ret, 'issuer', { value: issuer.toString(), writable: false});
			let serial = this.toHex(new Uint8Array(sid.valueBlock.value[1].valueBlock.valueHex));
			Object.defineProperty(ret, 'serialNumber', { value: serial, writable: false });
		}
		else
		{
			let keyId = this.toHex(new Uint8Array(sid.valueBlock.valueHex));
			Object.defineProperty(ret, 'subjectKeyIdentifier', { value: keyId, writable: false });
		}
		return ret;
	}

	/**
	 * Obtém o conteúdo assinado.
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIError} em caso de falha ou caso o conteúdo assinado não esteja presente.
	 * @returns { ArrayBuffer } O conteúdo assinado em octetos.
	 */
	getSignedContent() {
		let encapContentInfo = this.signedData.valueBlock.value[2];
		if (
			!(encapContentInfo instanceof asn1js.Sequence) ||
			!(encapContentInfo.valueBlock.value[0] instanceof asn1js.ObjectIdentifier)
		)	throw new APIError('Documento não tem as características de um CMS SignedData', 'getSignedContent', APIError.DER_DECODE_CMS_ERROR);
		if (
			!(encapContentInfo.valueBlock.value[1] instanceof asn1js.Constructed) ||
			encapContentInfo.valueBlock.value[1].idBlock.tagNumber != 0 ||
			typeof encapContentInfo.valueBlock.value[1].valueBlock.value[0] === 'undefined'
		)	throw new APIError('O conteúdo assinado não está embarcado no documento CMS', 'getSignedContent', APIError.CMS_ECONTENT_FIELD_EMPTY);
		let eContent = encapContentInfo.valueBlock.value[1].valueBlock.value[0];
		if (!(eContent instanceof asn1js.OctetString)) throw new APIError('Documento não tem as características de um CMS SignedData', 'getSignedContent', APIError.DER_DECODE_CMS_ERROR);
		return eContent.valueBlock.valueHex;
	}

	/**
	 * Obtém a data alegada da assinatura, se presente
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIError} em caso de falha.
	 * @returns { Date } O conteúdo do atributo assinado, se presente, ou null.
	 */
	getSigningTime() {
		let ret = null;
		let signedAttrs = this.getSignedAttributes();
		let fetched = this.findAttribute(signedAttrs, ASN1FieldOID.cmsSigningTime);
		if (fetched) {
			if (!(fetched instanceof asn1js.GeneralizedTime)) throw new APIError('Falha ao desencodar o atributo Signing Time', 'getSigningTime', APIError.DER_DECODE_CMS_ERROR);
			ret = fetched.toDate();
		}
		return ret;
	}
}

module.exports = {
	AroariError: APIError,
	SignMechanism: Hamahiri.SignMechanism,
	CommitmentType: CommitmentType,
	Base64: Base64,
	Enroll: Enroll,
	Sign: Sign,
	CMSSignedData: CMSSignedData
};