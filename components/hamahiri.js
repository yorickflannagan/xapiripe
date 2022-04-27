/**
 * @file Módulo nativo Node.js para acesso aos dispositivos criptográficos
 * @copyright Copyleft &copy; 2021 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';
const addon = require('./hamahiri-native');

/**
 * Global objects
 * @namespace Xapiripe
 */
/**
 * Certificate object
 * @class Certificate
 * @memberof Xapiripe
 * @property { string } subject - Titular do certificado
 * @property { string } issuer  - Emissor do certificado
 * @property { string } serial  - Número de série do certificado, onde os bytes são representados em hexadecimal
 * @property { Number } handle  - Handle para acesso à chave privada associada ao certificado
 */


/**
 * Acesso aos dispositivos criptográficos instalados no computador local
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
 * Representação interna de um par de chaves RSA
 * @class KeyPair
 * @memberof Hamahiri
 * @property { Uint8Array } pubKey - Chave pública (campo SubjectPublicKeyInfo do PKCS #10) encodada em DER
 * @property { Number     } privKey - Handle para a chave privada
 */

 
/**
 * Constante PKCS #11 para os algoritmos de assinatura suportados
 * @memberof Hamahiri
 * @typedef { Number } SignMechanism
 */
 class SignMechanism
{
	/**
	 * Constante para o algoritmo sha1WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default 0x00000006
	 */
	static CKM_SHA1_RSA_PKCS   = 0x00000006;

	/**
	 * Constante para o algoritmo sha256WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default 0x00000040
	 */
	static CKM_SHA256_RSA_PKCS = 0x00000040;

	/**
	 * Constante para o algoritmo sha384WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default 0x00000041
	 */
	static CKM_SHA384_RSA_PKCS = 0x00000041;

	/**
	 * Constante para o algoritmo sha512WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default 0x00000042
	 */
	static CKM_SHA512_RSA_PKCS = 0x00000042;
}

/**
 * Implementa as operações de acesso a dispositivos criptográficos
 * @memberof Hamahiri
 */
 class Hamahiri
{
	constructor() { this.addon = new addon.Hamahiri(); }
}

/**
 * Operações de emissão de certificados (enrollment)
 * @memberof Hamahiri
 * @extends Hamahiri
 */
 class Enroll extends Hamahiri
{
	constructor() { super(); }

	/**
	 * Enumera os dispositivos criptográficos presentes (Cryptographic Services Providers para RSA)
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @return { Array } Lista de strings contendo os nomes dos dispositivos presentes
	 */
	enumerateDevices() {
		return this.addon.enumerateDevices();
	};

	/**
	 * Gera um par de chaves RSA
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { string } device  Cryptographic Service Provider a ser utilizado para gerar as chaves
	 * @param { Number } keySize Tamanho (em bits) das chaves RSA
	 * @returns { KeyPair } Retorna o par de chaves gerado como uma instância de {@link Hamahiri.KeyPair}.
	 */
	generateKeyPair(device, keySize) {
		return this.addon.generateKeyPair(device, keySize);
	}

	/**
	 * Assina o buffer contendo o hash da requisição de assinatura de certificado
	 * @throws  { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param   { Uint8Array    } hash      Hash do conteúdo. Deve ter o tamanho apropriado às chaves RSA e ao algoritmo especificado.
	 * @param   { SignMechanism } algorithm Constante PKCS #11 do algoritmo de assinatura
	 * @param   { Number        } key       Handle para a chave privada de assinatura, obtido previamente
	 * @returns { Uint8Array } Buffer assinado.
	 */
	signRequest(hash, algorithm, key) {
		return this.addon.signRequest(hash, algorithm, key);
	}

	/**
	 * Libera o handle para uma chave privada
	 * @throws  { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { Number } hHandle Handle retornado anteriormente
	 * @returns { boolean } Indicador de sucesso
	 */
	releaseKeyHandle(hHandle) {
		return this.addon.releaseKeyHandle(hHandle);
	}

	/**
	 * Remove do repositório criptográfico um par de chaves criado por generateKeyPair
	 * @throws {Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de argumentos inválidos
	 * @param { Number } key Handle para a chave gerada, obtido por {@link Enroll.generateKeyPair}
	 * @returns Indicador de sucesso da operação. Uma chave inexistente não é considerada uma falha.
	 */
	deleteKeyPair(key) {
		return this.addon.deleteKeyPair(key);
	}

	/**
	 * Instala o certificado de usuário, caso a chave pública esteja associada a uma chave privada existente
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { Uint8Array } userCertificate Certificado do usuário codificado em DER
	 * @returns { boolean } Indicador de sucesso da operação. Caso o certificado tenha sido instalado
	 * anteriormente, retorna false
	 */
	installCertificate(userCertificate) {
		return this.addon.installCertificate(userCertificate);
	}

	/**
	 * Instala a cadeia de certificados emissores confiáveis. Deve-se verificar previamente se a cadeia é válida e se sua
	 * AC final assinou um certificado de usuário com instalação prévia bem sucedida.
	 * @throws  { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param   { Array } chain  Cadeia de certificados codificada em DER, representada como uma matriz de Uint8Array
	 * @returns { boolean } Indicador de sucesso da operação. Caso a cadeia tenha sido instalada
	 * anteriormente, retorna false
	 */
	installChain(chain) {
		let i = 0;
		let added = true;
		while (i < chain.length)
		{
			let rv = this.addon.installCACertificate(chain[i]);
			added = !rv ? false : added;
			i++;
		}
		return added;
	}

	/**
	 * Remove o certificado especificado pelo seu titular.
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param  { String } subject Titular do certificado a ser excluído.
	 * @param  { String } issuer  Emissor do certificado
	 * @returns { boolean } Indicador de sucesso da operação. Caso o certificado não seja encontrado, retorna false.
	 */
	deleteCertificate(subject, issuer) {
		return this.addon.deleteCertificate(subject, issuer);
	}
}

/**
 * Implementa a assinatura digital de documentos
 * @memberof Hamahiri
 * @extends Hamahiri
 */
 class Sign extends Hamahiri
{
	constructor() { super(); }

	/**
	 * Enumera os certificados em vigor que estejam associados a chaves privadas RSA nos repositórios criptográficos
     * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @returns { Array } Um array de objetos {@link Xapiripe.Certificate}
	 */
	 enumerateCertificates() {
		return this.addon.enumerateCertificates();
	}

	/**
	 * Assina o buffer contendo o hash do conteúdo
	 * @throws  { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param   { Uint8Array    } hash      Hash do conteúdo. Deve ter o tamanho apropriado às chaves RSA e ao algoritmo especificado.
	 * @param   { SignMechanism } algorithm Constante PKCS #11 do algoritmo de assinatura
	 * @param   { Number        } key       Handle para a chave privada de assinatura, obtido previamente
	 * @returns { Uint8Array } Buffer assinado.
	 */
	 sign(hash, algorithm, key) {
		return this.addon.sign(hash, algorithm, key);
	}

	/**
	 * Obtém a cadeia de certificados associada ao certificado de usuário final especificado
     * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { Number } handle Handle para o certificado desejado
	 * @returns { Array } Um array ordenado de Uint8Array, onde o elemento 0 corresponde ao certificado de usuário final
	 * e o elemento length - 1 corresponde à AC raiz da cadeia emissora.
	 */
	getCertificateChain(handle) {
		return this.addon.getCertificateChain(handle);
	}

	/**
	 * Obtém o certificado emissor do certificado especificado
	 * @param { Uint8Array } cert Certificado cujo emissor é desejado, codificado em DER
	 * @returns { Array } Um array, possivelmente vazio, de objetos Uint8Array, contendo a codificação DER dos certificados
	 * encontrados nos repositórios CA e Root do Windows cujo campo subject sejam iguais ao campo issuer do certificado
	 * fornecido como parâmetro.
	 */
	getIssuerOf(cert) {
		return this.addon.getIssuerOf(cert);
	}
}

module.exports = {
	SignMechanism: SignMechanism,
	Enroll:        Enroll,
	Sign:          Sign
}