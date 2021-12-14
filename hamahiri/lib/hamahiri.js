/**
 * @file Módulo nativo Node.js para acesso aos dispositivos criptográficos
 * @copyright Copyleft &copy; 2021 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';
const addon = require('../build/Release/hamahiri-native');

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
 * @property { Uint8Array } privKey - Chave pública (campo SubjectPublicKeyInfo do PKCS #10) encodada em DER
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
	 * @default
	 */
	static CKM_SHA1_RSA_PKCS   = 0x00000006;

	/**
	 * Constante para o algoritmo sha256WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default
	 */
	static CKM_SHA256_RSA_PKCS = 0x00000040;

	/**
	 * Constante para o algoritmo sha384WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default
	 */
	static CKM_SHA384_RSA_PKCS = 0x00000041;

	/**
	 * Constante para o algoritmo sha512WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default
	 */
	static CKM_SHA512_RSA_PKCS = 0x00000042;
}

/**
 * Implementa as operações de acesso a dispositivos criptográficos
 * @memberof Hamahiri
 */
 class Hamahiri
{
	constructor() { this._addon = new addon.Hamahiri(); }

	/**
	 * Assina o buffer contendo o hash do conteúdo
	 * @throws  { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param   { Uint8Array    } hash      Hash do conteúdo. Deve ter o tamanho apropriado às chaves RSA e ao algoritmo especificado.
	 * @param   { SignMechanism } algorithm Constante PKCS #11 do algoritmo de assinatura
	 * @param   { Number        } key       Handle para a chave privada de assinatura, obtido previamente
	 * @returns { Uint8Array } Buffer assinado.
	 */
	 sign(hash, algorithm, key) {
		return this._addon.sign(hash, algorithm, key);
	}

	/**
	 * Libera o handle para uma chave privada
	 * @throws  { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { Number } hHandle Handle retornado anteriormente
	 * @returns { boolean } Indicador de sucesso
	 */
	 releaseKeyHandle(hHandle) {
		return this._addon.releaseKeyHandle(hHandle);
	}

	/**
	 * Remove do repositório criptográfico um par de chaves criado por generateKeyPair
	 * @throws {Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de argumentos inválidos
	 * @param { Number } key Handle para a chave gerada, obtido por {@link Enroll.generateKeyPair}
	 * @returns Indicador de sucesso da operação. Uma chave inexistente não é considerada uma falha.
	 */
	 deleteKeyPair(key) {
		return this._addon.deleteKeyPair(key);
	}
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
		return this._addon.enumerateDevices();
	};

	/**
	 * Gera um par de chaves RSA
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { string } device  Cryptographic Service Provider a ser utilizado para gerar as chaves
	 * @param { Number } keySize Tamanho (em bits) das chaves RSA
	 * @returns { KeyPair } Retorna o par de chaves gerado como uma instância de {@link Hamahiri.KeyPair}.
	 */
	generateKeyPair(device, keySize) {
		return this._addon.generateKeyPair(device, keySize);
	}

	/**
	 * Instala o certificado de usuário, caso a chave pública esteja associada a uma chave privada existente
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { Uint8Array } userCertificate Certificado do usuário codificado em DER
	 * @returns { boolean } Indicador de sucesso da operação. Caso o certificado tenha sido instalado
	 * anteriormente, retorna false
	 */
	 installCertificate(userCert) {
		return this._addon.installCertificate(userCert);
	}

	/**
	 * Instala a cadeia de certificados emissores confiáveis. Deve-se verificar previamente se a cadeia é válida e se sua
	 * AC final assinou um certificado de usuário com instalação prévia bem sucedida.
	 * @throws { Failure } Dispara uma instância de {@link Hamahiri.Failure} em caso de falha
	 * @param { Array } chain  Cadeia de certificados codificada em DER, representada como uma matriz de Uint8Array
	 * @returns { boolean } Indicador de sucesso da operação. Caso a cadeia tenha sido instalada
	 * anteriormente, retorna false
	 */
	 installChain(chain) {
		return this._addon.installChain(chain);
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
		return this._addon.enumerateCertificates();
	}
}

module.exports = {
	SignMechanism: SignMechanism,
	Enroll:        Enroll,
	Sign:          Sign
}
