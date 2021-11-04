'use strict';

/**
 * @file Módulo nativo Node.js para acesso aos dispositivos criptográficos
 * @copyright Copyleft &copy; 2021 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

/**
 * Referência externa à API Node para C++
 * @namespace Napi
 */
/**
 * Referência externa à classe Napi::Error (implementa a classe Javascript Error)
 * @class Error
 * @memberof Napi
 */

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
 * @property { string } serial  - Número de série do certificado, encodado em Base64
 * @property { Number } handle  - Handle para acesso à chave privada associada ao certificado
 */

/**
 * Acesso aos dispositivos criptográficos instalados no computador local
 * @namespace Hamahiri
 */


/**
 * Constante para o algoritmo sha1WithRSAEncryption
 * @constant
 * @memberof Hamahiri
 * @type { Number }
 * @default
 */
const CKM_SHA1_RSA_PKCS = 0x00000006;
/**
 * Constante para o algoritmo sha256WithRSAEncryption
 * @constant
 * @memberof Hamahiri
 * @type { Number }
 * @default
 */
 const CKM_SHA256_RSA_PKCS = 0x00000040;
/**
 * Constante para o algoritmo sha384WithRSAEncryption
 * @constant
 * @memberof Hamahiri
 * @type { Number }
 * @default
 */
 const CKM_SHA384_RSA_PKCS = 0x00000041;
/**
 * Constante para o algoritmo sha512WithRSAEncryption
 * @constant
 * @memberof Hamahiri
 * @type { Number }
 * @default
 */
 const CKM_SHA512_RSA_PKCS = 0x00000042;
/**
 * Constante PKCS #11 para os algoritmos de assinatura suportados
 * @memberof Hamahiri
 * @typedef { Number } SignMechanism
 */


/**
 * Detalhamento dos erros ocorridos no processamento nativo
 * @extends Napi.Error
 * @memberof Hamahiri
 * @property { string } component - Componente que disparou o erro
 * @property { string } method    - Método ou função que disparou o erro
 * @property { Number } errorCode - Código Xapiripë do erro
 * @property { Number } apiError  - Código do erro gerado pela API de terceiros (por exemplo, a Windows CryptoAPI)
 */
class Failure extends Error
{
	component;
	method;
	errorCode;
	apiError;
}

/**
 * Representação interna de um par de chaves RSA
 * @memberof Hamahiri
 * @property { Uint8Array } privKey - Chave pública (campo SubjectPublicKeyInfo do PKCS #10) encodada em DER
 * @property { Number     } privKey - Handle para a chave privada
 */
class KeyPair
{
	pubKey;
	privKey;
}


/**
 * Implementa as operações de acesso a dispositivos criptográficos
 * @memberof Hamahiri
 */
class Hamahiri
{
	/**
	 * Assina o buffer contendo o hash do conteúdo
	 * @throws  { Failure } Dispara uma instância de Failure em caso de falha
	 * @param   { Uint8Array    } hash      Hash do conteúdo. Deve ter o tamanho apropriado às chaves RSA e ao algoritmo especificado.
	 * @param   { SignMechanism } algorithm Constante PKCS #11 do algoritmo de assinatura
	 * @param   { Number        } key       Handle para a chave privada de assinatura, obtido previamente
	 * @returns { Uint8Array } Buffer assinado.
	 */
	sign() {}
}

/**
 * Operações de emissão de certificados (enrollment)
 * @memberof Hamahiri
 * @extends Hamahiri
 */
class Enroll extends Hamahiri
{

	/**
	 * Enumera os dispositivos criptográficos presentes (Cryptographic Services Providers para RSA)
	 * @throws { Failure } Dispara uma instância de Failure em caso de falha
	 * @return { Array } Lista de strings contendo os nomes dos dispositivos presentes
	 */
	enumerateDevices() {}

	/**
	 * Gera um par de chaves RSA
	 * @throws { Failure } Dispara uma instância de Failure em caso de falha
	 * @param { string } device  Cryptographic Service Provider a ser utilizado para gerar as chaves
	 * @param { Number } keySize Tamanho (em bits) das chaves RSA
	 * @returns { KeyPair } Retorna o par de chaves gerado como uma instância de {@link Hamahiri.KeyPair}.
	 */
	generateKeyPair() {};

	/**
	 * Instala o certificado de usuário, caso a chave pública esteja associada a uma chave privada existente
	 * @throws { Failure } Dispara uma instância de Failure em caso de falha ou caso o certificado não possa
	 * ser associado a uma chave existente
	 * @param { Uint8Array } userCertificate Certificado do usuário codificado em DER
	 * @returns { boolean } Indicador de sucesso da operação. Caso o certificado tenha sido instalado
	 * anteriormente, retorna false
	 */
	installCertificate() {}

	/**
	 * Instala a cadeia de certificados de Autoridade Certificadora emissora de um certificado
	 * previamente instalado.
	 * @throws { Failure } Dispara uma instância de Failure em caso de falha ou caso a cadeia não corresponda
	 * a um certificado de usuário instalado
	 * @param { Array } chain  Cadeia de certificados codificada em DER, representada como uma matriz de Uint8Array
	 * @returns { boolean } Indicador de sucesso da operação. Caso a cadeia tenha sido instalada
	 * anteriormente, retorna false
	 */
	installChain() {}
}

/**
 * Implementa a assinatura digital de documentos
 * @memberof Hamahiri
 * @extends Hamahiri
 */
class Sign extends Hamahiri
{
	/**
	 * Enumera os certificados em vigor que estejam associados a chaves privadas RSA nos repositórios criptográficos
     * @throws { Failure } Dispara uma instância de Failure em caso de falha
	 * @returns { Array } Um array de objetos {@link Xapiripe.Certificate}
	 */
	enumerateCertificates() {}
}
