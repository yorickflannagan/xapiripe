/**
 * @file Especificação das interfaces da API Xapiripe. Esta API assegura compatibilidade com as
 * extensões criptográficas da Kryptonite (ver https://bitbucket.org/yakoana/kryptonite.git)
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';


/**
 * Objeto retornado em caso de Promise rejeitada informando o conteúdo da falha.
 * Destinado a manter compatibilidade com a API Kryptonite.
 * @property { Number } result Resultado da operação. Sempre 1, indicando falha.
 * @property { Number } reason Código de erro. No caso da Kryptonite, um dos códigos estruturados fornecidos pelo produto;
 * no caso do serviço Hekura, o status code HTTP.
 * @property { String } statusText Linha de status HTTP no caso do serviço Hekura. Para a API Kryptonite o campo não
 * está presente
 */
export class PromiseRejected {

	/**
	 * Cria uma nova instância do objeto
	 * @param { Number } reason Código de erro ou de status
	 * @param { Number } statusText Linha de status HTTP, se definido
	 */
	constructor(reason, statusText) {
		this.result = 1;
		this.reason = reason;
		this.statusText = statusText;
	}
}

/**
 * Fornece acesso às funcionalidades de emissão de certificados digitais
 */
export class Enroll {

	/**
	 * Enumera os dispositivos criptográficos presentes (Cryptographic Services Providers para RSA)
	 * @returns uma Promise que, quando resolvida, entrega um array de strings, onde cada item é o nome dado
	 * pelo fabricante ao CSP, conforme instalação do Windows
	 */
	enumerateDevices() {
		return Promise.resolve([ 'array de nomes de CSP' ]);
	}

	/**
	 * Gera um par de chaves RSA e assina uma requisição de certificado digital.
	 * @param { Aroari.EnrollOptions } options Parâmetros para operação, onde:
	 * <ul>
	 * 	<li>
	 * 	device: Cryptographic Service Provider ou Key Storage Provider que a ser utilizado para gerar
	 * 	as chaves RSA. Deve corresponder exatamente a um dos dispositivos retornados por
	 * 	{@link enumerateDevices}
	 *	</li>
		* 	<li>keySize: Tamanho (em bits) das chaves RSA a serem geradas. Opcional. Default: 2048</li>
		* 	<li>
		* 	signAlg - Algoritmo a ser utilizado na assinatura da requisição de certificado. Opcional.
		* 	Default: CKM_SHA256_RSA_PKCS
		* 	</li>
		* 	<li>rdn: Nome distinto do titular do certificado</li>
		* </ul>
		* <p>Para o RDN, os parâmetros são:</p>
		* <ul>
		* 	<li>c: País da AC (country). Opcional</li>
		* 	<li>o: Organização da Autoridade Certificadora (organization). Opcional</li>
		* 	<li>ou: Unidade organizacional da Autoridade Certificadora (organization unit). Opcional</li>
		* 	<li>cn: Nome comum do titular do certificado (common name). Obrigatório</li>
		* </ul>
		* @returns Promise que, quando resolvida, retorna um PKCS #10 codificado em Base64 no formato PEM.
		*/
	generateCSR(options) {
		return Promise.resolve('PKCS #10 codificado em Base64 no formato PEM');
	}

	/**
	 * Instala o certificado assinado e sua cadeia. O certificado de usuário final somente é instalado se for
	 * encontrada uma chave privada associada à sua chave pública no repositório do Windows. Toda a cadeia de
	 * certificados é criptograficamente verificada antes de sua instalação, sendo requerido o certificado
	 * de uma AC raiz.
	 * @param   { String   } pkcs7 Documento PKCS #7 codificado em Base64 de acordo com a convenção PEM, emitido pela 
	 * AC para transporte do certificado do titular e a cadeia de Autoridades Certificadoras associada.
	 * @throws  { APIError } Dispara uma instância de {@link Aroari.APIErrors} em caso de falha.
	 * @returns Promise que, quando resolvida, retorna true se toda a cadeia de certificados de AC for
	 * instalada; caso um dos certificados de AC já esteja presente no repositório do Windows, retorna false.
	 */
	installCertificates(pkcs7) {
		return Promise.resolve(true);
	}
}

/**
 * Fornece acesso às funcionalidades de assinaturas digitais
 */
export class Sign {

	/**
	 * Enumera os certificados em vigor que estejam associados a chaves privadas RSA nos repositórios criptográficos
	 * @returns uma Promise que, quando resolvida, retorna um array de objetos descritivos de um certificado, a saber:
	 * <ul>
	 * 	<li>subject: Titular do certificado</li>
	 * 	<li>issuer: Emissor do certificado</li>
	 * 	<li>serial: Número de série do certificado, onde os bytes são representados em hexadecimal</li>
	 * 	<li>handle: Handle numérico para acesso à chave privada associada ao certificado</li>
	 * </ul>
	 */
	enumerateCerts() {
		return Promise.resolve([ { subject: '', issuer: '', serial: '', handle: Number.MIN_VALUE } ]);
	}

	/**
	 * Assina digitalmente um documento ou transação
	 * @param { Object } options Parâmetros para a operação, onde:
	 * <ul>
	 * 	<li>certificate: certificado de assinatura, retornado por {@link enumerateCerts}</li>
	 * 	<li>toBesigned: Documento ou transação a ser assinada. Pode tanto ser uma string quanto um ArrayBuffer</li>
	 * 	<li>attach: Indica se o documento toBeSigned deve ser anexado ao envelope CMS Signed Data. Opcional. Default: true</li>
	 * 	<li>algorithm> Constante indicativa do algoritmo de assinatura a ser utilizado. Opcional. Default: CKM_SHA256_RSA_PKCS</li>
	 * 	<li>cades: Oções CAdES da assinatura. Opcional</li>
	 * </ul>
	 * <p>Para a opção cades, os parâmetros são:</p>
	 * <ul>
	 * 	<li>policy: Tipo de política de assinatura. Valor default: CAdES-BES</li>
	 * 	<li>addSigningTime: Indicador de inclusão atributo assinado Signing Time. Opcional. Valor default: true</li>
	 * 	<li>commitmentType: Se contiver um valor descritivo, inclui o OID do atributo assinado Commitment
 	 * 	Type Indication. Valor default: proofOfSender</li>
	 * </ul>
	 * @returns Promise que, quando resolvida, retorna um documento PKCS#7 codificado em base64 no formato PEM
	 */
	sign(options) {
		return Promise.resolve('PKCS#7 codificado em base64 no formato PEM');
	}
}

/**
 * Fornece acesso às funcionalidades de verificação de assinaturas digitais
 */
export class Verify {

	/**
	 * 
	 * @param { Object } options Parâmetros para a verficação, a saber:
	 * <ul>
	 * 	<li>pkcs7: Documento CMS Signed Data para ser verificado. Obrigatório;</li>
	 * 	<li>signingCert: Certificado de assinatura. Opcional. Se não informado, o certificado de assinatura, deve estar embarcado no documento CMS;</li>
	 * 	<li>eContent: Conteúdo assinado. Opcional. Se não informado, deve estar embarcado no documento CMS;</li>
	 * 	<li>verifyTrustworthy: Indicador de verificação da confiabilidade do certificado do assinante. Se não estiver presente assume-se o valor false.</li>
	 * 	<li>
	 * 	getSignerIdentifier: Indicador de que é requerido para que a operação devolva, na sua resposta, o campo de identificação do assinante.
	 * 	Se não estiver presente assume-se o valor false;
	 * 	</li>
	 * 	<li>
	 * 	getSignedContent: Indicador de que é requerido para que a operação devolva, na sua resposta, o valor do campo EncapsulatedContentInfo.
	 * 	Se não estiver presente assume-se o valor false;
	 * 	</li>
	 * 	<li>
	 * 	getSigningTime: Indicador de que é requerido que a operação devolva, na sua resposta, o atributo assinado SigningTime, se existir
	 * 	no documento.  Se não estiver presente assume-se o valor false.
	 * 	</li>
	 * </ul>
	 * <p>Na especificação da interface REST, os campos pkcs7, signingCert e eContent estão definidos como um objeto AltString, onde:</p>
	 * <ul>
	 * 	<li>
	 * 	data: A representação dos dados. Pode ser do tipo ArrayBuffer ou String. Se do tipo string, pode estar codificado em Base64 conforme
	 * 	indicado na propriedade binary;
	 * 	</li>
	 * 	<li>
	 * 	binary: Indicador de dado binário (codificado em Base64) ou string. Se não estiver presente, este indicador é inferido do
	 * 	tipo de dado da propriedade data: se ArrayBuffer, é inferido como true; se String, é inferido como false.
	 * 	</li>
	 * </ul>
	 * @returns um objeto indicando a resposta ás várias requisições contidas nos parâmetros de entrada, a saber:
	 * <ul>
	 * 	<li>signatureVerification: Indica o resultado da verificação criptográfica da assinatura;</li>
	 * 	<li>messageDigestVerification: Indica o resultado da verificação do atributo assinado Message Digest;</li>
	 * 	<li>signingCertVerification: Indica o resultado da verificação do atributo assinado ESS signing-certificate-v2, se presente;</li>
	 * 	<li>certChainVerification: Indica o resultado da verificação da confiabilidade do certificado do assinante, se solicitada;</li>
	 * 	<li>eContent: Conteúdo assinado, caso tenha sido solicitado. Se presente é um objeto do tipo AltString;</li>
	 * 	<li>signerIdentifier: Identificação do assinante, se solicitada</li>
	 * 	<li>signingTime: Valor do atributo assinado SigningTime, se solicitado (e presente no documento CMS).</li>
	 * </ul>
	 * <p>Se solicitado, o campo signerIdentifier é retornado como presente no documento CMS, a saber:</p>
	 * <ul>
	 * 	<li>issuer: o emissor do certificado, caso a identificação do assinante esteja representada por um IssuerAndSerialNumber;</li>
	 * 	<li>serial: o número de sério do certificado, se a identificação for um IssuerAndSerialNumber. É representado como um número em hexadecimal;</li>
	 * 	<li>subjectKeyIdentifier: Identificação do assinante pelo hash da chave pública do certificado, codificado em hexadecimal, caso o emissor seja representado assim.</li>
	 * </ul>
	 */
	verify(options) {
		return Promise.resolve({
			signatureVerification: true,
			messageDigestVerification: true,
			signingCertVerification: true,
			certChainVerification: true,
			eContent: { data: null, binary: false },
			signerIdentifier: { issuer: null, serial: null, subjectKeyIdentifier:  null },
			signingTime: new Date()
		});
	}
}

/**
 * Localizador do serviço Hekura
 * @member { String }
 * @default http://127.0.0.1:9171
 */
export const urlHekura = 'http://127.0.0.1:9171';
