/**
 * @file Cliente web do serviço Hekura.
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { PromiseRejected, urlHekura } from './api.js';
import { HekuraEnroll, HekuraSign, HekuraVerify } from './xapiripe.js';
import { KryptoniteEnroll, KryptoniteSign, KryptoniteVerify } from './kryptonite.js';
import { Base64, Deflate, Inflate } from './fittings.js';

/**
 * API de acesso ao serviço Hekura. Em modo de compatibilidade, pode acessar funcionalidade equivalente à API das
 * extensões Kryptonite (ver https://bitbucket.org/yakoana/kryptonite.git).
 * Atenção: deve ser acessado somente após o evento window.load
 * @namespace
 */
export var xabo = {
	
	/**
	 * Constante para o algoritmo sha1WithRSAEncryption
	 * @constant
	 * @type { Number }
	 * @default 0x00000006
	 */
	CKM_SHA1_RSA_PKCS: 0x00000006,

	/**
	 * Constante para o algoritmo sha256WithRSAEncryption
	 * @constant
	 * @type { Number }
	 * @default 0x00000040
	 */
	CKM_SHA256_RSA_PKCS: 0x00000040,

	/**
	 * Constante para o algoritmo sha384WithRSAEncryption
	 * @constant
	 * @type { Number }
	 * @default 0x00000041
	 */
	CKM_SHA384_RSA_PKCS: 0x00000041,

	/**
	 * Constante para o algoritmo sha512WithRSAEncryption
	 * @constant
	 * @memberof Hamahiri
	 * @type { Number }
	 * @default 0x00000042
	 */
	CKM_SHA512_RSA_PKCS: 0x00000042,

	/**
	 * Indica que o assinante reconhece a criação, a aprovação e o envio do documento assinado
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.6.1
	 */
	proofOfOrigin: '1.2.840.113549.1.9.16.6.1',

	/**
	 * Indica que o assinante recebeu o conteúdo assinado
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.6.2
	 */
	proofOfReceipt: '1.2.840.113549.1.9.16.6.2',

	/**
	 * Indica que um Trusted Service Provider sinalizou ao destinatário a entrega do conteúdo assinado
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.6.3
	 */
	proofOfDelivery: '1.2.840.113549.1.9.16.6.3',

	/**
	 * Indica que o assinante enviou o conteúdo, mas não necessariamente o criou
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.6.4
	 */
	proofOfSender: '1.2.840.113549.1.9.16.6.4',

	/**
	 * Indica que o assinante aprova o conteúdo assinado
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.6.5
	 */
	proofOfApproval: '1.2.840.113549.1.9.16.6.5',

	/**
	 * Indica que o assinante criou o conteúdo, mas não necessariamente o enviou ou aprovou
	 * @member { String }
	 * @default 1.2.840.113549.1.9.16.6.6
	 */
	proofOfCreation: '1.2.840.113549.1.9.16.6.6',

	/**
	 * Valor da propriedade QueryResult.code.
	 * Operação bem sucedida (API retornada)
	 * @member { Number }
	 * @default 0
	 */
	querySuccess: 0,

	/**
	 * Valor da propriedade QueryResult.code.
	 * Serviço Hekura não localizado. Implica na busca das extensões Kryptonite
	 * @member { Number }
	 * @default 1
	 */
	queryHekuraNotFound: 1,

	/**
	 * Valor da propriedade QueryResult.code.
	 * Serviço Hekura localizado mas ocorreu falha na obtenção da especificação YAML. Nenhuma API é retornada
	 * @member { Number }
	 * @default 2
	 */
	queryHekuraFailure: 2,

	/**
	 * Valor da propriedade QueryResult.code.
	 * Serviço Hekura com versão menor que a desejada. Nenhuma API é retornada
	 * @member { Number }
	 * @default 3
	 */
	queryHekuraWrongVersion: 3,

	/**
	 * Valor da propriedade QueryResult.code.
	 * Nenhum cliente localizado. Nenhuma API é retornada
	 * @member { Number }
	 * @default 4
	 */
	queryNoAPIFound: 4,

	/**
	 * Sinal informativo da API em uso: Xapiripe
	 * @member { String }
	 * @default Xapiripe
	 */
	signetXapiripe: 'Xapiripe',

	/**
	 * Sinal informativo da API em uso: Kryptonite
	 * @member { String }
	 * @default Kryptonite
	 */
	signetKryptonite: 'Kryptonite',

	/**
	 * Obtém a API correspondente ao cliente instalado. A função sempre tenta determinar primeiro se o serviço
	 * Hekura está instalado. Se não estiver instalado (ou a origem do script não estiver autorizada), isto é,
	 * se o fetch da URL Hekura falhar, ela então determina se pelo menos uma das extensões criptográficas
	 * Kryptonite está instalada.
	 * @param { boolean } compatibilityMode Indicador da necessidade de agregar à API métodos de compatibilidade
	 * com as extensões Kryptonite (de conversão para Base64 e compressão de dados). Opcional. Valor default: false.
	 * @param { String } version Número da menor versão do serviço Hekura requerida para o retorno da API. Se este
	 * parâmetro for passado, a função obtém a especificação YAML do serviço e determina se a versão ali 
	 * declarada é maior ou pelo menos igual à solicitada. Neste caso, se houve falha na obtenção do corpo da
	 * resposta HTTP ao fetch (ou se a versão não for a pretendida), a função retorna um erro.
	 * @returns Promise que, quando resolvida, retorna uma instância do objeto {@link API}. Se a resolução da 
	 * Promise for uma falha, retorna uma instância do objeto {@link QueryResult}.
	 */
	queryInterface: function(compatibilityMode = false, version = '') {

		const HEKURA_NOT_FOUND_MSG = 'O serviço Hekura não foi encontrado. É possível que ele esteja instalado mas que o presente site não tenha sido autorizado pelo usuário. Verificando a instalação das extensões Kryptonita...';
		const HEKURA_FAILURE_MSG = 'O serviço Hekura foi encontrado mas retornou o código HTTP %s. Impossível continuar.';
		const HEKURA_GET_FAILURE_MSG = 'Ocorreu a seguinte falha ao obter a especificação do serviço Hekura: %s. Impossível continuar.';
		const WRONG_HEKURA_VERSION_MSG = 'O serviço Hekura %s está instalado mas a versão menor desejada não é suportada.';
		const NO_API_FOUND_MSG = 'Nem o serviço Hekura nem as extensões Kryptonita estão instaladas e/ou configuradas apropriadamente. Impossível utilizar os serviços criptográficos.';

		/**
		 * Fornece acesso às APIs Xapiripe ou Kryptonite. As três últimas propriedades só são retornadas caso
		 * seja desejado o modo de compatibilidade com a Kryptonite.
		 * @property { String } signet Identificador do cliente utilizado, isto é: Xapiripe ou Kryptonite
		 * @property { Object } enroll Instância do objeto Enroll. No caso da API Kryptonite esta propriedade
		 * pode estar indefinida, caso o usuário não tenha instalado a extensão emissão de certificados digitais.
		 * No caso da API Xapiripe, a propriedade é sempre definida.
		 * @property { Object } sign Instância do objeto Sign. No caso da API Kryptonite esta propriedade
		 * pode estar indefinida, caso o usuário não tenha instalado a extensão de assinatuas digitais.
		 * No caso da API Xapiripe, a propriedade é sempre definida.
		 * @property { Object } verify Instância do objeto Verify. No caso da API Kryptonite esta propriedade
		 * pode estar indefinida, caso o usuário não tenha instalado a extensão verificação de assinaturas digitais.
		 * No caso da API Xapiripe, a propriedade é sempre definida.
		 * @property { Object } base64 Instância do objeto Base64. Esta propriedade só estará definida se a função
		 * {@link queryInterface} for executada no mode de compatabilidade.
		 * @property { Object } deflater Instância do objeto Deflate. Esta propriedade só estará definida se a função
		 * {@link queryInterface} for executada no mode de compatabilidade.
		 * @property { Object } inflater Instância do objeto Inflate. Esta propriedade só estará definida se a função
		 * {@link queryInterface} for executada no mode de compatabilidade.
		 */
		class API {
			/**
			 * Não exportado
			 */
			constructor(signet, enroll, sign, verify) {
				this.signet = signet;
				this.enroll = enroll;
				this.sign = sign;
				this.verify = verify;
			}
		}
		class XapiripeAPI extends API {
			constructor() {
				super(xabo.signetXapiripe, new HekuraEnroll(), new HekuraSign(), new HekuraVerify());
			}
		}
		class KryptoniteAPI extends API {
			constructor(enroll, sign, verify) {
				super(xabo.signetKryptonite, enroll, sign, verify);
			}
		}
		class QueryResult {
			constructor(code, msg) {
				this.code = code;
				this.message = msg;
			}
		}

		function checkVersion(schema, version) {
			try {
				function compare(va, vb) {
					let a = Number.parseInt(va);
					let b = Number.parseInt(vb);
					if (isNaN(a) || isNaN(b)) throw new Error('Invalid version number');
					return a - b;
				}
				function greaterOrEquals(target, source) {
					let i = 0, j = 0;
					while (i < source.length && j == 0) {
						j = compare(target[i], source[i]);
						if (j < 0) return false;
						if (j > 0) return true;
						i++;
					}
					return true;
				}
				let ob = JSON.parse(schema);
				if (!ob.openapi || !ob.info || !ob.info.version) throw new Error('Schema is not a valid OpenAPI specification');
				let target = ob.info.version.split('.');
				let source = version.split('.');
				if (target.length != 3 || source.length > target.length) throw new Error('Invalid version number');
				if (greaterOrEquals(target, source)) return new QueryResult(xabo.querySuccess);
				else new QueryResult(xabo.queryHekuraWrongVersion, WRONG_HEKURA_VERSION_MSG.replace('%s', ob.info.version));
			}
			catch (e) { return new QueryResult(xabo.queryHekuraFailure, HEKURA_GET_FAILURE_MSG.replace('%s', e.toString())); }
		}
		function hekuraCheck(version = '') {
			return new Promise((resolve, reject) => {
				window.fetch(urlHekura, { method: 'GET', mode: 'cors', cache: 'no-store' }).then((response) => {
					if (response.ok) {
						if (version.length > 0) {
							response.text().then((value) => {
								let ret = checkVersion(value, version);
								if (ret.code == xabo.querySuccess) return resolve(new XapiripeAPI());
								else return reject(ret);
							})
							.catch((reason) => { return reject(new QueryResult(xabo.queryHekuraFailure, HEKURA_GET_FAILURE_MSG.replace('%s', reason.toString())))});
						}
						else return resolve(new XapiripeAPI());
					}
					else return reject(new QueryResult(xabo.queryHekuraFailure, HEKURA_FAILURE_MSG.replace('%s', response.status.toString())));
				})
				.catch(() => { return reject(new QueryResult(xabo.queryHekuraNotFound, HEKURA_NOT_FOUND_MSG)); });
			});
		}
		function kryptoniteCheck() {
			let ret;
			let enroll;
			let sign;
			let verify;
			if (typeof kptaenroll !== 'undefined') enroll = new KryptoniteEnroll(kptaenroll);
			if (typeof kptasign   !== 'undefined') sign = new KryptoniteSign(kptasign);
			if (typeof kptaverify !== 'undefined') verify = new KryptoniteVerify(kptaverify);
			if (
				typeof enroll !== 'undefined' ||
				typeof sign   !== 'undefined' ||
				typeof verify !== 'undefined'
			)	ret = new KryptoniteAPI(enroll, sign, verify);
			return ret;
		}
		function addCompatibilityProperties(api) {
			return Object.defineProperties(api, {
				base64:   { value: new Base64()  },
				deflater: { value: new Deflate() },
				inflater: { value: new Inflate() }
			});
		}
		
		return new Promise((resolve, reject) => {
			let api = xabo.queryInterface.api;
			if (typeof api !== 'undefined') return resolve(xabo.queryInterface.api);
			hekuraCheck(version).then((hekuraObject) => {
				api = hekuraObject;
				if (compatibilityMode) api = addCompatibilityProperties(api);
				xabo.queryInterface.api = api;
				return resolve(xabo.queryInterface.api);
			}).catch((reason) => {
				switch (reason.code) {
				case xabo.queryHekuraNotFound:
					console.log(reason.message);
					api = kryptoniteCheck();
					if (typeof api === 'undefined') return reject(new PromiseRejected(xabo.queryNoAPIFound, NO_API_FOUND_MSG));
					break;
				default: return reject(new PromiseRejected(reason.code, reason.message));
				}
				if (compatibilityMode) api = addCompatibilityProperties(api);
				xabo.queryInterface.api = api;
				return resolve(xabo.queryInterface.api);
			});
		});
	}	
};

