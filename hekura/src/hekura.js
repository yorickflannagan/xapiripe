/**
 * @file API criptogrática exposta como serviço HTTP para atendimento às aplicações web
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';
const tcp = require('tcp-port-used');
const http = require('http');
const path = require('path');
const Aroari = require(path.join(__dirname, '..', '..', 'aroari'));
const fs = require('fs');
const Wanhamou = require(path.join(__dirname, '..', '..', 'wanhamou'));
const Logger = Wanhamou.Logger;
const sprintf = Wanhamou.sprintf;


/**
 * Callback chamada sempre que uma operação criptográfica está para ser realizada, visando obter a aprovação do usuário.
 * @callback approvalCallback
 * @param { String } operationId Identificador da operação, conforme especificação OpenAPI do serviço
 * @param { String } referer Valor do header Referer da requisição HTTP recebida
 * @param { String | ArrayBuffer } value Informação apropriada à operação. Por exemplo, o conteúdo a ser assinado
 * @returns { Boolean } Valor lógico indicando a aprovação (ou não) da operação
 */
 function approvalCallback(operationId, referer, value) { return true; }


/**
 * Dispositivo simplificado de log
 * @namespace Wanhamou
 */

/**
 * Opções de inicialização do log
 * @class LogOptions
 * @memberof Wanhamou
 * @property { String } path	Diretório de localização do arquivo de log. Valor default __dirname
 * @property { String } fname	Padrão de nome do log, na forma [nome]-n.[ext], onde nome é o nome e ext a extensão 
 * que se deseja para o arquivo. Valor default xapiripe-n.log
 * @property { Number } maxSize	Tamanho máximo (em KB) do arquivo de log antes de ser obrigado a rotacionar. Valor default: 2048
 * @property { Number } rotate	Quantidade máxima de arquivos de log antes que seja necessário sobrescrever o mais antigo. Valor default: 5
 * @property { Number } level	Nível corrente do log. Serão logados somente as mensagens com valor igual ou maior. Valor default INFO
 */


/**
 * Serviço REST de atendimento aos usuários web da API Criptográfica Aroari
 * @namespace Hekura
 */

/**
 * Detalhamento dos erros ocorridos no processamento
 * @extends Aroari.AroariError
 * @memberof Hekura
 */
class ServiceError extends Aroari.AroariError
{
	/**
	 * Porta de atendimento já em uso
	 * @member { Number }
	 * @default 128
	 */
	static HTTP_PORT_ALREADY_USED = 128;

	/**
	 * Cria uma nova instância do relatório de erros
	 * @param { String } msg Mensagem descritiva
	 * @param { String } method Método ou função onde ocorreu o erro
	 * @param { Number } errorCode Código de erro no módulo
	 * @param { Object } native Objeto de erro do módulo nativo eventualmente propagado, ou null
	 */
	 constructor(msg, method, errorCode, native) { super(msg, method, errorCode, native); }
}

/**
 * Implementação básica da verificação da confiabilidade da origem de uma requisição
 * @memberof Hekura
 */
class CORSBlockade
{
	/**
	 * Cria uma nova instância da verificação de origem
	 * @param { iterable } trusted Set (ou array) de origens confiáveis. Opcional
	 */
	constructor(trusted) {
		this.trustedOrigins = new Set(trusted);
	}

	/**
	 * Adiciona uma nova origem à lista de origens confiáveis
	 * @param { String } origin Origem confiável, na forma [protocolo]://[dominio]:[porta], conforme especificação
	 * <a href = "https://fetch.spec.whatwg.org/#http-origin">W3C</a>
	 */
	addTrustedOrigin(origin) {
		this.trustedOrigins.add(origin);
	}

	/**
	 * Verifica a confiabilidade da origem
	 * @param { Object } headers Cabeçalhos HTTP recebidos na requisição, tal como fornecidos pela propriedade
	 * headers da classe http.IncomingMessage (Node.js)
	 * @returns Indicador de confiabilidade da origem.
	 */
	allowOrigin(headers) {
		let allow = false;
		let origin = headers['origin'];
		if (origin) allow = this.trustedOrigins.has(origin);
		return allow;
	}
}


/**
 * Define a interface de um serviço de atendimento
 * @memberof Hekura
 */
class AbstractService
{
	/**
	 * Cria uma nova instância do serviço de atendimento
	 * @param { String } url Path REST atendido
	 * @param { Number } corsMaxAge O valor em segundos que os preflight requests do protocolo CORS podem ser cacheados.
	 * @param { approvalCallback} callback Função a ser chamada visando obter a aprovação do usuário para a operação criptográfica
	 */
	constructor(url, corsMaxAge, approvalCallback) {
		this.url = url;
		this.maxAge = corsMaxAge;
		this.approvalCallback = approvalCallback;
	}

	/**
	 * Verifica se o serviço suporta o método HTTP especificado
	 * @param { String } method Método HTTP evocado pela requisição
	 * @returns Indicador de suporte ao método
	 */
	accept(method) { return true; }

	/**
	 * Implementa o atendimento à requisição CORS de preflight, conforme especificado em
	 * https://fetch.spec.whatwg.org/#cors-preflight-request
	 * @param { Object } headers Cabeçalhos HTTP recebidos na requisição, tal como fornecidos pela propriedade
	 * headers da classe http.IncomingMessage (Node.js)
	 * @returns { Object } Uma instância do objeto Map com os headers requeridos para a resposta à requisição
	 */
	preflight(headers) { return new Map(); }

	/**
	 * Atende à requisição REST especificada
	 * @param { Object } request Instância de http.IncomingMessage contendo a requisição HTTP
	 * @param { Object } response Instância de http.ServerResponse para fornecimento da resposta HTTP
	 * @param { Buffer } body O corpo da requisição já completamente lido, se algum tiver sido enviado.
	 */
	execute(request, response, body) {}
}

/**
 * Serviço de fornecimento do arquivo YAML de especificação do serviço
 * @extends Hekura.AbstractService
 * @memberof Hekura
 */
class RootService extends AbstractService
{
	constructor(corsMaxAge, approvalCallback) { super('/', corsMaxAge, approvalCallback); }
	accept(method) { return (method === 'GET'); }
	execute(request, response) {
		let logger = Logger.getLogger('RootService');
		let origin = request.headers['origin'];
		let target = path.join(__dirname, 'hekura-schema.json');
		try {
			let schema = fs.readFileSync(target, { encoding: 'utf-8' });
			response.setHeader('Access-Control-Allow-Origin', origin);
			response.setHeader('Content-Type', 'application/json');
			response.write(schema);
			response.statusCode = 200;
			logger.debug(sprintf('Espeficação REST enviada à origem %s: [\r\n%s\r\n]', origin, Wanhamou.beautify(schema)));
		}
		catch (err) {
			logger.debug(sprintf('Ocorreu o seguinte erro ao obter a especificação REST a partir da requisição originada em %s: %s', origin, err.toString()));
			response.statusCode = 500;
		}
		Logger.releaseLogger();
	}
}

const generateCSRProps = new Set([ '', 'device', 'keySize', 'signAlg', 'rdn', 'c', 'o', 'ou', 'cn' ]);
const installCertificatesProps = new Set([ '', 'pkcs7' ]);
/**
 * Serviço de atendimento às operações de emissão de certificado
 * @extends Hekura.AbstractService
 * @memberof Hekura
 */
class EnrollService extends AbstractService
{
	constructor(corsMaxAge, approvalCallback) {
		super('/enroll', corsMaxAge, approvalCallback);
		this.api = new Aroari.Enroll();
	}
	accept(method) { return (method === 'GET') || (method === 'POST') || (method === 'PUT') || (method === 'OPTIONS'); }
	preflight(headers) {
		let ret = new Map();
		ret.set('Access-Control-Allow-Origin', headers['origin']);
		ret.set('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	#processGet(headers, response) {
		let logger = Logger.getLogger('EnrollService');
		let origin = headers['origin'];
		let referer = headers['referer'];
		if (this.approvalCallback('enumerateDevices', referer)) {
			try {
				let devices = this.api.enumerateDevices();
				response.setHeader('Access-Control-Allow-Origin', origin);
				response.setHeader('Content-Type', 'application/json');
				response.write(JSON.stringify(devices));
				response.statusCode = 200;
				logger.debug(sprintf('O serviço enumerateDevices retornou o seguinte objeto à origem %s: %s', origin, JSON.stringify(devices, null, 2)));
			}
			catch (err) {
				logger.error('Ocorreu o seguinte erro ao processar a requisição originada em %s pelo serviço enumerateDevices: %s', origin, err.toString());
				response.statusCode = 500;
			}
		}
		else {
			response.statusCode = 401;
			logger.warn(sprintf('Serviço enumerateDevices originado em %s rejeitado pelo usuário', referer));
		}
		Logger.releaseLogger();
	}
	#processPost(headers, response, body) {
		let logger = Logger.getLogger('EnrollService');
		let origin = headers['origin'];
		let referer = headers['referer'];
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param;
			try {
				param = JSON.parse(body.toString(), (key, value) => {
					if (generateCSRProps.has(key)) return value;
					throw new Error(sprintf('Propriedade não especificada de nome %s foi encontrada', key));
				});
				if (typeof param.device !== 'string') throw new Error('Argumento device inválido');
				if (typeof param.keySize !== 'undefined') {
					if (typeof param.keySize !== 'number') throw new Error('Argumento keySize inválido');
				}
				if (typeof param.signAlg !== 'undefined') {
					if (typeof param.signAlg !== 'number') throw new Error('Argumento signAlg inválido');
				}
				if (typeof param.rdn === 'undefined' || typeof param.rdn.cn !== 'string') throw new Error('Argumento rdn inválido');
			}
			catch (err) {
				logger.warn(sprintf('Ocorreu o seguinte erro ao processar os parâmetros da requisição originada em %s pelo serviço generateCSR: %s', origin, err.toString()))
				Logger.releaseLogger();
				response.statusCode = 400;
				return;
			}
			if (this.approvalCallback('generateCSR', referer)) {
				try {
					let pkcs7 = this.api.generateCSR(param);
					response.setHeader('Access-Control-Allow-Origin', origin);
					response.setHeader('Content-Type', 'text/plain');
					response.write(pkcs7);
					response.statusCode = 200;
					logger.debug(sprintf('O serviço generateCSR respondeu à requisição originada em %s com o seguinte CSR:\r\n%s', origin, pkcs7));
				}
				catch (err) {
					logger.error(sprintf('Ocorreu o seguinte erro ao processar a requisição originada em %s pelo serviço generateCSR: %s', origin, err.toString()));
					if (err.errorCode == Aroari.AroariError.ARGUMENT_ERROR) response.statusCode = 400;
					else response.statusCode = 500;
				}
			}
			else {
				response.statusCode = 401;
				logger.warn(sprintf('Serviço generateCSR originado em %s rejeitado pelo usuário', referer));
			}
		}
		else {
			response.statusCode = 415;
			logger.warn(sprintf('Tipo de conteúdo %s originado em %s não suportado pelo serviço generateCSR', ctype, origin));
		}
		Logger.releaseLogger();
	}
	#processPut(headers, response, body) {
		let logger = Logger.getLogger('EnrollService');
		let origin = headers['origin'];
		let referer = headers['referer'];
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param;
			try {
				let json = JSON.parse(body.toString(), (key, value) => {
					if (installCertificatesProps.has(key)) return value;
					throw new Error(sprintf('Propriedade não especificada %s encontrada', key));
				});
				if (typeof json.pkcs7 !== 'string') throw new Error('Argumento pkcs7 inválido');
				let b64 = json.pkcs7
					.replace('-----BEGIN PKCS7-----', '')
					.replace('-----END PKCS7-----', '')
					.replace('-----BEGIN CMS-----', '')
					.replace('-----END CMS-----', '')
					.replace(/\r?\n|\r|\n|\n/g, '');
				param = Aroari.Base64.atob(b64);
			}
			catch (err) {
				logger.warn(sprintf('Ocorreu o seguinte erro ao processar os parâmetros da requisição originada em %s pelo serviço installCertificates: %s', origin, err.toString()));
				response.statusCode = 400;
				Logger.releaseLogger();
				return;
			}
			if (this.approvalCallback('installCertificates', referer)) {
				try {
					let done = this.api.installCertificates(param);
					response.setHeader('Access-Control-Allow-Origin', origin);
					if (done) response.statusCode = 201;
					else response.statusCode = 200;
					logger.debug(sprintf('Código HTTP %s retornado à requisição originada em %s pelo serviço installCertificates', response.statusCode.toString(), origin));
				}
				catch (err) {
					logger.error(sprintf('Ocorreu o seguinte erro ao processar a requisição originada em %s pelo serviço installCertificates: %s', origin, err.toString()));
					if (err.errorCode == Aroari.AroariError.ARGUMENT_ERROR) response.statusCode = 400;
					else if (
						err.errorCode == Aroari.AroariError.INSTALL_SIGNER_CERT_ERROR ||
						err.errorCode == Aroari.AroariError.CERTIFICATE_CHAIN_VERIFY_ERROR
					)	response.statusCode = 451;
					else response.statusCode = 500;
				}
			}
			else {
				response.statusCode = 401;
				logger.warn(sprintf('Serviço installCertificates originado em %s rejeitado pelo usuário', referer));
			}
		}
		else {
			response.statusCode = 415;
			logger.warn(sprintf('Tipo de conteúdo %s originado em %s não suportado pelo serviço installCertificates', ctype, origin));
		} 
		Logger.releaseLogger();
	}
	execute(request, response, body) {
		const { method, headers } = request;
		if      (method === 'GET')  this.#processGet(headers, response);
		else if (method === 'POST') this.#processPost(headers, response, body);
		else if (method === 'PUT')  this.#processPut(headers, response, body);
		else response.statusCode = 405;
	}
}


const signProps = new Set([ '', 'handle', 'toBeSigned', 'data', 'binary', 'attach', 'algorithm', 'cades', 'policy', 'addSigningTime', 'commitmentType' ]);
/**
 * Serviço de atendimento às operações de assinatura digital
 * @extends Hekura.AbstractService
 * @memberof Hekura
 */
class SignService extends AbstractService
{
	constructor(corsMaxAge, approvalCallback) {
		super('/sign', corsMaxAge, approvalCallback);
		this.api = new Aroari.Sign();
	}
	accept(method) { return (method === 'GET') || (method === 'POST') || (method === 'OPTIONS'); }
	preflight(headers) {
		let ret = new Map();
		ret.set('Access-Control-Allow-Origin', headers['origin']);
		ret.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	#processGet(headers, response) {
		let logger = Logger.getLogger('SignService');
		let referer = headers['referer'];
		let origin = headers['origin'];
		if (this.approvalCallback('enumerateCertificates', referer)) {
			try {
				let certs = this.api.enumerateCertificates();
				response.setHeader('Access-Control-Allow-Origin', origin);
				response.setHeader('Content-Type', 'application/json');
				response.write(JSON.stringify(certs));
				response.statusCode = 200;
				logger.debug(sprintf('O serviço enumerateCertificates retornou o seguinte objeto à requisição originada em %s: %s', origin, JSON.stringify(certs, null, 2)));
			}
			catch (err) {
				logger.debug(sprintf('Ocorreu o seguinte erro no processamento originado em %s pelo serviço enumerateCertificates: %s', origin, err.toString()));
				response.statusCode = 500;
			}
		}
		else {
			response.statusCode = 401;
			logger.warn(sprintf('A requisição do serviço enumerateCertificates originada em %s foi rejeitada pelo usuário', referer));
		}
		Logger.releaseLogger();
	}
	#processPost(headers, response, body) {
		let logger = Logger.getLogger('SignService');
		let referer = headers['referer'];
		let origin = headers['origin'];
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param = new Object();
			try {
				let json = JSON.parse(body.toString(), (key, value) => {
					if (signProps.has(key)) return value;
					throw new Error(sprintf('Propriedade não especificada %s encontrada', key));
				});
				if (typeof json.handle !== 'number') throw new Error('Argumento handle inválido');
				param = Object.defineProperty(param, 'handle', { value : json.handle });
				if (typeof json.toBeSigned !== 'object' || typeof json.toBeSigned.data !== 'string') throw new Error('Argumento toBeSigned inválido');
				let convert = false;
				if (typeof json.toBeSigned.binary !== 'undefined') {
					if (typeof json.toBeSigned.binary !== 'boolean') throw new Error('Argumento toBeSigned.binary inválido');
					convert = json.toBeSigned.binary;
				}
				let dataToSign;
				if (convert) dataToSign = Aroari.Base64.atob(json.toBeSigned.data).buffer;
				else dataToSign = json.toBeSigned.data;
				param = Object.defineProperty(param, 'toBeSigned', { value: dataToSign });
				if (typeof json.attach !== 'undefined') {
					if (typeof json.attach !== 'boolean') throw new Error('Argumento attach inválido');
					param = Object.defineProperty(param, 'attach', { value: json.attach });
				}
				if (typeof json.algorithm !== 'undefined') {
					if (typeof json.algorithm !== 'number') throw new Error('Argumento algorithm inválido');
					param = Object.defineProperty(param, 'algorithm', { value: json.algorithm });
				}
				if (typeof json.cades !== 'undefined') {
					if (typeof json.cades !== 'object') throw new Error('Argumento cades inválido');
					param = Object.defineProperty(param, 'cades', { value: json.cades });
				}
			}
			catch (err) {
				logger.warn(sprintf('Ocorreu o seguinte erro ao processar os parâmetros recebidos na requisição originada em %s pelo serviço sign: %s', origin, err.toString()));
				response.statusCode = 400;
				Logger.releaseLogger();
				return;
			}
			if (this.approvalCallback('sign', referer, param.toBeSigned)) {
				try {
					let pkcs7 = this.api.sign(param);
					response.setHeader('Access-Control-Allow-Origin', origin);
					response.setHeader('Content-Type', 'text/plain');
					response.write(pkcs7);
					response.statusCode = 200;
					logger.debug(sprintf('O serviço sign respondeu à requisição originada em %s com o documento:\r\n', origin, pkcs7));
				}
				catch (err) {
					logger.error(sprintf('Ocorreu o seguinte erro no processamento da requisição originada em %s pelo serviço sign: %s', origin,  err.toString()));
					if (err.errorCode == Aroari.AroariError.ARGUMENT_ERROR) response.statusCode = 400;
					else response.statusCode = 500;
				}
			}
			else {
				response.statusCode = 401;
				logger.warn(sprintf('A requisição do serviço sign originada em %s foi rejeitada pelo usuário', referer));
			}
		}
		else {
			response.statusCode = 415;
			logger.warn(sprintf('Tipo de conteúdo %s originado em %s não suportado pelo serviço sign', ctype, origin));
		}
		Logger.releaseLogger();
	}
	execute(request, response, body) {
		const { method, headers } = request;
		if      (method === 'GET')  this.#processGet(headers, response);
		else if (method === 'POST') this.#processPost(headers, response, body);
		else response.statusCode = 405;
	}
}

// TODO: VerifyService must implement getSigningTime
const verifyProps = new Set([ '', 'pkcs7', 'data', 'binary', 'signingCert', 'eContent', 'verifyTrustworthy', 'getSignerIdentifier', 'getSignedContent']);
const allowList = [ 'signatureVerification', 'messageDigestVerification', 'signingCertVerification', 'certChainVerification', 'signerIdentifier', 'issuer', 'serialNumber', 'eContent', 'data', 'binary' ];
/**
 * Serviço de atendimento às operações de verificação de assinaturas digitais
 * @extends Hekura.AbstractService
 * @memberof Hekura
 */
class VerifyService extends AbstractService
{
	constructor(corsMaxAge, approvalCallback) { super('/verify', corsMaxAge, approvalCallback); }
	accept(method) { return (method === 'POST') || (method === 'OPTIONS'); }
	preflight(headers) {
		let ret = new Map();
		ret.set('Access-Control-Allow-Origin', headers['origin']);
		ret.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	execute(request, response, body) {
		const { method, headers } = request;
		let logger = Logger.getLogger('VerifyService');
		let origin = headers['origin'];
		let referer = headers['referer'];
		if (method !== 'POST') {
			response.statusCode = 405;
			logger.warn(sprintf('Método %s recebido da origem %s não suportado', method, origin));
			Logger.releaseLogger();
			return;
		}
		let ctype = headers['content-type'];
		if (!ctype || ctype !== 'application/json') {
			response.statusCode = 415;
			logger.warn(sprintf('Tipo de conteúdo %s recebido da origem %s não suportado', ctype, origin));
			Logger.releaseLogger();
			return;
		}
		let cmsSignedData;
		let vrfyParam = new Object();
		let verifyTrustworthy = false;
		let getSignerIdentifier = false;
		let getSignedContent = false;
		try {
			let json = JSON.parse(body.toString(), (key, value) => {
				if (verifyProps.has(key)) return value;
				throw new Error(sprintf('Propriedade não especificada %s encontrada', key));
			});
			if (typeof json.pkcs7 !== 'object' && typeof json.pkcs7.data !== 'string') throw new Error('Argumento pkcs7 inválido');
			let convert = false;
			if (typeof json.pkcs7.binary !== 'undefined') {
				if (typeof json.pkcs7.binary !== 'boolean') throw new Error('Argumento pkcs7.binary inválido');
				convert = json.pkcs7.binary;
			}
			let input;
			if (convert) input = Aroari.Base64.atob(json.pkcs7.data).buffer;
			else input = json.pkcs7.data;
			cmsSignedData = new Aroari.CMSSignedData(input);
			if (typeof json.signingCert !== 'undefined') {
				if (typeof json.signingCert.data !== 'string') throw new Error('Argumento signingCert inválido');
				convert = false;
				if (typeof json.signingCert.binary !== 'undefined') {
					if (typeof json.signingCert.binary !== 'boolean') throw new Error('Argumento signingCert.binary inválido');
					convert = json.signingCert.binary;
				}
				if (convert) input = Aroari.Base64.atob(json.signingCert.data).buffer;
				else input = json.signingCert.data;
				vrfyParam = Object.defineProperty(vrfyParam, 'signingCert', { value: input });
			}
			if (typeof json.eContent !== 'undefined') {
				if (typeof json.eContent.data !== 'string') throw new Error('Argumento eContent inválido');
				convert = false;
				if (typeof json.eContent.binary !== 'undefined') {
					if (typeof json.eContent.binary !== 'boolean') throw new Error('Argumento eContent.binary inválido');
					convert = json.eContent.binary;
				}
				if (convert) input = Aroari.Base64.atob(json.eContent.data).buffer;
				else input = json.eContent.data;
				vrfyParam = Object.defineProperty(vrfyParam, 'eContent', { value: input });
			}
			if (typeof json.verifyTrustworthy !== 'undefined') {
				if (typeof json.verifyTrustworthy !== 'boolean') throw new Error('Argumento verifyTrustworthy inválido');
				verifyTrustworthy = json.verifyTrustworthy;
			}
			if (typeof json.getSignerIdentifier !== 'undefined') {
				if (typeof json.getSignerIdentifier !== 'boolean') throw new Error('Argumento getSignerIdentifier inválido');
				getSignerIdentifier = json.getSignerIdentifier;
			}
			if (typeof json.getSignedContent !== 'undefined') {
				if (typeof json.getSignedContent !== 'boolean') throw new Error('Argumento getSignedContent inválido');
				getSignedContent = json.getSignedContent;
			}
		}
		catch (err) {
			response.statusCode = 400;
			logger.warn(sprintf('Ocorreu o seguinte erro ao processar os parâmetros recebidos da origem %s pelo serviço verify: %s', origin, err.toString()));
			Logger.releaseLogger();
			return;
		}

		let signatureVerification;
		let messageDigestVerification;
		let signingCertVerification;
		let certChainVerification;
		let sid;
		let eContent;
		if (this.approvalCallback('verify', referer)) {
			try {
				cmsSignedData.verify(vrfyParam);
				signatureVerification = true;
				messageDigestVerification = true;
				signingCertVerification = true;
				if (verifyTrustworthy) {
					cmsSignedData.verifyTrustworthy(vrfyParam.signingCert);
					certChainVerification = true
				}
				if (getSignerIdentifier) sid = cmsSignedData.getSignerIdentifier();
				if (getSignedContent) {
					eContent = { data: null, binary: true };
					eContent.data = Aroari.Base64.btoa(new Uint8Array(cmsSignedData.getSignedContent()));
				}
				response.statusCode = 200;
			}
			catch (error) {
				if      (error.errorCode == Aroari.AroariError.CMS_SIGNATURE_DOES_NOT_MATCH) signatureVerification = false;
				else if (error.errorCode == Aroari.AroariError.CMS_MESSAGE_DIGEST_NOT_MATCH) messageDigestVerification = false;
				else if (error.errorCode == Aroari.AroariError.CMS_SIGNING_CERTIFICATEV2_NOT_MATCH) signingCertVerification = false;
				else if (error.errorCode == Aroari.AroariError.CMS_VRFY_NO_ISSUER_CERT_FOUND) certChainVerification = false;
				else {
					response.statusCode = 400;
					logger.warn(sprintf('Ocorreu o seguinte erro ao processar os parâmetros da origem %s pelo serviço verify: %s', origin, error.toString()));
				}
			}
			if (response.statusCode != 400) {
				let ret = new Object();
				ret = Object.defineProperty(ret, 'signatureVerification', { value: signatureVerification });
				ret = Object.defineProperty(ret, 'messageDigestVerification', { value: messageDigestVerification });
				ret = Object.defineProperty(ret, 'signingCertVerification', { value: signingCertVerification });
				if (certChainVerification) ret = Object.defineProperty(ret, 'certChainVerification', { value: certChainVerification });
				if (sid) ret = Object.defineProperty(ret, 'signerIdentifier', { value: sid });
				if (eContent) ret = Object.defineProperty(ret, 'eContent', { value: eContent });
				response.setHeader('Access-Control-Allow-Origin', origin);
				response.setHeader('Content-Type', 'application/json');
				let responseBody = JSON.stringify(ret, allowList);
				response.write(responseBody);
				logger.debug(sprintf('O serviço  verify respondeu à requisição recebida da origem %s com o seguinte objeto: [\r\n%s\r\n]', origin, JSON.stringify(ret, null, 2)));
			}
		}
		else {
			response.statusCode = 401;
			logger.warn(sprintf('Requisição recebida da origem %s rejeitada pelo usuário', referer));
		}
		Logger.releaseLogger();
	}
}

/**
 * Opções de inicialização do servidor Hekura
 * @class ServerOptions
 * @memberof Hekura
 * @property { Number } port Porta de atendimento. Se indefinido, assume o valor 9171
 * @property { Number } maxAge O valor em segundos que os preflight requests do protocolo CORS podem ser cacheados. Se indefinido, assume o valor 1800
 * @property { Object } cors Implementação de bloqueio de origens não confiáveis. Se definido deve ser uma herança de
 * {@link Hekura.CORSBlockade}. Caso o parâmetro não seja informado ou o objeto não seja uma instância de CORSBlockade, 
 * esta impementação é utilizada silenciosamente
 * @property { approvalCallback } callback Função a ser chamada visando obter a aprovação do usuário para a operação criptográfica. Visando simplificar
 * os testes de regressão, a propriedade assume como default uma função que sempre retorna true. No entanto, em vista do modelo de ameaças da solução,
 * é esperado que um valor seja passado.
 */

/**
 * Servidor HTTP de atendimento REST
 * @memberof Hekura
 */
class HTTPServer
{
	/**
	 * Cria uma nova instância do serviço.
	 * @param { Object } options Opções de inicialização. Ver {@link Hekura.ServerOptions}
	 */
	constructor({
		port = 9171,
		maxAge = 1800,
		cors = new CORSBlockade ,
		callback = approvalCallback
	} = {}) {
		this.logger = Logger.getLogger('Hekura Service');
		this.blockade = cors;
		this.services = new Map();
		this.services.set('/', new RootService(maxAge, callback));
		this.services.set('/enroll', new EnrollService(maxAge, callback));
		this.services.set('/sign', new SignService(maxAge, callback));
		this.services.set('/verify', new VerifyService(maxAge, callback));
		this.server = http.createServer(this.#listener.bind(this));
		this.checkPort = new Promise((resolve) => {
			tcp.check(port, '127.0.0.1').
			then((ready) => {
				this.port = port;
				return resolve(!ready);
			});
		});
		let origins = '[\r\n';
		let it = this.blockade.trustedOrigins.values();
		let item = it.next();
		while (!item.done) {
			origins = origins.concat('\t\t', item.value, '\r\n');
			item = it.next();
		}
		this.logger.debug(sprintf('O serviço foi instanciado com os seguintes parâmetros:\r\n\tPorta: %s\r\n\tAccess-Control-Max-Age: %s\r\n\tOrigens confiáveis: %s]', port.toString(), maxAge.toString(), origins));
	}

	#listener(request, response) {
		let chunks = [];
		const { method, headers, url } = request;
		let origin = headers['origin'];
		this.logger.debug(sprintf('Recebida requisição com o método %s da origem %s destinada à url %s, contendo os seguintes cabeçalhos: [\r\n%s\r\n]', method, origin, url, JSON.stringify(headers, null, 2)));
		request.on('error', (err) => {
			this.logger.error(sprintf('Ocorreu o seguinte erro ao processar o corpo da requisição recebida da origem %s: %s', origin, err.toString()));
			response.statusCode = 500;
			response.end();
		})
		.on('data', (chunk) => { chunks.push(chunk); })
		.on('end', () => {
			let body = Buffer.concat(chunks);
			if (body.length > 0) this.logger.debug(sprintf('Corpo da requisição: [\r\n%s]', Wanhamou.beautify(body.toString().replace(/\\r?\\n|\\r|\\n/g, '\r\n'))));
			if (this.blockade.allowOrigin(headers)) {
				let svc = this.services.get(url);
				if (svc) {
					if (svc.accept(method)) {
						if (method === 'OPTIONS') {
							let responseHeaders = svc.preflight(headers);
							let it = responseHeaders.keys();
							let item = it.next();
							let msg = 'Cabeçalhos devolvidos como resposta ao preflight: [\r\n';
							while (!item.done) {
								let key = item.value;
								let value = responseHeaders.get(key);
								response.setHeader(key, value);
								msg = msg.concat('\t', key, ': ', value, '\r\n');
								item = it.next();
							}
							response.statusCode = 204;
							this.logger.debug(msg.concat(']'));
						}
						else svc.execute(request, response, body);
						this.logger.info(sprintf('Atendida a requisição com o método %s originada em %s e destinada à URL %s', method, origin, url));
					}
					else {
						this.logger.warn(sprintf('Método %s da requisição originada em %s rejeitado pelo processador', method, origin));
						response.statusCode = 405;
					}
				}
				else {
					this.logger.warn(sprintf('Destino %s da requisição originada em %s não encontrado', url, origin));
					response.statusCode = 404;
				}
			}
			else {
				this.logger.warn(sprintf('Origem %s rejeitada como não confiável', origin));
				response.statusCode = 403;
			}
			response.end();
		});
	}

	/**
	 * Inicia o serviço de atendimento
	 * @throws { ServiceError } Dispara uma instância de {@link Hekura.ServiceError} caso a porta já esteja utilizada
	 */
	start() {
		return new Promise((resolve, reject) => {
			return this.checkPort.then((ready) => {
				if (!ready) return reject(ServiceError.HTTP_PORT_ALREADY_USED);
				this.server.listen(this.port, () => {
					this.logger.info('Serviço iniciado');
					return resolve(true);
				});
			});
		});
	}

	/**
	 * Finaliza o serviço de atendimento
	 */
	stop() {
		return new Promise((resolve, reject) => {
			this.server.close((err) => {
				if (!err) {
					this.logger.info('Serviço finalizado corretamente');
					Logger.releaseLogger();
					return resolve(true);
				}
				this.logger.error(sprintf('Ocorreu a seguinte falha na finalização do serviço: %s', err.toString()));
				Logger.releaseLogger();
				return reject(err);
			});
		});
	}
}

module.exports = {
	ServiceError: ServiceError,
	CORSBlockade: CORSBlockade,
	HTTPServer: HTTPServer
}