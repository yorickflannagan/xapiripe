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
 * @property { Number } rotate	Quantidade máxima de arquivos de log antes que seja necessário sobrescrever o mais antigo. Valor default: 3
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
	constructor(corsMaxAge, callback) { super('/', corsMaxAge, approvalCallback); }
	accept(method) { return (method === 'GET'); }
	execute(request, response) {
		let logger = Wanhamou.Logger.getLogger('RootService');
		let target = path.join(__dirname, 'hekura-schema.json');
		try {
			let schema = fs.readFileSync(target, { encoding: 'utf-8' });
			response.setHeader('Access-Control-Allow-Origin', request.headers['origin']);
			response.setHeader('Content-Type', 'application/json');
			response.write(schema);
			response.statusCode = 200;
			logger.debug('Especificação REST enviada à origem '.concat(request.headers['origin'], ': [\r\n', schema, '\r\n]'));
		}
		catch (err) {
			logger.error('Ocorreu o seguinte erro ao obter a especificação REST: '.concat(err.toString()));
			response.statusCode = 500;
		}
		Wanhamou.Logger.releaseLogger();
	}
}

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
		ret.set('Access-Control-Allow-Origin', headers['origin']);	// We suppose that it is true since origin validation was already done
		ret.set('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	#processGet(headers, response) {
		let logger = Wanhamou.Logger.getLogger('EnrollService');
		if (this.approvalCallback('enumerateDevices', headers['referer'])) {
			try {
				let devices = this.api.enumerateDevices();
				response.setHeader('Access-Control-Allow-Origin', headers['origin']);
				response.setHeader('Content-Type', 'application/json');
				response.write(JSON.stringify(devices));
				response.statusCode = 200;
				logger.debug('O serviço enumerateDevices retornou o seguinte objeto à origem '.concat(headers['origin'], ': ', JSON.stringify(devices)));
			}
			catch (err) {
				logger.error('Ocorreu o seguinte erro ao processar o serviço enumerateDevices: '.concat(err.toString()));
				response.statusCode = 500;
			}
		}
		else {
			response.statusCode = 401;
			logger.warn('Serviço enumerateDevices originado em '.concat(headers['referer'], ' rejeitado pelo usuário'));
		}
		Wanhamou.Logger.releaseLogger();
	}
	#processPost(headers, response, body) {
		let logger = Wanhamou.Logger.getLogger('EnrollService');
		logger.debug('Parâmetros recebidos pelo serviço generateCSR: '.concat(body.toString()));
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param;
			try {
				// TODO: Implement a reviver callback to reject unknown fields
				param = JSON.parse(body.toString());
				if (typeof param.device !== 'string') throw new Error('Argumento device inválido');
				if (typeof param.keySize !== 'undefined') {
					if (typeof param.keySize !== 'number') throw new Error('Argumento keySize inválido');
				}
				if (typeof param.signAlg !== 'undefined') {
					if (typeof param.signAlg !== 'number') throw new Error('Argumento signAlg inválido');
				}
				if (typeof param.rdn === 'undefined' || typeof param.rdn.cn === 'undefined') throw new Error('Argumento rdn inválido');
			}
			catch (err) {
				logger.warn('Ocorreu o seguinte erro ao processar os parâmetros do serviço generateCSR: '.concat(err.toString()));
				Wanhamou.Logger.releaseLogger();
				response.statusCode = 400;
				return;
			}
			if (this.approvalCallback('generateCSR', headers['referer'])) {
				try {
					let pkcs7 = this.api.generateCSR(param);
					response.setHeader('Access-Control-Allow-Origin', headers['origin']);
					response.setHeader('Content-Type', 'text/plain');
					response.write(pkcs7);
					response.statusCode = 200;
					logger.debug('O serviço generateCSR respondeu à requisição originada em '.concat(headers['origin'], ' com o seguinte CSR: ', pkcs7));
				}
				catch (err) {
					logger.error('Ocorreu o seguinte erro ao processar o serviço generateCSR originado em '.concat(headers['origin'], ': ', err.toString()));
					if (err.errorCode == Aroari.AroariError.ARGUMENT_ERROR) response.statusCode = 400;
					else response.statusCode = 500;
				}
			}
			else {
				response.statusCode = 401;
				logger.warn('Serviço generateCSR originado em '.concat(headers['referer'], ' rejeitado pelo usuário'));
			}
		}
		else {
			response.statusCode = 415;
			logger.warn('Tipo de conteúdo '.concat(ctype, ' originado em ', headers['origin'], ' não suportado pelo serviço generateCSR'));
		}
		Wanhamou.Logger.releaseLogger();
	}
	#processPut(headers, response, body) {
		let logger = Wanhamou.Logger.getLogger('EnrollService');
		logger.debug('Parâmetros recebidos pelo serviço installCertificates: '.concat(body.toString()));
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param;
			try {
				// TODO: Implement a reviver callback to reject unknown fields
				let json = JSON.parse(body.toString());
				if (typeof json.pkcs7 !== 'string') throw new Error('Argumento inválido');
				let b64 = json.pkcs7.replace('-----BEGIN PKCS7-----', '').replace('-----END PKCS7-----', '').replace('-----BEGIN CMS-----', '').replace('-----END CMS-----', '').replace(/\r?\n|\r/g, '');
				param = Aroari.Base64.atob(b64);
			}
			catch (err) {
				logger.warn('Ocorreu o seguinte erro ao processar os parâmetros do serviço installCertificates: '.concat(err.toString()));
				response.statusCode = 400;
				Wanhamou.Logger.releaseLogger();
				return;
			}
			if (this.approvalCallback('installCertificates', headers['referer'])) {
				try {
					let done = this.api.installCertificates(param);
					response.setHeader('Access-Control-Allow-Origin', headers['origin']);
					if (done) response.statusCode = 201;
					else response.statusCode = 200;
					logger.debug('Código de estado HTTP retornado à requisição originada em '.concat(headers['origin'], 'pelo serviço installCertificates: ', response.statusCode.toString()));
				}
				catch (err) {
					logger.error('Ocorreu o seguinte erro ao processar o serviço installCertificates: '.concat(err.toString()));
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
				logger.warn('Serviço installCertificates originado em '.concat(headers['referer'], ' rejeitado pelo usuário'));
			}
		}
		else {
			response.statusCode = 415;
			logger.warn('Tipo de conteúdo '.concat(ctype, ' originado em ', headers['origin'], ' não suportado pelo serviço installCertificates'));
		} 
		Wanhamou.Logger.releaseLogger();
	}
	execute(request, response, body) {
		const { method, headers } = request;
		if      (method === 'GET')  this.#processGet(headers, response);
		else if (method === 'POST') this.#processPost(headers, response, body);
		else if (method === 'PUT')  this.#processPut(headers, response, body);
		else response.statusCode = 405;
	}
}

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
		ret.set('Access-Control-Allow-Origin', headers['origin']);	// We suppose that it is true since origin validation was already done
		ret.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	#processGet(headers, response) {
		let logger = Wanhamou.Logger.getLogger('SignService');
		if (this.approvalCallback('enumerateCertificates', headers['referer'])) {
			try {
				let certs = this.api.enumerateCertificates();
				response.setHeader('Access-Control-Allow-Origin', headers['origin']);
				response.setHeader('Content-Type', 'application/json');
				response.write(JSON.stringify(certs));
				response.statusCode = 200;
				logger.debug('O serviço enumerateCertificates retornou o seguinte objeto à requisição originada em '.concat(headers['origin'], ': ', JSON.stringify(certs)));
			}
			catch (err) {
				logger.debug('Ocorreu o seguinte erro no processamento do serviço enumerateCertificates: '.concat(err.toString()));
				response.statusCode = 500;
			}
		}
		else {
			response.statusCode = 401;
			logger.warn('A requisição do serviço enumerateCertificates originada em '.concat(headers['referer'], ' foi rejeitada pelo usuário'));
		}
		Wanhamou.Logger.releaseLogger();
	}
	#processPost(headers, response, body) {
		let logger = Wanhamou.Logger.getLogger('SignService');
		logger.debug('Parâmetros recebidos pelo serviço sign: '.concat(body.toString()));
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param = new Object();
			try {
				// TODO: Implement a reviver callback to reject unknown fields
				let json = JSON.parse(body.toString());
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
				logger.warn('Ocorreu o seguinte erro ao processar os parâmetros do serviço sign: '.concat(err.toString()));
				response.statusCode = 400;
				Wanhamou.Logger.releaseLogger();
				return;
			}
			if (this.approvalCallback('sign', headers['referer'], param.toBeSigned)) {
				try {
					let pkcs7 = this.api.sign(param);
					response.setHeader('Access-Control-Allow-Origin', headers['origin']);
					response.setHeader('Content-Type', 'text/plain');
					response.write(pkcs7);
					response.statusCode = 200;
					logger.debug('O serviço sign respondeu à requisição originada em '.concat(headers['origin'], ': ', pkcs7));
				}
				catch (err) {
					logger.error('Ocorreu o seguinte erro no processamento do serviço sign: '.concat(err.toString()));
					if (err.errorCode == Aroari.AroariError.ARGUMENT_ERROR) response.statusCode = 400;
					else response.statusCode = 500;
				}
			}
			else {
				response.statusCode = 401;
				logger.warn('A requisição do serviço sign originada em '.concat(headers['referer'], ' foi rejeitada pelo usuário'));
			}
		}
		else {
			response.statusCode = 415;
			logger.warn('Tipo de conteúdo '.concat(ctype, ' originado em ', headers['origin'], ' não suportado pelo serviço sign'));
		}
		Wanhamou.Logger.releaseLogger();
	}
	execute(request, response, body) {
		const { method, headers } = request;
		if      (method === 'GET') this.#processGet(headers, response);
		else if (method === 'POST') this.#processPost(headers, response, body);
		else response.statusCode = 405;
	}
}

/**
 * Serviço de atendimento às operações de verificação de assinaturas digitais
 * @extends Hekura.AbstractService
 * @memberof Hekura
 */
const ALLOW_LIST = [
	'signatureVerification',
	'messageDigestVerification',
	'signingCertVerification',
	'certChainVerification',
	'signerIdentifier',
	'issuer',
	'serialNumber',
	'eContent',
	'data',
	'binary'
];
class VerifyService extends AbstractService
{
	constructor(corsMaxAge, approvalCallback) { super('/verify', corsMaxAge, approvalCallback); }
	accept(method) { return (method === 'POST') || (method === 'OPTIONS'); }
	preflight(headers) {
		let ret = new Map();
		ret.set('Access-Control-Allow-Origin', headers['origin']);	// We suppose that it is true since origin validation was already done
		ret.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	execute(request, response, body) {
		const { method, headers } = request;
		let logger = Wanhamou.Logger.getLogger('VerifyService');
		logger.debug('Parâmetros recebidos pelo serviço verify: '.concat(body.toString()));
		if (method !== 'POST') {
			response.statusCode = 405;
			logger.warn('Método '.concat(method, ' recebido da origem ', headers['origin'], ' não suportado'));
			Wanhamou.Logger.releaseLogger();
			return;
		}
		let ctype = headers['content-type'];
		if (!ctype || ctype !== 'application/json') {
			response.statusCode = 415;
			logger.warn('Tipo de conteúdo '.concat(ctype, ' recebido da origem ', headers['origin'], ' não suportado'));
			Wanhamou.Logger.releaseLogger();
			return;
		}
		let cmsSignedData;
		let vrfyParam = new Object();
		let verifyTrustworthy = false;
		let getSignerIdentifier = false;
		let getSignedContent = false;
		try {
			// TODO: Implement a reviver callback to reject unknown fields
			let json = JSON.parse(body.toString());
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
			logger.warn('Ocorreu o seguinte erro ao processar os parâmetros recebidos da origem '.concat(headers['origin'], ': ', err.toString()));
			Wanhamou.Logger.releaseLogger();
			return;
		}

		let signatureVerification;
		let messageDigestVerification;
		let signingCertVerification;
		let certChainVerification;
		let sid;
		let eContent;
		if (this.approvalCallback('verify', headers['referer'])) {
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
					logger.warn('Ocorreu o seguinte erro ao processar os parâmetros da origem '.concat(headers['origin'], ': ', error.toString()));
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
				response.setHeader('Access-Control-Allow-Origin', headers['origin']);
				response.setHeader('Content-Type', 'application/json');
				let responseBody = JSON.stringify(ret, ALLOW_LIST);
				response.write(responseBody);
				logger.debug('O serviço  verify respondeu à requisição recebida da origem '.concat(headers['origin'], ': ', responseBody));
			}
		}
		else {
			response.statusCode = 401;
			logger.warn('Requisição recebida da origem '.concat(headers['referer'], ' rejeitada pelo usuário'));
		}
		Wanhamou.Logger.releaseLogger();
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
		this.logger = Wanhamou.Logger.getLogger('Hekura Service');
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
		let origins = '[';
		this.blockade.trustedOrigins.forEach((val, value) => {
			origins.concat(value, '\r\n');
		});
		origins.concat(']');
		let msg = 'O serviço foi instanciado com os seguintes parâmetros:\r\n'.concat(
			'Porta: ', port.toString(), '\r\n',
			'Access-Control-Max-Age: ', maxAge.toString(), '\r\n',
			'Origens confiáveis: ', origins
		);
		this.logger.debug(msg);
	}

	#listener(request, response) {
		let chunks = [];
		const { method, headers, url } = request;
		let msg = 'Cabeçalhos da requisição: [\r\n';
		for (let item in headers) { msg.concat(item, '=', headers[item], '\r\n'); }
		this.logger.debug(msg.concat(']'));
		request.on('error', (err) => {
			this.logger.error('Ocorreu o seguinte erro ao processar o corpo da requisição recebida: '.concat(err.toString()));
			response.statusCode = 500;
			response.end();
		})
		.on('data', (chunk) => { chunks.push(chunk); })
		.on('end', () => {
			let body = Buffer.concat(chunks);
			this.logger.debug('Corpo da requisição: [\r\n'.concat(body.toString(), ']'));
			if (this.blockade.allowOrigin(headers)) {
				let svc = this.services.get(url);
				if (svc) {
					if (svc.accept(method)) {
						if (method === 'OPTIONS') {
							let responseHeaders = svc.preflight(headers);
							responseHeaders.forEach((value, key) => { response.setHeader(key, value); });
							response.statusCode = 204;
							let msg = 'Cabeçalhos devolvidos como reposta ao preflight: [\r\n';
							responseHeaders.forEach((value, key) => { msg.concat(key, ': ', value, '\r\n'); });
							this.logger.debug(msg.concat(']'));
						}
						else {
							svc.execute(request, response, body);
							this.logger.info('Atendida a requisição originada em ', headers['origin'], ' e destinada à URL: '.concat(url));
						}
					}
					else {
						this.logger.warn('Método '.concat(method, ' originado em', headers['origin'], ' rejeitado pelo processador'));
						response.statusCode = 405;
					}
				}
				else {
					this.logger.warn('Destino '.concat(url, ' originado em', headers['origin'], ' não encontrado'));
					response.statusCode = 404;
				}
			}
			else {
				this.logger.warn('Origem '.concat(headers['origin'], ' rejeitada como não confiável'));
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
					Wanhamou.Logger.releaseLogger();
					return resolve(true);
				}
				this.logger.error('Ocorreu a seguinte falha na finalização do serviço: '.concat(err.toString()));
				Wanhamou.Logger.releaseLogger();
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