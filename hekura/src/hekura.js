/**
 * @file API criptogrática exposta como serviço HTTP para atendimento às aplicações web
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';
const tcp = require('tcp-port-used');
const http = require('http');
const path = require('path');
const Aroari = require(path.join(__dirname, '..', '..', 'aroari', 'src', 'aroari'));
const fs = require('fs');

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
		let target = path.join(__dirname, 'hekura-schema.json');
		try {
			let schema = fs.readFileSync(target, { encoding: 'utf-8' });
			response.setHeader('Access-Control-Allow-Origin', request.headers['origin']);
			response.setHeader('Content-Type', 'application/json');
			response.write(schema);
			response.statusCode = 200;
		}
		catch (err) {
			// TODO: Implement a Log engine
			console.error(err);
			response.statusCode = 500;
		}
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
		if (this.approvalCallback('enumerateDevices', headers['referer'])) {
			try {
				let devices = this.api.enumerateDevices();
				response.setHeader('Access-Control-Allow-Origin', headers['origin']);
				response.setHeader('Content-Type', 'application/json');
				response.write(JSON.stringify(devices));
				response.statusCode = 200;
			}
			catch (error) {
				// TODO: Implement a log engine
				console.error(error);
				response.statusCode = 500;
			}
		}
		else response.statusCode = 401;
	}
	#processPost(headers, response, body) {
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param;
			try {
				param = JSON.parse(body.toString());
				if (typeof param.device !== 'string') throw new Error('Invalid argument');
				if (typeof param.keySize !== 'undefined') {
					if (typeof param.keySize !== 'number') throw new Error('Invalid argument');
				}
				else param = Object.defineProperty(param, 'keySize', { value: 2048 });
				if (typeof param.signAlg !== 'undefined') {
					if (typeof param.signAlg !== 'number') throw new Error('Invalid argument');
				}
				else param = Object.defineProperty(param, 'signAlg', { value: Aroari.SignMechanism.CKM_SHA256_RSA_PKCS });
				if (typeof param.rdn === 'undefined' || typeof param.rdn.cn === 'undefined') throw new Error('Invalid argument');
			}
			catch (err) { response.statusCode = 400; }
			if (this.approvalCallback('generateCSR', headers['referer'])) {
				try {
					let pkcs7 = this.api.generateCSR(param);
					response.setHeader('Access-Control-Allow-Origin', headers['origin']);
					response.setHeader('Content-Type', 'text/plain');
					response.write(pkcs7);
					response.statusCode = 200;
				}
				catch (error) {
					// TODO: Implement a log engine
					console.error(error);
					response.statusCode = 500;
				}
			}
			else response.statusCode = 401;
		}
		else response.statusCode = 415;
	}
	#processPut(headers, response, body) {
		let ctype = headers['content-type'];
		if (ctype && ctype === 'application/json') {
			let param;
			try {
				let json = JSON.parse(body.toString());
				if (typeof json.pkcs7 !== 'string') throw new Error('Invalid argument');
				let b64 = json.pkcs7.replace('-----BEGIN PKCS7-----', '').replace('-----END PKCS7-----', '').replace('-----BEGIN CMS-----', '').replace('-----END CMS-----', '').replace(/\r?\n|\r/g, '');
				param = Aroari.Base64.atob(b64);
			}
			catch (err) { response.statusCode = 400; return; }
			if (this.approvalCallback('installCertificates', headers['referer'])) {
				try {
					let done = this.api.installCertificates(param);
					response.setHeader('Access-Control-Allow-Origin', headers['origin']);
					if (done) response.statusCode = 201;
					else response.statusCode = 200;
				}
				catch (error) {
					// TODO: Implement a log engine
					console.error(error);
					if (
						error.errorCode == Aroari.AroariError.INSTALL_SIGNER_CERT_ERROR ||
						error.errorCode == Aroari.AroariError.CERTIFICATE_CHAIN_VERIFY_ERROR
					)	response.statusCode = 451;
					else response.statusCode = 500;
				}
			}
			else response.statusCode = 401;
		}
		else response.statusCode = 415;
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
	constructor(corsMaxAge, approvalCallback) { super('/sign', corsMaxAge, approvalCallback); }
	accept(method) { return (method === 'GET') || (method === 'POST') || (method === 'OPTIONS'); }
	preflight(headers) {
		let ret = new Map();
		ret.set('Access-Control-Allow-Origin', headers['origin']);	// We suppose that it is true since origin validation was already done
		ret.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	execute(request, response, body) {
		// TODO:
	}
}

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
		ret.set('Access-Control-Allow-Origin', headers['origin']);	// We suppose that it is true since origin validation was already done
		ret.set('Access-Control-Allow-Methods', 'POST, OPTIONS');
		if (headers['access-control-request-headers']) ret.set('Access-Control-Allow-Headers', 'Content-Type');
		ret.set('Access-Control-Max-Age', this.maxAge);
		return ret;
	}
	execute(request, response, body) {
		// TODO:
	}
}

/**
 * Callback chamada sempre que uma operação criptográfica está para ser realizada, visando obter a aprovação do usuário.
 * @callback approvalCallback
 * @param { String } operationId Identificador da operação, conforme especificação OpenAPI do serviço
 * @param { String } referer Valor do header Referer da requisição HTTP recebida
 * @param { String | ArrayBuffer } value Informação apropriada à operação. Por exemplo, o conteúdo a ser assinado
 * @returns { Boolean } Valor lógico indicando a aprovação (ou não) da operação
 */
 function approvalCallback(operationId, referer, value) {
	return true;
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
	}

	#listener(request, response) {
		let chunks = [];
		const { method, headers, url } = request;
		request.on('error', (err) => {
			// TODO: Implement a log engines
			console.error(err);
			response.statusCode = 500;
			response.end();
		})
		.on('data', (chunk) => { chunks.push(chunk); })
		.on('end', () => {
			let body = Buffer.concat(chunks);
			if (this.blockade.allowOrigin(headers)) {
				let svc = this.services.get(url);
				if (svc) {
					if (svc.accept(method)) {
						if (method === 'OPTIONS') {
							let responseHeaders = svc.preflight(headers);
							responseHeaders.forEach((value, key) => { response.setHeader(key, value); });
							response.statusCode = 204;
						}
						else svc.execute(request, response, body);
					}
					else response.statusCode = 405;
				}
				else response.statusCode = 404;
			}
			else response.statusCode = 403;
			// TODO: Implement a Log engine
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
				if (!err) return resolve(true);
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