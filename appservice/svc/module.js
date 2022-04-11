/**
 * @file Modelo de mensagens entre eos coomponentes da aplicação de distribuição do serviço Hekura
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { threadId } = require('worker_threads');

const uriPattern = /^(http|https):\/\/(([a-zA-Z0-9$\-_.+!*'(),;:&=]|%[0-9a-fA-F]{2})+@)?(((25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|localhost|([a-zA-Z0-9]+\.)+([a-zA-Z]{2,}))(:[0-9]+)?(\/(([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*)*)?(\?([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?(\#([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?)?$/;


/**
 * Origem confiável
 * @property { String } origin: origem na forma [protocolo]://[dominio]:[porta]
 * @property { String } id: identificador da origem (um UUID). Valor default é calculado.
 */
class Origin {
	/**
	 * Cria uma nova instância do objeto
	 * @param { String } origin: origem na forma [protocolo]://[dominio]:[porta]
	 */
	constructor(origin) {
		if (!origin.match(uriPattern)) throw new Error('Argumento origin inválido');
		this.origin = origin;
		this.id = crypto.randomUUID();
	}
}
/**
 * Origens confiáveis. Lista consultada pelo processamento REST para atender à contramedida (ii) do documento Modelo de Ameaças.
 * @property { boolean } warning: indicador da necessidade de alertar o usuário sempre que, na interface gráfica, tentar remover uma origem. Default: true.
 * @property { Array } origins: lista de origens confiáveis, conforme {@link Origin}.
 */
class TrustedOrigins {
	constructor() {
		this.warning = true;
		this.origins = [];
	}
}
/**
 * Opções de inicialização do serviço.
 * @property { Number } port: porta do serviço. Default> 9171.
 * @property { Number } maxAge: valor (em segundos) a ser fornecido no header CORS Access-Control-Max-Age. Default: 1800.
 * @property { TrustedOrigins } trustedOrigins: origens confiáveis, conforme {@link TrustedOrigins}.
 */
class ServerOptions {
	constructor() {
		this.port = 9171;
		this.maxAge = 1800;
		this.trustedOrigins = new TrustedOrigins();
	}
}
/**
 * Opções de log
 * @property { String } path: caminho completo para os arquivos de log. Default: __dirname/runtime.
 * @property { String } fname: padrão para nome dos arquivos de log. Deve conter a string "-n". Default: xapiripe-n.log,
 * @property { Number } maxSize: tamanho máximo (em KB) que o arquivo de log pode alcançar antes de rotacionar. Default: 2048.
 * @property { Number } rotate: quantidade máxima de arquivos de log a serem criados antes de sobrescrever o mais antigo. Default: 5.
 * @property { Number } level: nível de log a ser adotado pela aplicação. Default: 1 (info). Ver a documentação do componente Wanhamou.
 */
class LogOptions {
	constructor() {
		this.path = path.join(__dirname, 'runtime');
		this.fname = 'xapiripe-n.log';
		this.maxSize = 2048;
		this.rotate = 5;
		this.level = 1;
	}
}
/**
 * Uma requisição de operação que não precisa de confirmação do usuário
 * @property { String } referer: origem da requisição
 * @property { String } operationId: identificação da operação
 */
class DoNotDisturb {
	constructor(referer, operationId) {
		this.referer = referer;
		this.operationId = operationId;
	}
}

class AppOptions {
	constructor() {
		this.askToRestart = true;
		this.restartOnChange = true;
	}
}

const cfgProperties = [
	'logOptions',
	'path',
	'fname',
	'maxSize',
	'rotate',
	'level',
	'serverOptions',
	'port',
	'maxAge',
	'trustedOrigins',
	'warning',
	'origins',
	'doNotDisturb',
	'app',
	'askToRestart',
	'restartOnChange'
];
const cfgTemplate = new Map()
	.set('logOptions', 'object')
	.set('path', 'string')
	.set('fname', 'string')
	.set('maxSize', 'number')
	.set('rotate', 'number')
	.set('level', 'number')
	.set('serverOptions', 'object')
	.set('port', 'number')
	.set('maxAge', 'number')
	.set('trustedOrigins', 'object')
	.set('warning', 'boolean')
	.set('origins', 'object')
	.set('origin', 'string')
	.set('id', 'string')
	.set('doNotDisturb', 'object')
	.set('referer', 'string')
	.set('operationId', 'string')
	.set('app', 'object')
	.set('askToRestart', 'boolean')
	.set('restartOnChange', 'boolean')
	.set('', 'object');
 
/**
 * Configuração do serviço
 * @property { LogOptions } logOptions: opções de log, conforme {@link LogOptions}.
 * @property { ServerOptions } serverOptions: opções do serviço, conforme {@link ServerOptions}
 * @property { Array } doNotDisturb: lista de operações por origem que não requerem confirmação do usuário novamente
 */
class Config
{
	constructor() {
		this.logOptions = new LogOptions();
		this.serverOptions = new ServerOptions();
		this.doNotDisturb = [];
		this.app = new AppOptions();
	}

	/**
	 * Salva o estado corrente da configuração
	 * @param { string } options: caminho completo para o arquivo JSON
	 */
	store(options) { fs.writeFileSync(options, JSON.stringify(this)); }
	/**
	 * Carrega a configuração a partir de um arquivo JSON, se existir
	 * @param { string } options: caminho completo para o arquivo JSON
	 * @returns uma instância do objeto
	 */
	static load(options) {
		let ret = new Config();
		let json = JSON.stringify(ret);
		if (fs.existsSync(options)) {
			json = fs.readFileSync(options, 'utf-8');
			this.validate(json, true);
			ret = Object.setPrototypeOf(JSON.parse(json), Config.prototype);
		}
		return ret;
	}
	/**
	 * Valida o JSON de configuração
	 * @param { string } cfg: JSON de configuração
	 * @param { boolean } strict: indica se o validador deve checar as propriedades obrigatórias
	 */
	static validate(cfg, strict) {
		let properties = new Set(cfgProperties);
		JSON.parse(cfg, (key, value) => {
			let tp = cfgTemplate.get(key);
			if (typeof tp === 'undefined') {
				if (key.match(/^-?\d+$/)) tp = 'object';
			}
			if (typeof tp === 'undefined') throw new Error('Propriedade ' + key + ' não reconhecida');
			if (typeof value !== tp) throw new Error('O tipo da propriedade ' + key + ' precisa ser ' + tp);
			properties.delete(key);
			return value;
		});
		if (strict && properties.size > 0) throw new Error('O objeto não contém todas as propriedades obigatórias');
	}

	/**
	 * Adiciona uma requisição de operação que não precisa mais de confirmação do usuário
	 * @param { String } referer: origem da requisição
	 * @param { String } operationId: identificação da operação
	 */
	addDoNotDisturb(referer, operationId) {
		this.doNotDisturb.push(new DoNotDisturb(referer, operationId));
	}
	/**
	 * Verifica se a requisição de operação especificada não precisa mais de confirmação do usuário
	 * @param { String } referer: origem da requisição
	 * @param { String } operationId: identificação da operação
	 * @returns indicador
	 */
	everBeenDisturbed(referer, operationId) {
		let idx = this.doNotDisturb.findIndex((elem) => { return elem.referer === referer && elem.operationId === operationId; });
		return idx > -1;
	}
	/**
	 * Define uma origem confiável. Se a origem já constar da lista, a anterior é substituída.
	 * @param { String } origin: origem a ser incluída
	 * @returns o UUID gerado para a origem
	 */
	setOrigin(origin) {
		let newOrigin = new Origin(origin);
		let oldIdx = this.serverOptions.trustedOrigins.origins.findIndex((elem) => { return elem.origin === origin; });
		if (oldIdx > -1) this.serverOptions.trustedOrigins.origins[oldIdx] = newOrigin;
		else this.serverOptions.trustedOrigins.origins.push(newOrigin);
		return newOrigin.id;
	}
}


/**
 * Mensagem trocada no contexto da aplicação entre seus vários processos
 */
class Message {
	/**
	 * Sinaliza a necessidade de finalização do serviço Hekura
	 * @member { String }
	 * @default stop-service
	 */
	static STOP = 'stop-service';
	/**
	 * Sinaliza a necessidade de alertar o usuário de que uma operação originada na web foi requerida
	 * @member { String }
	 * @default warn-user
	 */
	static WARN = 'warn-user';
	/**
	 * Cria uma nova instância do objeto
	 * @param { String } signal: identificador do tipo da mensagem
	 */
	constructor(signal) {
		this.signal = signal;
	}
}

/**
 * Mensagem indicando a necessidade de alertar o usuário para uma requisição em particular. Originada no processo do serviço
 * e destinada ao processo principal da aplicação.
 * @property { String } signal: identificador da mensagem
 * @property { String } msgId: identificador (UUID) da mensagem
 * @property { String } operationId: identificador da operação solicitada pela requisição
 * @property { String } referer: origem da requisição
 * @property { String | ArrayBuffer } value: conteúdo a ser assinado, caso a operação seja de assinatura.
 */
 class WarnMessage extends Message {
	constructor(operationId, referer, value) {
		super(Message.WARN);
		this.msgId = crypto.randomUUID();
		this.operationId = operationId;
		this.referer = referer;
		this.value = value;
	}
}

/**
 * Mensagem com as informações necessárias à composição do alerta ao usuário. Originada no processo principal da aplicação
 * e destinada ao processo de renderização do alerta.
 * @property { String } signal: identificador da mensagem
 * @property { String } msgId: identificador (UUID) da mensagem
 * @property { String } operationId: identificador da operação solicitada pela requisição
 * @property { String } referer: origem da requisição
 * @property { String | ArrayBuffer } value: conteúdo a ser assinado, caso a operação seja de assinatura.
 * @property { String } message: texto da mensagem de alerta a ser exibido ao usuário
 */
class UserQuestion extends WarnMessage  {
	/**
	 * Cria uma nova instância do objeto
	 * @param { WarnMessage } warn: objeto recebido originalmente do processo do serviço Hekura
	 * @param { String } message: texto da mensagem de alerta a ser exibido ao usuário
	 */
	constructor(warn, message) {
		super(warn.operationId, warn.referer, warn.value);
		this.message = message;
	}
}

/**
 * Mensagem indicando a decisão do usuário sobre o alerta fornecido. Originada no processo principal da
 * aplicação e destinada ao processo do serviço Hekura, como responsta à WarnMessage anteriormente enviada.
 * @property { String } signal: identificador da mensagem
 * @property { String } msgId: identificador (UUID) da mensagem enviada originalmente pelo serviço Hekura
 * @property { boolean } response: resposta do usuário indicando aceita ou não a requisição
 */
class WarnResponse extends Message {
	/**
	 * Mensagem enviada como resposta à mensagem WarnMessage recebida
	 * @param { String } msgId: identificador (UUID) da mensagem enviada originalmente pelo serviço Hekura
	 * @param { boolean } response: resposta do usuário indicando se aceita ou não a requisição
	 */
	constructor(msgId, response) {
		super(Message.WARN);
		this.msgId = msgId;
		this.response = response;
	}
}

/**
 * Mensagem indicando a resposta do usuário à UserQuestion formulada anteriormente. Originada no processo
 * de renderização do alerta ao usuário e destinada ao processo principal, para que este possa rersponder à
 * mensagem enviada originalmente pelo processo do serviço Hekura
 * @property { String } signal: identificador da mensagem
 * @property { String } msgId: identificador (UUID) da mensagem enviada originalmente pelo processo principal
 * @property { boolean } response: resposta do usuário indicando aceita ou não a requisição
 * @property { boolean } dontAsk: indicador de "não perturbe", indicando que mensagens referentes a esta origem
 * e operação não precisam mais ser enviadas ao usuário, para alerta
 */
class UserAnswer extends WarnResponse {
	/**
	 * Cria uma nova i nstância do objeto
	 * @property { String } msgId: identificador (UUID) da mensagem enviada originalmente pelo processo principal
	 * @property { boolean } response: resposta do usuário indicando aceita ou não a requisição
	 * @property { boolean } dontAsk: indicador de "não perturbe", indicando que mensagens referentes a esta origem
	 * e operação não precisam mais ser enviadas ao usuário, para alerta
	 */
	constructor(msgId, response, dontAsk) {
		super(msgId, response);
		this.dontAsk = dontAsk;
	}
}

/**
 * Representa uma Promise retornada num contexto e resolvida em outro.
 */
class DelayedPromise
{
	/**
	 * Cria uma nova instância de uma DelayedPromise
	 * @param { Function } resolve: callback evocada na resolução da Promise
	 * @param { Function } reject: callback evocada na rejeição da Promise
	 */
	constructor(resolve, reject)
	{
		this.resolve = resolve;
		this.reject = reject;
	}
}

module.exports = { Config, Message, WarnMessage, WarnResponse, UserQuestion, UserAnswer, DelayedPromise };