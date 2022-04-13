/**
 * @file Modelo de mensagens entre eos coomponentes da aplicação de distribuição do serviço Hekura
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 */

'use strict';

const crypto = require('crypto');

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

module.exports = { Message, WarnMessage, WarnResponse, UserQuestion, UserAnswer, DelayedPromise };