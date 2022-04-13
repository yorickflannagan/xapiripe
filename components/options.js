/**
 * @file Acesso às configurações das diferentes aplicações
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

 'use strict';

 const path = require('path');
 const fs = require('fs');
 const crypto = require('crypto');
 
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
  * @property { String } path: caminho completo para os arquivos de log. Default: __dirname.
  * @property { String } fname: padrão para nome dos arquivos de log. Deve conter a string "-n". Default: xapiripe-n.log,
  * @property { Number } maxSize: tamanho máximo (em KB) que o arquivo de log pode alcançar antes de rotacionar. Default: 2048.
  * @property { Number } rotate: quantidade máxima de arquivos de log a serem criados antes de sobrescrever o mais antigo. Default: 5.
  * @property { Number } level: nível de log a ser adotado pela aplicação. Default: 1 (info). Ver a documentação do componente Wanhamou.
  */
 class LogOptions {
	 constructor() {
		 this.path = path.resolve(__dirname, '..');
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
 
 /**
  * Opções das aplicações
  * @property { boolean } askToRestart: indicador para alertar o usuário da necessidade de reiniciar a aplicação
  * @property { boolean } restartOnChange: indicador de obrigatoriedade de reiniciar a aplicação após uma mudança na configuração
  * @property { String  } updateURL: URL de atualização do aplicativo, se requerido
  */
 class AppOptions {
	 constructor() {
		 this.askToRestart = true;
		 this.restartOnChange = true;
		 this.updateURL = 'http://127.0.0.1:9090';
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
	 'restartOnChange',
	 'updateURL'
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
	 .set('updateURL', 'string')
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
 
 
 module.exports = { Config };