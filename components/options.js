/**
 * @file Acesso às configurações das diferentes aplicações
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const fs = require('fs');

const uriPattern = /^(http|https):\/\/(([a-zA-Z0-9$\-_.+!*'(),;:&=]|%[0-9a-fA-F]{2})+@)?(((25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|localhost|([a-zA-Z0-9]+\.)+([a-zA-Z]{2,}))(:[0-9]+)?(\/(([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*)*)?(\?([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?(\#([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?)?$/;

function jsonValidator(json, props, template, strict) {
	let properties = new Set(props);
	JSON.parse(json, (key, value) => {
		let tp = template.get(key);
		let keyIsArray = !Number.isNaN(Number.parseInt(key));
		if (typeof tp === 'undefined') {
			if (key.match(/^-?\d+$/)) {
				if (keyIsArray) {
					if (typeof value === 'string') tp = 'string';
					else if (typeof value === 'number') tp = 'number';
					else tp = 'object';
				}
				else tp = 'object';
			}
		}
		if (typeof tp === 'undefined') throw new Error('Propriedade ' + key + ' não reconhecida');
		if (typeof value !== tp) throw new Error('O tipo da propriedade ' + key + ' precisa ser ' + tp);
		properties.delete(key);
		return value;
	});
	if (strict && properties.size > 0) throw new Error('O objeto não contém todas as propriedades obigatórias');
}


const DISTRIBUTION_PROPERTIES = [
	'productId',
	'productName',
	'productDescription',
	'company',
	'distributorId',
	'updateURL',
	'interval',
	'loadingGif',
	'trusted'
];
const DISTRIBUTION_TEMPLATE = new Map()
	.set('productId', 'string')
	.set('productName', 'string')
	.set('productDescription', 'string')
	.set('company', 'string')
	.set('distributorId', 'string')
	.set('updateURL', 'string')
	.set('interval', 'number')
	.set('loadingGif', 'string')
	.set('trusted', 'object')
	.set('', 'object');

 /**
  * Identificação da distribuição do produto
  * @property { String } productId			identificador do produto
  * @property { String } productName		nome do produto
  * @property { String } productDescription	descrição do produto
  * @property { String } company			nome do fabricante
  * @property { String } distributorId		identificador do distribuidor
  * @property { String } updateURL			URL de atualização do produto,
  * @property { Number } interval			intervalo (em segundos) entre cada verificação de atualização
  * @property { String } loadingGif			logo do distribuidor (para o instalador)
  * @property { Object } trusted			array de URLs confiáveis por default
  */
 class Distribution {
	 /**
	  * Cria uma nova distribuição do produto especificado
	  */
	 constructor() {
		 this.productId = '';
		 this.productName = '';
		 this.productDescription = '';
		 this.company = 'The Crypthing Initiative';
		 this.distributorId = '';
		 this.updateURL = '';
		 this.interval = 60 * 15;
		 this.loadingGif = 'install-spinner.gif';
		 this.trusted = [];
	 }
 	 /**
	  * Carrega a identificação da distribtuição a partir de um arquivo JSON, que deve existir
	  * @param { string } target: caminho completo para o arquivo JSON
	  * @returns uma instância do objeto
	  */
	static load(target) {
		let ret = fs.readFileSync(target, 'utf-8');
		jsonValidator(ret, DISTRIBUTION_PROPERTIES, DISTRIBUTION_TEMPLATE, true);
		return Object.setPrototypeOf(JSON.parse(ret), Distribution.prototype);
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
 
module.exports = { uriPattern, jsonValidator, Distribution, DelayedPromise };
