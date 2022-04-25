/**
 * @file Acesso às configurações das diferentes aplicações
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const path = require('path');
const fs = require('fs');

const uriPattern = /^(http|https):\/\/(([a-zA-Z0-9$\-_.+!*'(),;:&=]|%[0-9a-fA-F]{2})+@)?(((25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])(\.(25[0-5]|2[0-4][0-9]|[0-1][0-9][0-9]|[1-9][0-9]|[0-9])){3})|localhost|([a-zA-Z0-9]+\.)+([a-zA-Z]{2,}))(:[0-9]+)?(\/(([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*(\/([a-zA-Z0-9$\-_.+!*'(),;:@&=]|%[0-9a-fA-F]{2})*)*)?(\?([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?(\#([a-zA-Z0-9$\-_.+!*'(),;:@&=\/?]|%[0-9a-fA-F]{2})*)?)?$/;

function jsonValidator(json, props, template, strict) {
	let properties = new Set(props);
	JSON.parse(json, (key, value) => {
		let tp = template.get(key);
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


const DISTRIBUTION_PROPERTIES = [
	'productId',
	'productName',
	'productDescription',
	'company',
	'exe',
	'distributorId',
	'updateURL'
];
const DISTRIBUTION_TEMPLATE = new Map()
	.set('productId', 'string')
	.set('productName', 'string')
	.set('productDescription', 'string')
	.set('company', 'string')
	.set('exe', 'string')
	.set('distributorId', 'string')
	.set('updateURL', 'string')
	.set('', 'object');

 /**
  * Identificação da distribuição do produto
  * @property { String } productId: identificador do produto
  * @property { String } distributorId: identificador do distribuidor
  * @property { String } updateURL: URL de atualização do produto
  */
 class Distribution {
	 /**
	  * Cria uma nova distribuição do produto especificado
	  * @param { String } id: identificador do produto
	  * @param { String } name: nome do produto
	  * @param { String } description: descrição do produto
	  * @param { String } exe: nome do executável do produto (incluir extensão)
	  */
	 constructor(id, name, description, exe) {
		 this.productId = id ? id :'';
		 this.productName = name ? name : '';
		 this.productDescription = description ? description : '';
		 this.exe = exe ? exe : '';
		 this.company = 'The Crypthing Initiative';
		 this.distributorId = '';
		 this.updateURL = '';
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

 
module.exports = { uriPattern, jsonValidator, Distribution };
