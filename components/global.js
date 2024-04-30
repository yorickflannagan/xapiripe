/**
 * @file Implementações de uso comum
 * @copyright Copyleft &copy; 2021-2024 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

const Failure = require('./hamahiri').Failure;

/**
 * Utilitários
 * @namespace Global
 */


/**
 * Detalhamento de erros ocorridos durante o processamento de uma API
 * @memberof Global
 * @property { string  } component - Componente que disparou o erro
 * @property { String  } message Mensagem descritiva
 * @property { String  } method Método ou função onde ocorreu o erro
 * @property { Number  } errorCode Código de erro no módulo
 * @property { Failure } nativeError Objeto de erro do módulo nativo, ou null
 */
class ComponentError extends Error {

	/**
	 * Cria uma nova instância do relatório de erros
	 * @param { String  } component - Nome do componente responsável pelo erro
	 * @param { String  } msg Mensagem descritiva
	 * @param { String  } method Método ou função onde ocorreu o erro
	 * @param { Number  } errorCode Código de erro no módulo
	 * @param { Failure } nativeError Objeto de erro do módulo nativo, ou null
	 */
	constructor(component, msg, method, errorCode, nativeError) {
		super(msg);
		this.component = component;
		this.method = method;
		this.errorCode = errorCode ? errorCode : 0;
		this.nativeError = nativeError ? nativeError : null;
	}

	toString() {
		let value = 'Error message: '.concat(this.message,
			' Component: ', this.component,
			' Method: ', this.method,
			' Error code: ', this.errorCode.toString()
			);
		if (this.nativeError) value.concat(this.nativeError.toString());
		return value;
	}
}


const encodings = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const equals = "=".charCodeAt(0);
const dash = "-".charCodeAt(0);
const decodings = [
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
	52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
	-1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
 ];
const equals_value	= -2;
const dash_value 	= -3;
decodings[equals]	= equals_value;
decodings[dash] 	= dash_value;
const pre = 0;
const content_1 = 1;
const content_2 = 2;
const content_3 = 3;
const content_4 = 4;
/**
 * Utilitário para conversão de e para Base64
 * @memberof Global
 */
class Base64 {
	/**
	 * Converte um array de bytes para Base64
	 * @param { Uint8Array } bytes Cadeia de bytes a ser convertida
	 * @param { Boolean } breakLines Se true, a linha é quebrada na coluna 64. Opcional. Valor default: false
	 * @returns { String } Argumento convertido para Base64
	 */
	static btoa(bytes, breakLines)
	{
		var base64        = '';
		var byteLength    = bytes.byteLength;
		var byteRemainder = byteLength % 3;
		var mainLength    = byteLength - byteRemainder;
		var a, b, c, d;
		var chunk;
		for (var i = 0; i < mainLength; i = i + 3) {
			chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			a = (chunk & 16515072) >> 18;
			b = (chunk & 258048)   >> 12;
			c = (chunk & 4032)     >>  6;
			d = chunk & 63;
			base64 += encodings[a] + encodings[b] + encodings[c] + encodings[d];
		}
		if (byteRemainder == 1) {
			 chunk = bytes[mainLength];
			 a = (chunk & 252) >> 2;
			 b = (chunk & 3)   << 4;
			 base64 += encodings[a] + encodings[b] + '==';
		 }
		 else if (byteRemainder == 2) {
			chunk = (bytes[mainLength] << 8) | bytes[mainLength + 1];
			a = (chunk & 64512) >> 10;
			b = (chunk & 1008)  >>  4;
			c = (chunk & 15)    <<  2;
			base64 += encodings[a] + encodings[b] + encodings[c] + '=';
		}
		let ret = base64;
		if (breakLines) {
			let pem = [];
			let start = 0;
			while (start < base64.length)
			{
				pem.push(base64.slice(start, start + 64));
				start += 64;
			}
			ret = pem.join('\r\n');
		}
		return ret;
	}

	/**
	 * Converte o argumento de Baser64 para um array de bytes
	 * @throws { Error } Dispara uma exceção caso a string não seja válida em Base64
	 * @param { String } base64 Array de bytes codificado em Base64
	 * @returns { Uint8Array } Array de bytes convertido
	 */
	static atob(base64)	{
		var charlen = base64.length;
		var byteoff = 0;
		var byteLength = Math.round(((charlen) / 4 * 3)+1);
		var bytes = new Uint8Array(byteLength);
		var chunk = 0;
		var i = 0;
		var code;
		code = decodings[base64.charCodeAt(i)];
		if (code == dash_value) {
			while (code == dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			if (i!=0) {
				while(code != dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
				while(code == dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
			}
		}
		while (code<0 && code != dash_value && i < charlen) code=decodings[base64.charCodeAt(++i)];
		if (code == dash_value || i >= charlen) throw new Error("A codificação recebida como base64 é inválida");
		var stage = pre; 
		while (i < charlen && code != dash_value) {
			while (i < charlen && stage != content_4 && code != dash_value) {
				stage++;
				switch(stage) {
					case content_1:
						chunk = code << 18;
						break;
					case content_2:
						chunk |= code << 12;
						break;
					case content_3:
						chunk |= code << 6;
						break;
					case content_4:
						chunk |= code;
						break;
				}
				code = decodings[base64.charCodeAt(++i)];
				while (code < 0 && code != dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			}
			switch(stage) {
			case content_1: throw new Error("A codificação recebida como base64 é inválida");
			case content_4:	bytes[byteoff + 2] = chunk &  255;
			/* falls through */
			case content_3:	bytes[byteoff + 1] = chunk >> 8;
			/* falls through */
			case content_2:	bytes[byteoff    ] = chunk >> 16;
			}
			byteoff += stage-1;
			stage = pre;
		}
		return bytes.subarray(0,byteoff);
	}
}

module.exports = {
	ComponentError:	APIError,
	Base64:			Base64Conveter
};