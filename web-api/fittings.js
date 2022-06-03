/**
 * @file Fornece os recursos de API compatíveis com as extensões da Kryptonite (ver https://bitbucket.org/yakoana/kryptonite.git).
 * Acessível somente no uso da API Xapiripe no seu modo de compatibilidade
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { PromiseRejected } from './api.js';
import { Writable } from 'stream';
import { ZipFile } from 'yazl';
import { fromBuffer } from 'yauzl';

const INVALID_B64 = 'A codificação recebida como base64 é inválida';
const OB_CLOSED = 'Objeto já finalizado';
const INVALID_HANDLE = 'Handle de arquivo zip inválido';
const MALFORMED_ZIP = 'Arquivo zip mal formado';
const ENTRY_NOT_FOUND = 'Entrada não encontrada: ';
const UNINITIALIZED_ZIP = 'Zip não inicializado';
const INTERNAL_FAILURE = 'Falha interna na descompressão';


/**
 * Recursos de conversão de e para Base64. Disponível somente no modo de compatibilidade.
 */
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
const dash_value = -3;
decodings[equals] = equals_value;
decodings[dash] = dash_value;
const pre = 0;
const content_1 = 1;
const content_2 = 2;
const content_3 = 3;
const content_4 = 4;
export class Base64 {

	/**
	 * Codifica a entrada especificada em Base64
	 * @param { Uint8Array } bytes Dados a serem convertidos
	 * @param { Boolean } breakLines Se true, a linha é quebrada na coluna 64. Opcional. Valor default: false
	 * @returns String contendo os dados codificados
	 */
	btoa(bytes, breakLines) {
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
	 * Decodifica a entrada especificada de Base64 para o formato binário
	 * @param { String } base64 Dados codificados
	 * @returns Instância de Uint8Array contendo os dados originais
	 */
	atob(base64) {
		var charlen = base64.length;
		var byteoff = 0;
		var byteLength = Math.round(((charlen) / 4 * 3) + 1);
		var bytes = new Uint8Array(byteLength)
		var chunk = 0;
		var i = 0;
		var code;
		code = decodings[base64.charCodeAt(i)];
		if (code == dash_value) {
			while (code == dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			if (i != 0)
			{
				while(code != dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
				while(code == dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
			}
		}
		while (code < 0 && code != dash_value && i < charlen) code = decodings[base64.charCodeAt(++i)];
		if (code == dash_value || i >= charlen) throw new Error(INVALID_B64);
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
			case content_1: throw new Error(INVALID_B64);
			case content_4:	bytes[byteoff + 2] = chunk &  255;
			case content_3:	bytes[byteoff + 1] = chunk >> 8;
			case content_2:	bytes[byteoff    ] = chunk >> 16;
			}
			byteoff += stage-1;
			stage = pre;
		}
		return bytes.subarray(0,byteoff);
	}
}


class MemoryStream extends Writable {

	constructor() {
		super();
		this._buffer = new Array();
		this._stream= null;	
	}

	#getEncoding(value)
	{
		let ret;
		if (
			value === 'ascii' ||
			value ===  'utf8' ||
			value ===  'utf-8' ||
			value ===  'utf16le' ||
			value ===  'ucs2' ||
			value ===  'ucs-2' ||
			value ===  'base64' ||
			value ===  'latin1' ||
			value ===  'binary' ||
			value ===  'hex'
		)	ret = value;
		return ret;
	}
	_write(chunk, encoding, callback) {
		if (this._stream) callback(new Error(OB_CLOSED));
		else {
			let err;
			let data;
			try {
				if (typeof chunk === 'string') data = Buffer.from(chunk, this.#getEncoding(encoding));
				else data = chunk;
				this._buffer.push(data);
			}
			catch (e) { err = e; }
			callback(err);
		}
	}
	_final(callback) { this.emit('finish', this.toBuffer()); }
	toBuffer() {
		if (!this._stream) this._stream = Buffer.concat(this._buffer);
		return new Uint8Array(this._stream.buffer);
	}
}

const REGULAR_FILE = parseInt('0100664', 8); /* (0100000 => POSIX S_IFREG: regular file) + 664 => -rw-rw-r-- equiv chown */
let dCounter = 0;
class Deflater { 
	constructor() {
		this.zip = new ZipFile();
		this.writer = new MemoryStream();
		this.zip.outputStream.pipe(this.writer);
		this.hHandle = ++dCounter;
	}
	add(entry) {
		this.zip.addBuffer(
			Buffer.from(entry.entry),
			entry.name,
			{ mtime: new Date(entry.date), mode: REGULAR_FILE, compress: entry.compress }
		);
	}
	close() {
		return new Promise((resolve) =>  {
			this.writer.on('finish', () => { return resolve(this.writer.toBuffer()); });
			this.zip.end();
		});
	}
}

/**
 * Fornece acesso a recursos de compressão de dados.
 * Thanks to Josh Wolfe (see https://github.com/thejoshwolfe/yazl and https://github.com/thejoshwolfe/yauzl)
 */
export class Deflate {

	/**
	 * Cria uma nova instância do objeto
	 */
	constructor() { this.map = new Map(); }

	/**
	 * Inicializa um novo arquivo ZIP (em memória)
	 * @returns Promise que, quando resolvida, retorna um handle numérico para o arquivo.
	 */
	create() {
		return new Promise((resolve) => {
			let deflater = new Deflater();
			this.map.set(deflater.hHandle, deflater);
			return resolve(deflater.hHandle);
		});
	}

	/**
	 * Adiciona uma nova entrada ao arquivo zip
	 * @param { Number } handle Valor retornado pelo método {@link create}
	 * @param { ArrayBuffer | Uint8Array } entry Conteúdo a ser compactado
	 * @param { String } name Nome da nova entrada
	 * @param { Number } date Data da entrada. Opcional. Valor default: instante corrente
	 * @param { boolean } compress Indicador de compressão. Valor default: true (nível 8 de compressão); caso contrário,
	 * a entrada é simplesmente arquivada
	 * @returns Promise que, quando resolvida, retorna um indicador de sucesso da operação.
	 */
	add(handle, entry, name, date = Date.now(), compress = true) {
		return new Promise((resolve, reject) => {
			let deflater = this.map.get(handle);
			if (!deflater) return reject(new PromiseRejected(229, INVALID_HANDLE));
			try {
				let data = entry instanceof Uint8Array ? entry : new Uint8Array(entry);
				deflater.add({ entry: data, name: name, date: date, compress: compress });
				return resolve(true);
			}
			catch (e) { return reject(new PromiseRejected(230, e.toString())); }
		});
	}

	/**
	 * Finaliza a criação do arquivo zip
	 * @param { Number } handle Valor retornado pelo método {@link create}
	 * @param { boolean } preserve Indicador de formato do retorno. Se true, o valor retornado é um Uint8Array
	 * que não é convertido para Base64. Valor default: false, com a consequente conversão para Base64
	 * @returns Promise que, quando resolvida, retorna o arquivo de dados comprimido no formato String
	 * ou Uint8Array, de acordo com o parâmetro preserve
	 */
	close(handle, preserve = false) {
		return new Promise((resolve, reject) => {
			let deflater = this.map.get(handle);
			if (!deflater) return reject(new PromiseRejected(229, INVALID_HANDLE));
			this.map.delete(handle);
			deflater.close().then((value) => {
				let ret = value;
				if (!preserve) ret = new Base64().btoa(value);
				return resolve(ret);
			});
		});
	}
}

let iCounter = 0;
class Inflater {
	static open(buffer) {
		return new Promise((resolve, reject) => {
			let ret = new Inflater(buffer);
			fromBuffer(ret.buffer, {}, (err, zipFile) => {
				if (err) return reject(new PromiseRejected(228, err.message));
				else if (zipFile)
				{
					ret.zip = zipFile;
					ret.zip.on('entry', (entry) => { ret.entries.set(entry.fileName, entry); });
					ret.zip.on('end', () => { return resolve(ret) });
				}
				else reject(new PromiseRejected(228, MALFORMED_ZIP));
			});
		});
	}
	constructor(buffer) {
		this.handle = ++iCounter;
		this.buffer = Buffer.from(buffer);
		this.zip;
		this.entries = new Map();
	}
	list() { return new Set(this.entries.keys()); }
	inflate(name) {
		return new Promise((resolve, reject) => {
			let entry = this.entries.get(name);
			if (!entry) return reject(new PromiseRejected(231, ENTRY_NOT_FOUND + name));
			if (!this.zip) return reject(new PromiseRejected(228, UNINITIALIZED_ZIP));
			this.zip.openReadStream(entry, (err, stream) => {
				if (err) return reject(new PromiseRejected(231, err));
				if (!stream) return reject(new PromiseRejected(228, INTERNAL_FAILURE));
				let writer = new MemoryStream();
				stream.on('end', () => { return resolve(writer.toBuffer()); });
				stream.pipe(writer);
			});
		});
	}
}

/**
 * Fornece acesso a recursos de descompactação de dados.
 * Thanks to Josh Wolfe (see https://github.com/thejoshwolfe/yazl and https://github.com/thejoshwolfe/yauzl)
 */
export class Inflate {

	/**
	 * Cria uma nova instância do objeto
	 */
	 constructor() { this.map = new Map(); }

	 /**
	 * Abre um arquivo compactado para descompressão
	 * @param { ArrayBuffer | Uint8Array } zip Arquivo zip a ser descomprimido
	 * @returns Promise que, quando resolvida, retorna um handle numérico para o arquivo
	 */
	open(zip) {
		return new Promise((resolve, reject) => {
			Inflater.open(zip).then((inflater) => {
				this.map.set(inflater.handle, inflater);
				return resolve(inflater.handle);
			})
			.catch((reason) => { return reject(reason); });
		});
	}

	/**
	 * Lista as entradas presentes pelo nome
	 * @param { Number } handle Valor retornado pelo método {@link open}
	 * @returns Promise que, quando resolvida, retorna um array contendo os nomes de todas as entradas presentes.
	 */
	list(handle) {
		return new Promise((resolve, reject) => {
			let inflater = this.map.get(handle);
			if (!inflater) return reject(new PromiseRejected(229, INVALID_HANDLE));
			return resolve(Array.from(inflater.list()));
		});
	}

	/**
	 * Descompacta a entrada especificada pelo nome
	 * @param { Number } handle Valor retornado pelo método {@link open}
	 * @param { String } name Nome da entrada (deve ser um dos retornados pelo método {@link list})
	 * @param { boolean } preserve Indicador de formato do retorno. Se true, o valor retornado é um Uint8Array
	 * que não é convertido para Base64. Valor default: false, com a consequente conversão para Base64
	 * @returns Promise que, quando resolvida, retorna o arquivo de dados comprimido no formato String
	 * codificada  em Base64 ou Uint8Array, de acordo com o parâmetro preserve
	 */
	inflate(handle, name, preserve = false) {
		return new Promise((resolve, reject) => {
			let inflater = this.map.get(handle);
			if (!inflater) return reject(new PromiseRejected(229, INVALID_HANDLE));
			inflater.inflate(name).then((value) => {
				let ret = value;
				if (!preserve) ret = new Base64().btoa(value);
				return resolve(ret);
			})
			.catch((reason) => { return reject(reason); });
		});
	}

	/**
	 * Fecha o arquivo compactado
	 * @param { Number } handle Valor retornado pelo método {@link open}
	 * @returns Promise que, quando resolvida, retorna um indicador de sucesso da operação.
	 */
	close(handle) {
		return new Promise((resolve, reject) => {
			let inflater = this.map.get(handle);
			if (!inflater) return reject(new PromiseRejected(229, INVALID_HANDLE));
			this.map.delete(handle);
			return resolve(true);
		});
	}
}