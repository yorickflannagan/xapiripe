/**
 * Xapiripë Project
 * Software components for CAdES signatures
 * See https://datatracker.ietf.org/doc/html/rfc5126
 *
 * Copyleft (C) 2020-2022 The Crypthing Initiative
 * Authors:
 * 		yorick.flannagan@gmail.com
 *
 * Xapiripe - Standalone Hekura service
 * See https://bitbucket.org/yakoana/xapiripe/src/master/appservice
 * ask.js - Warning dialog renderer
 * 
 * This application is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3.0 of
 * the License, or (at your option) any later version.
 *
 * This application is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See https://opensource.org/licenses/LGPL-3.0
 *
 */
'use strict';


const { ipcRenderer } = require('electron');
const { UserAnswer } = require('./module');

const BUFFER_MAX_LENGTH = 1024 * 256;
const DOC_TOO_LONG = '...\nO documento a ser assinado é muito grande para visualização completa. Clique no botão download para baixá-lo e inspecioná-lo completamente.';
const DOC_IS_BIN = 'O documento a ser assinado não parece estar codificado em UTF-8. Se desejar inspecioná-lo, clique no botão Download.';
const ERROR_NO_PARAM = 'O diálogo e alerta sobre operação criptográfica a ser realizada não recebeu o parâmetro apropriado. A aplicação não está funcionando corretamente.';
const ERROR_INVALID_PARAM = 'O diálogo e alerta sobre operação criptográfica a ser realizada recebeu um parâmetro inválido. A aplicação não está funcionando corretamente.';
const ERROR_NO_CONTROLS = 'O diálogo e alerta sobre operação criptográfica a ser realizada está mal formado. A aplicação não está funcionando corretamente.';

/**
 * Instância de UserQuestion com as informações necessárias para a exibição do alerta
 */
let param;

/**
 * Determina, através da análise de algumas amostras, se um array de bytes (Uint8Array) está codificado em UTF-8.
 * A implementação se utiliza de três amostras, tomadas do início, do meio e d fim do array.
 * Se o array for menor que 2048 bytes, todo ele analisado.
 */
class Sampler
{
	/**
	 * Cria uma nova instância do algoritmo com o tamanho de amostra especificado
	 * @param { Number } sampleLen: tamanho em bytes da amostra. Valor default 128
	 */
	constructor(sampleLen = 128) {
		this.length = sampleLen;
	}
	/**
	 * Conta a quantidade de caracteres representada no byte especificado
	 * @param { Number } byte: byte a ser analisado
	 * @returns a quantidade de caracteres
	 */
	#count_chars(byte) {
		let j = 0;
		while (j < 6 && (byte >> (7 - j) & 1)) j++;
		return (j - 1);
	}
	/**
	 * Analisa a amostra fornecida
	 * @param { Uint8Array } buffer: array de bytes sob análise
	 * @param { Number } pos: posição inicial da amostra no buffer
	 * @param { Number } len: tamanho da amostra
	 * @returns caso um caractere não aceitável em UTF-8 seja encontrado, retorna false. Caso contrário, true.
	 */
	#sample(buffer, pos, len) {
		let i = pos;
		if (buffer.length < pos + len) throw new RangeError("Out of range arguments");
		while (i < len)
		{
			let c = buffer[i];
			if ((c > 31 && c < 128) || c == 9 || c == 10 || c == 13) i++;
			else if (c > 191 && c < 254)
			{
				i++;
				for (let j = 0, k = this.count_chars(c); j < k; j++, i++)
				{
					c = buffer[i];
					if (c < 128 && c > 191) return false;
				}
			}
			else return false;
		}
		return true;
	}
	/**
	 * Obtém uma amostra para análise
	 * @param { Uint8Array } buffer: array de bytes sob análise
	 * @param { Numbere } pos: posição calculada da amostra
	 * @returns a posição da amostra desejada
	 */
	#get_sample(buffer, pos)
	{
		let i = pos;
		while (i > 0)
		{
			let c = buffer[i];
			if (c < 128 || (c > 191 && c < 254)) return i;
			i--;
		}
		return i;
	}

	/**
	 * Analisa um array de bytes para determinar se está codificado em UTF-8
	 * @param { Uint8Array } buffer: array de byts
	 * @returns um booleano indicando se a amostra parece ou não codificada em UTF-8
	 */
	check(buffer)
	{
		let pos = 0;
		let ret = false;
		if (buffer.length < 2048) return this.sample(buffer, 0, buffer.length);
		ret = this.sample(buffer, pos, this.length);
		if (ret)
		{
			pos = this.get_sample(buffer, buffer.length - this.length);
			ret = this.sample(buffer, pos, this.length);
			if (ret)
			{
				pos = this.get_sample(buffer, Math.trunc(buffer.length / 2));
				ret = this.sample(buffer, pos, this.length);
			}
		}
		return ret;
	}
}

/**
 * Retorno da análise da codificação de documento
 * @property { String } contents: conteúdo (possivelmente parcial) a ser exibido ou mensagem indicativa de conteúdo binário
 * @property { boolean } download: indicador de conteúdo completo disponível para download, caso ultrapasse 256 KB
 */
class Sample {
	constructor() {
		this.contents = '';
		this.download = false;
	}
}

/**
 * Obtém uma mostra exibível do conteúdo binário, caso esteja codificado em UTF-8. Caso contrário retorna uma mensagem indicativa.
 * @param { ArrayBuffer } value: conteúdo a ser analisado
 * @returns uma instância de Sample com a parte do conteúdo passível de visualização
 */
function getBinaryContentsSample(value) {
	let ret = new Sample();
	let buffer = new Uint8Array(value);
	let sampler = new Sampler();
	let isUTFEncoded = sampler.check(buffer);
	if (isUTFEncoded) {
		ret.contents = new TextDecoder('utf-8').decode(buffer.subarray(0, BUFFER_MAX_LENGTH));
		ret.download = buffer.length > BUFFER_MAX_LENGTH;
		if (ret.download) ret.contents = ret.contents.concat(DOC_TOO_LONG);
	}
	else {
		ret.contents = DOC_IS_BIN;
		ret.download = true;
	}
	return ret;
}

/**
 * Retorna conteúdo exibível até 256 KB do buffer informado
 * @param { String } value: conteúdo exibível
 * @returns uma instância de Sample
 */
function getTextContentsSample(value) {
	let ret = new Sample();
	ret.contents = value.substring(0, BUFFER_MAX_LENGTH);
	ret.download = value.length > BUFFER_MAX_LENGTH;
	if (ret.download) ret.contents = ret.contents.concat(DOC_TOO_LONG);
	return ret;
}

/**
 * Envia ao processo principal a resposta do usuário ao alerta
 * @param { boolean } accept: indicador da resposta do usuário;
 * @param { boolean } dontAsk: indicador do desejo de não perturbar novamente
 */
function sendUserAnswerMessage(accept, dontAsk) {
	let answer = new UserAnswer(param.msgId, accept, dontAsk);
	ipcRenderer.send('user-answer', answer);
	window.close();
}

window.addEventListener('DOMContentLoaded', () => {
	let arg = process.argv.find((elem) => { return elem.startsWith('--id='); });
	if (!arg) {
		ipcRenderer.send('report-error', ERROR_NO_PARAM);
		window.close();
	}
	let id = arg.substring(5);
	param = ipcRenderer.sendSync('get-params', id);
	if (!param || !param.message || !param.msgId) {
		ipcRenderer.send('report-error', ERROR_INVALID_PARAM);
		window.close();
	}

	let pLegend = document.getElementById('pLegend');
	let pContents = document.getElementById('pContents');
	let btnAccept = document.getElementById('btnAccept');
	let btnRefuse = document.getElementById('btnRefuse');
	let chkDontAsk = document.getElementById('chkDontAsk');
	let btnDownload = document.getElementById('btnDownload');
	if (!(pLegend && pContents && btnAccept && btnRefuse && chkDontAsk && btnDownload)) {
		ipcRenderer.send('report-error', ERROR_NO_CONTROLS);
		window.close();
	}

	pLegend.innerHTML = param.message;
	if (param.value) {
		let sample = {};
		let mimeType = 'text/plain';
		let fileName = 'contents.txt'
		if (param.value instanceof ArrayBuffer) {
			sample = getBinaryContentsSample(param.value);
			mimeType = 'application/octet-stream';
			fileName = 'contents.bin';
		}
		else sample = getTextContentsSample(param.value);
		pContents.innerHTML = sample.contents;
		pContents.hidden = false;
		if (sample.download) {
			btnDownload.addEventListener('click', () => {
				let blob = new Blob([param.value], { type: mimeType });
				let url = URL.createObjectURL(blob);
				let elem = document.createElement('a');
				elem.setAttribute('href', url);
				elem.setAttribute('download', fileName);
				elem.setAttribute('id', 'link');
				document.body.appendChild(elem);
				document.getElementById('link').click();
			});
			btnDownload.hidden = false;
		}
	}
	btnAccept.addEventListener('click', () => {
		sendUserAnswerMessage(true, chkDontAsk.checked);
	});
	btnRefuse.addEventListener('click', () => {
		sendUserAnswerMessage(false, chkDontAsk.checked);
	});
});