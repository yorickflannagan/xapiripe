/**
 * @file Fornece os recursos de API compatíveis com as extensões da Kryptonite (ver https://bitbucket.org/yakoana/kryptonite.git).
 * Acessível somente no uso da API Xapiripe no seu modo de compatibilidade
 * @copyright Copyleft &copy; 2021-2022 by The Crypthing Initiative - All rights reversed
 * @author Marco Antonio Gutierrez<yorick.flannagan@gmail.com>
 * @version 1.0.0
 */

'use strict';

import { PromiseRejected } from './api.js';

/**
 * Recursos de conversão de e para Base64. Disponível somente no modo de compatibilidade.
 */
export class Base64 {

	/**
	 * Codifica a entrada especificada em Base64
	 * @param { Uint8Array } bytes Dados a serem convertidos
	 * @returns String contendo os dados codificados
	 */
	btoa(bytes) {
		return new String();
	}

	/**
	 * Decodifica a entrada especificada de Base64 para o formato binário
	 * @param { String } base64 Dados codificados
	 * @returns Instância de Uint8Array contendo os dados originais
	 */
	atob(base64) {
		return new Uint8Array();
	}
}

/**
 * Fornece acesso a recursos de compressão de dados.
 * Thanks to Josh Wolfe (see https://github.com/thejoshwolfe/yazl and https://github.com/thejoshwolfe/yauzl)
 */
export class Deflate {

	/**
	 * Inicializa um novo arquivo ZIP (em memória)
	 * @returns Promise que, quando resolvida, retorna um handle numérico para o arquivo.
	 */
	create() {
		return Promise.resolve(Number.MIN_VALUE);
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
		return Promise.resolve(new Boolean());
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
		return Promise.resolve(new Uint8Array())
	}
}

/**
 * Fornece acesso a recursos de descompactação de dados.
 * Thanks to Josh Wolfe (see https://github.com/thejoshwolfe/yazl and https://github.com/thejoshwolfe/yauzl)
 */
export class Inflate {

	/**
	 * 
	 * @param { ArrayBuffer | Uint8Array } zip Arquivo zip a ser descomprimido
	 * @returns Promise que, quando resolvida, retorna um handle numérico para o arquivo
	 */
	open(zip) {
		return Promise.resolve(Number.MIN_VALUE);
	}

	/**
	 * Lista as entradas presentes pelo nome
	 * @param { Number } handle Valor retornado pelo método {@link open}
	 * @returns Promise que, quando resolvida, retorna um array contendo os nomes de todas as entradas presentes.
	 */
	list(handle) {
		return Promise.resolve([ new String() ]);
	}

	/**
	 * Descompacta a entrada especificada pelo nome
	 * @param { Number } handle Valor retornado pelo método {@link open}
	 * @param { String } name Nome da entrada (deve ser um dos retornados pelo método {@link list})
	 * @param { boolean } preserve Indicador de formato do retorno. Se true, o valor retornado é um Uint8Array
	 * que não é convertido para Base64. Valor default: false, com a consequente conversão para Base64
	 * @returns Promise que, quando resolvida, retorna o arquivo de dados comprimido no formato String
	 * ou Uint8Array, de acordo com o parâmetro preserve
	 */
	inflate(handle, name, preserve = false) {
		return Promise.resolve(new Uint8Array());
	}

	/**
	 * Fecha o arquivo compactado
	 * @param { Number } handle Valor retornado pelo método {@link open}
	 * @returns Promise que, quando resolvida, retorna um indicador de sucesso da operação.
	 */
	close(handle) {
		return Promise.resolve(new Boolean());
	}
}