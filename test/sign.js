'use strict';

window.addEventListener('load', () => {

	let alarm = function(contents) {
		let old = document.getElementById('id-alarm');
		if (old) old.remove();
		let p = document.createElement('p');
		p.id = 'id-alarm';
		p.classList.add('highlight');
		p.classList.add('w3-red');
		p.innerText = contents;
		document.body.appendChild(p);
	};
	const enumCertsButton = document.getElementById('enum-certs');
	const certsSelect = document.getElementById('certs');
	const docsButton = document.getElementById('docs');
	const signButton = document.getElementById('sign');
	const outputText = document.getElementById('output');
	if (!(enumCertsButton && certsSelect && docsButton && signButton && outputText)) {
		alarm('Elemento HTML necessário não encontrado. Impossível continuar!');
		return;
	}
	let clientAPI;
		
	enumCertsButton.addEventListener('click', () => {
		if (!clientAPI) {
			alarm('API criptográfica não está presente.');
			return;
		}
		clientAPI.sign.enumerateCerts().then((certs) => {
			if (certs.length == 0) {
				alarm('Nenhum certificado de assinatura válido está presente.');
				return;
			}
			certsSelect.options.length = 0;
			certs.forEach((cert) => {
				let opt = document.createElement('option');
				opt.value = JSON.stringify(cert);
				opt.innerHTML = cert.subject;
				certsSelect.appendChild(opt);
			});
		})
		.catch((reason) => { alarm(JSON.stringify(reason)); });
	});

	function uuidv4() {
		return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
			(c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
		);
	}
	signButton.addEventListener('click', () => {
		if (!clientAPI) {
			alarm('API criptográfica não está presente');
			return;
		}
		if (docsButton.files.length == 0) {
			alarm('É necessário selecionar um arquivo para assinar');
			return;
		}
		let signerCert;
		try { signerCert = JSON.parse(certsSelect.options[certsSelect.selectedIndex].value); }
		catch(e) {
			alarm('Um certificado de assinatura deve ter sido selecionado previamente');
			return;
		}
		signButton.disabled = true;
		let reader = new FileReader();
		reader.addEventListener('load', () => {
			clientAPI.sign.sign({ certificate: signerCert, toBeSigned: reader.result, attach: true })
			.then((cms) => {
				let blob = new Blob([ cms ], { type: 'text/plain' });
				let url = URL.createObjectURL(blob);
				let link = document.createElement('a');
				link.href = url;
				let id = uuidv4();
				link.id = id;
				link.download = 'contents.pem';
				document.body.appendChild(link);
				document.getElementById(id).click();
				document.body.removeChild(link);
				signButton.disabled = false;
			})
			.catch((reason) => {
				alarm('Ocorreu o seguinte erro ao assinar: ' + JSON.stringify(reason));
				signButton.disabled = false;
			});
		});
		reader.addEventListener('error', () => {
			alarm('Ocorreu um erro ao carregar o arquivo para a assinatura: ' + reader.error.toString());
		});
		reader.readAsArrayBuffer(docsButton.files[0]);
	});
		
	xabo.queryInterface({ compatibilityMode: true }).then((api) => { clientAPI = api; })
	.catch((reason) => { alarm(reason.statusText); });
});