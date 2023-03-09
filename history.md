# Versão 0.9.0
Disponibilidade para uso na Intranet Caixa, no aplicativo CNS V2.

# Versão 0.9.1
- Correção da implementação da API Xabo: passagem de parâmetros inválida, com a correção correspondente na aplicação de teste app-client.js;
- Correção na implementação dos reject() nas promises fornecidas pelas classes do módulo kryptonite.js;
- Inclusão de método matchDN() na classe API do namespace Xabo para a comparação normativa entre distinguished names.

# Versão 0.9.2
- Correção de bug na passagem do parâmetro options.toBeSigned no método sign() da classe Sign de modo a assegurar que o contrato da documentação (o parâmetro pode tanto ser uma String quanto um ArrayBuffer) seja corretamente cumprido; admitido um Uint8Array como parâmetro;
- Correção na exibição do número de versão do serviço na bandeja do sistema;
- Correção de bug na janela de alerta de assinatura em caso de dados binários;
- Suporte a caracteres de formatação no conteúdo da janela de alerta;
- Garantia de capacidade de assinar arquivos muito grandes, limitado apenas pela memória disponível para o interpretador Javascript (arquivo de RE de 164 MB).

# Versão 0.9.3
- Atualização da ajuda, incluindo instruções para a liberação do aplicativo pelos recursos de segurança do sistema operacional;
- Correção do bug que não encerra corretamente o aplicativo caso a porta de serviço já esteja em uso;
- Correção do bug que não assume a alteração feita no diretório de log;
- Correção do problema da impossibilidade de logar erros ocorridos durante a atualização;
- Inclusão da capacidade de personalizar o intervalo entre cada busca por nova versão (arquivo distribution.json);
- Mudança no nome do instalador por conta de incapacidade do Squirrel.Windows incorporar o ícone da aplicação no instalador caso este tenha caracteres não alfanuméricos no seu nome;
- Criação de links para o serviço na Área de Trabalho e no Menu Iniciar do usuário corrente.

# Versão 0.9.4
- Correção do erro ocasionado pela ausência do header *referer* na requisição (mensagem com *undefined* em lugar
da origem da requisição);
- Prevenção de lançamento de uma nova instância da aplicação;
- Remoção de / acrescentada ao final de um identificador de origem na tela de Origens Confiáveis, que causava o não reconhecimento da origem;
- Inclusão de capacidade de personalização da animação do instalador;
- Alterações solicitadas pelo gestor;
- Inclusão das URL de atualiCRYPT_ACQUIRE_COMPARE_KEY_FLAGzação.

# Versão 1.0.1
- Exclusão do flag CRYPT_ACQUIRE_COMPARE_KEY_FLAG nas buscas pela chave privada para assegurar compatibilidade com o provider BirdID.
-  Change to ensure compatibility with the BirdID provider: flag CRYPT_ACQUIRE_COMPARE_KEY_FLAG exclusion.