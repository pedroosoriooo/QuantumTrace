# QuantumTrace — Hidden Signal

## Demonstração de cerca de dois minutos

Abre `INICIAR_APP.cmd` e deixa o terminal minimizado. Antes de apresentar,
faz uma análise dos dados do desafio para teres uma entrada no histórico.
Os dados incluídos são os exemplos sintéticos fornecidos pela organização,
sem alterações. As verificações usam expectativas manuais, não notas oficiais.

1. **Problema e proposta, 15 segundos.** É preciso saber onde está a criptografia
   antes de planear a migração. O QuantumTrace lê código, cloud e capturas TLS
   e liga cada observação a uma origem verificável.
2. **Análise e contagem, 20 segundos.** Carrega em Analisar dados do desafio.
   Mostra 28 ficheiros analisados e a conta: 1574 observações = 619 nos cartões
   + 955 opções TLS oferecidas. O total não representa vulnerabilidades únicas.
3. **Evidência, 25 segundos.** Pesquisa RSA e abre Ver evidência. Mostra a linha
   ou campo JSON, a regra e o próximo passo. Mostra também AES com o tamanho
   inferido; uma chamada no código não comprova execução.
4. **Casos por rever, 20 segundos.** Mostra os nove casos e o que falta. HMAC e
   PBKDF2 não são declarados seguros só porque aparece SHA-256 ou uma saída de
   256 bits. A regra para o hash de RSA-OAEP continua uma lacuna explícita.
5. **Rede, 20 segundos.** Abre as sessões TLS: 97 pares de hello e sete grupos
   híbridos selecionados. Mostra o pacote de uma sessão e as opções oferecidas.
   A primitiva ou grupo híbrido não certifica a sessão completa.
6. **Histórico e exportação, 20 segundos.** Compara duas execuções do mesmo
   conjunto: as observações devem manter-se. Explica que ficheiros novos podem
   ser escolhidos na app. Descarrega o JSON ou relatório offline; cada resultado
   conserva a evidência e as regras. A interface usa uma API JSON local e guarda
   relatórios em SQLite, com classificação por regras inspecionáveis.

Se o júri usar inglês, troca o idioma com o botão English. As explicações
técnicas e a evidência continuam na língua original do inventário.

## Antes de apresentar

- Confirma o funcionamento da nova app no computador da apresentação.
- Mantém Python 3.10+ e TShark disponíveis para incluir a captura. Sem TShark,
  uma nova análise do PCAP fica parcial; o relatório offline incluído conserva
  o resultado completo anteriormente gerado.
- Abre uma análise uma vez antes da apresentação para validar os totais e
  guardar o histórico. Abri-la depois não reexecuta o analisador.
- Conserva `ABRIR_RELATORIO.cmd` como acesso ao relatório offline incluído.
- Os 70 testes verificam comportamentos e expectativas específicas. Não
  apresentes 98,5% de cobertura de classificação como precisão de deteção.
- A classificação dos hashes usa uma extensão documentada da política do
  desafio; o modelo de consultas não é uma estimativa de ataque prático.
- Submete o projeto através do canal dos organizadores. Não houve publicação
  ou submissão automática.
