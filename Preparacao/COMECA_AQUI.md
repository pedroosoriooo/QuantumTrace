# QuantumTrace - preparação da apresentação

Este kit complementa o QuantumTrace 0.3. Não substitui a aplicação nem altera os dados fornecidos pela organização. Os exemplos são sintéticos e foram criados para esta preparação.

## Os próximos 30 a 45 minutos

1. Confirma que tens o ZIP completo da versão 0.3 extraído. A pasta correta contém `INICIAR_APP.cmd`, `quantumtrace`, `data` e `reports`.
2. A pasta `Preparacao` já está incluída neste projeto, ao lado de `INICIAR_APP.cmd`. Não precisas de a copiar para outra localização. Se atualizares uma instalação existente, copia também esta pasta para junto desse atalho.
3. Abre `INICIAR_APP.cmd` e mantém o terminal aberto. Analisa os dados do desafio uma vez. Para o conjunto incluído em 0.3, com TShark disponível, esperamos 28 ficheiros analisados, 1574 observações, 619 nos cartões, 955 opções TLS oferecidas, 9 por rever, 0 erros e 0 análises parciais.
4. Na app, escolhe os oito ficheiros da subpasta `Preparacao/FICHEIROS_NOVOS`. Analisa e confere a tabela abaixo.
5. Abre uma evidência, usa os filtros, exporta o JSON e volta a abrir a análise pelo histórico. Confirma que o texto e a janela de evidência são legíveis no ecrã que vais usar.
6. Para comparar automaticamente com as expectativas, abre `Preparacao/VALIDAR_EXEMPLOS.cmd`. Este teste adicional usa a aplicação que tens no PC e cria o seu próprio relatório em `Preparacao/resultados`. Não escreve no histórico da app nem substitui `reports/report.html` do projeto.

Se a app não abrir, a primeira tarefa é corrigir esse problema com a mensagem concreta do terminal. Se a captura ficar parcial, confirma o TShark. Se um exemplo divergir, conserva o ficheiro e o resultado; não alteres a expectativa apenas para obter um teste aprovado.

## Resultados esperados dos exemplos novos

| Ficheiro | Resultado esperado | O que demonstra |
| --- | --- | --- |
| `01_aes128.py` | AES, 128 bits, médio | Infere 16 bytes como 128 bits |
| `02_aes256.py` | AES, 256 bits, resiliente | Infere 32 bytes e resolve um import com nome alternativo |
| `03_rsa.py` | RSA, 3072 bits, crítico | O tamanho maior não remove a exposição da primitiva a Shor |
| `04_aes_desconhecido.py` | AES, tamanho desconhecido, por rever | Mantém a incerteza quando falta a origem da chave |
| `05_sem_chamadas_crypto.py` | Zero observações | Nomes em comentários e texto não são chamadas |
| `06_ChaveJava.java` | AES, 256 bits, resiliente | Inspeção de um padrão Java suportado |
| `07_chave_go.go` | AES, 128 bits, médio | Inspeção de um padrão Go suportado |
| `08_config_nova.json` | RSA crítico, AES-256 resiliente e ML-KEM resiliente | Inventaria declarações de configuração |

Total esperado: **8 ficheiros analisados; 9 observações; 2 críticas, 2 médias, 4 resilientes e 1 por rever; zero erros e zero análises parciais**. O índice é 37,5: `(2 x 100 + 2 x 50 + 4 x 0) / 8`. O caso por rever fica fora da média. O 768 de ML-KEM-768 é o nome do conjunto de parâmetros, não um segredo com 768 bits.

Os oito casos coincidiram com estas expectativas no ambiente Linux de preparação, usando QuantumTrace 0.3.3, com a pasta já colocada na raiz do projeto. Falta confirmar no teu Windows. Estes exemplos não medem a precisão geral e não são uma avaliação independente ou oficial. O controlo negativo foi construído sem chamadas criptográficas; zero observações noutros ficheiros nunca certifica ausência de criptografia.

Os ficheiros de entrada são apenas analisados. Não precisas de instalar `cryptography`, Java ou Go para estes oito testes. Não executes nem compiles os exemplos.

## Distribuição das 19 horas disponíveis

| Bloco | Tempo máximo | Terminado quando... |
| --- | --- | --- |
| Validar no PC, testar variações e corrigir problemas | 4 h | O percurso completo funciona e as divergências estão corrigidas ou documentadas |
| Clareza da interface e prioridades de migração | 2 h | Consegues encontrar um caso prioritário, a evidência e o próximo passo rapidamente |
| Guião e slides | 3 h | Tens uma explicação que respeita o tempo confirmado pela organização |
| Ensaios, gravação de reserva e entrega | 2 h | Fizeste três ensaios, tens uma alternativa offline e confirmaste os requisitos de entrega |
| Descanso e margem para imprevistos | 8 h | Conservas margem para problemas e chegas à apresentação em condições |

Começa hoje pelo percurso completo e pelo guião. As horas são limites de trabalho, não uma obrigação de as preencher. Antes de fechar os slides, confirma a duração da apresentação, a língua, os ficheiros pedidos e o canal de submissão com a organização.

## Melhorias a escolher depois da primeira validação

1. Corrigir primeiro qualquer falha que impeça iniciar, analisar ou exportar.
2. Rever as classificações de hashes e a apresentação dos grupos híbridos. As regras dos hashes são uma extensão nossa, não uma categoria NIST. Uma componente clássica crítica dentro de um grupo híbrido não prova que o conjunto híbrido está quebrado.
3. Se o percurso já for fiável, acrescentar um resumo de prioridades agrupado por ficheiro ou recurso: mecanismo, origem da evidência, motivo e próximo passo. A prioridade deve considerar se está configurado, oferecido ou negociado. Sem contexto empresarial, não apresentar isto como um ranking completo de risco real.
4. Simplificar o texto da política visível na página e conservar o detalhe técnico numa área expansível.

Congela a versão depois destes passos, guarda uma cópia do ZIP e reserva os ensaios para encontrar problemas concretos. As melhorias acima são tarefas propostas; este kit não as implementa automaticamente.

## Demonstração ao vivo com uma alteração real

1. Na app, analisa apenas `01_aes128.py`: deve aparecer AES-128, médio.
2. Abre esse ficheiro no editor. Troca `token_bytes(16)` por `token_bytes(32)` e guarda.
3. Seleciona novamente o ficheiro na app e faz outra análise: deve aparecer AES-256, resiliente.
4. Mostra o parâmetro e a localização da evidência. Se comparares os relatórios, a mudança do tamanho pode aparecer como observação removida e adicionada, porque o tamanho faz parte da identidade de comparação.
5. Explica: alterámos um parâmetro do exemplo e o inventário refletiu essa mudança; não demonstrámos a segurança completa de uma aplicação.
6. Restaura o valor 16 antes de executar de novo `VALIDAR_EXEMPLOS.cmd`, para voltar a coincidir com as expectativas originais.

Uma leitura de uma análise guardada não reexecuta o scanner. Na demonstração, usa o botão de nova análise para mostrar a alteração.

## Condições para fechar o projeto

- A app abre e o percurso de análise e exportação funciona no computador da apresentação.
- Tens um resultado novo que consegues justificar pela evidência e um caso que permanece por rever.
- Consegues explicar a diferença entre observações, ficheiros e recursos únicos.
- Consegues explicar o índice sem o apresentar como probabilidade de ataque.
- O relatório offline abre e tens uma gravação curta de reserva feita no teu PC.
- A duração, formato e canal de entrega foram confirmados. Nenhuma entrega ou publicação foi feita automaticamente por este kit.

## Ficheiros incluídos

- `GUIAO_E_PERGUNTAS.md`: guião provisório de cerca de dois minutos, versão inglesa e perguntas prováveis.
- `FICHEIROS_NOVOS`: os oito ficheiros a escolher na app.
- `VALIDAR_EXEMPLOS.cmd`: validação adicional no Windows.
- `validar_exemplos.py`: o programa de validação, que usa o core existente.
- `resultados_esperados.json`: expectativas manuais, escritas antes da primeira execução deste kit.
- `resultados`: relatório e registo da verificação no ambiente de preparação; uma nova validação atualiza-os.


## Versão congelada 0.3.3

A revisão das sugestões foi executada. Há agora prioridades agrupadas por
ficheiro/recurso/sessão, com estado da evidência, motivo e próximo passo.
Ofertas ficam como inventário; híbridos recebem revisão da construção. A política
visível foi simplificada e o detalhe técnico continua expansível. Os níveis dos
hashes conservam a extensão documentada do projeto. Os totais não mudaram.
O roteiro e o PowerPoint finais são entregues no pacote de apresentação separado.
Ensaia no PC; altera a versão apenas se encontrares um problema concreto.
